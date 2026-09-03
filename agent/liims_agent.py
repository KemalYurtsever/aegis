"""Authenticated LIIMS host-metrics agent with local diagnostics."""

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import psutil

AGENT_VERSION = "0.3.0"
LOGGER = logging.getLogger("liims-agent")
MAX_RESULT_CHARACTERS = 40_000


def load_config() -> dict:
    config_path = Path(os.environ.get("LIIMS_AGENT_CONFIG_FILE", Path(__file__).with_name("agent-config.json")))
    if not config_path.is_file():
        return {}
    # Windows PowerShell 5.1 writes a UTF-8 BOM; utf-8-sig accepts both forms.
    with config_path.open("r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


CONFIG = load_config()
SERVER_URL = os.environ.get("LIIMS_SERVER_URL", CONFIG.get("server_url", "http://127.0.0.1:8002")).rstrip("/")
AGENT_TOKEN = os.environ.get("LIIMS_AGENT_TOKEN", CONFIG.get("token", ""))
INTERVAL_SECONDS = max(10, int(os.environ.get("LIIMS_AGENT_INTERVAL_SECONDS", CONFIG.get("interval_seconds", 60))))
DIAGNOSTICS_ENABLED = str(
    os.environ.get("LIIMS_AGENT_DIAGNOSTICS_ENABLED", CONFIG.get("diagnostics_enabled", False))
).strip().lower() in {"1", "true", "yes", "on"}


def collect_payload() -> dict:
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "agent_version": AGENT_VERSION,
        "report_interval_seconds": INTERVAL_SECONDS,
        "diagnostics_enabled": DIAGNOSTICS_ENABLED,
        "cpu_percent": round(psutil.cpu_percent(interval=0.2), 2),
        "memory_percent": round(memory.percent, 2),
        "disk_percent": round(disk.percent, 2),
        "memory_used_bytes": memory.used,
        "memory_total_bytes": memory.total,
        "disk_used_bytes": disk.used,
        "disk_total_bytes": disk.total,
    }


def check_server() -> dict:
    request = urllib.request.Request(f"{SERVER_URL}/api/agent/health", method="GET")
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"Unexpected LIIMS health response: {response.status}")
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("status") != "healthy":
        raise RuntimeError("LIIMS agent ingress did not report a healthy status")
    return payload


def submit() -> dict:
    request = urllib.request.Request(
        f"{SERVER_URL}/api/agent/metrics",
        data=json.dumps(collect_payload()).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Agent-Token": AGENT_TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 201:
            raise RuntimeError(f"Unexpected LIIMS response: {response.status}")
        return json.loads(response.read().decode("utf-8"))


def run_fixed_command(arguments: list[str], timeout: int = 20) -> str:
    executable = shutil.which(arguments[0])
    if executable is None:
        raise RuntimeError(f"Required diagnostic tool is not installed: {arguments[0]}")
    completed = subprocess.run(
        [executable, *arguments[1:]],
        shell=False,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    output = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0:
        raise RuntimeError(f"{arguments[0]} exited with code {completed.returncode}: {output[:1000]}")
    return output[:MAX_RESULT_CHARACTERS]


def collect_service_scan(_parameters: dict) -> dict:
    output = run_fixed_command(
        ["nmap", "-sV", "--version-light", "-T3", "--host-timeout", "30s", "-Pn", "127.0.0.1"],
        timeout=40,
    )
    return {"scope": "local agent host", "tool": "nmap", "output": output}


def collect_packet_metadata(parameters: dict) -> dict:
    try:
        from scapy.all import IP, IPv6, TCP, UDP, sniff
    except ImportError as exc:
        raise RuntimeError("Scapy is required for packet metadata capture") from exc

    duration = min(30, max(1, int(parameters.get("duration_seconds", 10))))
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    records = []

    def observe(packet) -> None:
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        records.append({
            "source_ip": getattr(network, "src", None),
            "destination_ip": getattr(network, "dst", None),
            "protocol": "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP" if network else packet.name[:20],
            "source_port": getattr(transport, "sport", None),
            "destination_port": getattr(transport, "dport", None),
            "length_bytes": len(packet),
        })

    sniff(timeout=duration, count=maximum, prn=observe, store=False, promisc=False)
    return {
        "scope": "default local interface",
        "duration_seconds": duration,
        "captured_packets": len(records),
        "packets": records,
    }


def collect_security_log(parameters: dict) -> dict:
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    if platform.system() == "Windows":
        query = "*[System[(Level=1 or Level=2 or Level=3)]]"
        output = run_fixed_command(
            ["wevtutil", "qe", "System", f"/q:{query}", f"/c:{maximum}", "/rd:true", "/f:text"],
            timeout=25,
        )
        return {"source": "Windows System event log", "output": output}
    output = run_fixed_command(
        ["journalctl", "-p", "warning..alert", "-n", str(maximum), "--no-pager", "-o", "short-iso"],
        timeout=25,
    )
    return {"source": "systemd journal", "output": output}


def collect_connections(parameters: dict) -> dict:
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    items = []
    for connection in psutil.net_connections(kind="inet"):
        process_name = None
        if connection.pid:
            try:
                process_name = psutil.Process(connection.pid).name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        local = f"{connection.laddr.ip}:{connection.laddr.port}" if connection.laddr else None
        remote = f"{connection.raddr.ip}:{connection.raddr.port}" if connection.raddr else None
        items.append({
            "local_address": local,
            "remote_address": remote,
            "status": connection.status,
            "pid": connection.pid,
            "process": process_name,
        })
    items.sort(key=lambda item: (item["status"] != "LISTEN", item["process"] or "", item["local_address"] or ""))
    routes: object = []
    try:
        if platform.system() == "Windows":
            script = (
                "Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric "
                "| Sort-Object DestinationPrefix,RouteMetric | ConvertTo-Json -Compress"
            )
            output = run_fixed_command(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=20,
            )
            routes = json.loads(output) if output else []
        elif shutil.which("ip"):
            output = run_fixed_command(["ip", "-j", "route", "show"], timeout=20)
            routes = json.loads(output) if output else []
        else:
            routes = run_fixed_command(["netstat", "-rn"], timeout=20)
    except (RuntimeError, json.JSONDecodeError) as exc:
        routes = {"error": str(exc)[:300]}
    return {
        "total_connections": len(items),
        "connections": items[:maximum],
        "routing_table": routes,
    }


def collect_processes(parameters: dict) -> dict:
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    for process in psutil.process_iter():
        try:
            process.cpu_percent(None)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    time.sleep(0.2)
    processes = []
    for process in psutil.process_iter(["pid", "name", "username", "memory_percent"]):
        try:
            processes.append({
                "pid": process.info["pid"],
                "name": process.info["name"],
                "username": process.info["username"],
                "cpu_percent": round(process.cpu_percent(None), 2),
                "memory_percent": round(process.info["memory_percent"] or 0, 2),
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    processes.sort(key=lambda item: (item["cpu_percent"], item["memory_percent"]), reverse=True)
    return {"total_processes": len(processes), "processes": processes[:maximum]}


def collect_suid_files(parameters: dict) -> dict:
    if platform.system() == "Windows":
        return {"supported": False, "reason": "SUID permissions apply to Unix-like systems only."}
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    output = run_fixed_command(["find", "/", "-xdev", "-perm", "-4000", "-type", "f", "-print"], timeout=30)
    paths = [line for line in output.splitlines() if line.strip()]
    return {"total_found": len(paths), "paths": paths[:maximum]}


def collect_login_history(parameters: dict) -> dict:
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    if platform.system() == "Windows":
        query = "*[System[(EventID=4624 or EventID=4625)]]"
        output = run_fixed_command(
            ["wevtutil", "qe", "Security", f"/q:{query}", f"/c:{maximum}", "/rd:true", "/f:text"],
            timeout=25,
        )
        return {"source": "Windows Security event log", "output": output}
    return {"source": "login history", "output": run_fixed_command(["last", "-a", "-n", str(maximum)])}


def collect_local_accounts(parameters: dict) -> dict:
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    if platform.system() == "Windows":
        script = (
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordExpires "
            f"| Select-Object -First {maximum} | ConvertTo-Json -Compress"
        )
        output = run_fixed_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
        try:
            accounts = json.loads(output) if output else []
        except json.JSONDecodeError:
            accounts = output
        return {"source": "Windows local users", "accounts": accounts}

    import pwd

    accounts = [{
        "name": account.pw_name,
        "uid": account.pw_uid,
        "gid": account.pw_gid,
        "home": account.pw_dir,
        "shell": account.pw_shell,
        "privileged": account.pw_uid == 0,
    } for account in pwd.getpwall()]
    return {"source": "local account database", "total_accounts": len(accounts), "accounts": accounts[:maximum]}


def collect_firewall_rules(parameters: dict) -> dict:
    maximum = min(500, max(10, int(parameters.get("max_records", 100))))
    if platform.system() == "Windows":
        script = (
            "Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action,Profile "
            f"| Select-Object -First {maximum} | ConvertTo-Json -Compress"
        )
        output = run_fixed_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=25)
        try:
            rules = json.loads(output) if output else []
        except json.JSONDecodeError:
            rules = output
        return {"source": "Windows Defender Firewall", "rules": rules}

    candidates = (
        ["nft", "list", "ruleset"],
        ["ufw", "status", "verbose"],
        ["firewall-cmd", "--list-all"],
        ["iptables", "-L", "-n", "-v"],
    )
    for command in candidates:
        if shutil.which(command[0]):
            return {"source": command[0], "output": run_fixed_command(command, timeout=25)}
    raise RuntimeError("No supported firewall management tool was found")


DIAGNOSTIC_COLLECTORS = {
    "SERVICE_SCAN": collect_service_scan,
    "PACKET_CAPTURE": collect_packet_metadata,
    "SECURITY_LOG_SUMMARY": collect_security_log,
    "NETWORK_CONNECTIONS": collect_connections,
    "TOP_PROCESSES": collect_processes,
    "SUID_AUDIT": collect_suid_files,
    "LOGIN_HISTORY": collect_login_history,
    "LOCAL_ACCOUNTS": collect_local_accounts,
    "FIREWALL_RULES": collect_firewall_rules,
}


def poll_diagnostic_job() -> dict | None:
    request = urllib.request.Request(
        f"{SERVER_URL}/api/agent/jobs/next",
        headers={"X-Agent-Token": AGENT_TOKEN},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status == 204:
            return None
        if response.status != 200:
            raise RuntimeError(f"Unexpected diagnostic polling response: {response.status}")
        return json.loads(response.read().decode("utf-8"))


def submit_diagnostic_result(job_id: int, status: str, result=None, error: str | None = None) -> dict:
    encoded_result = json.dumps(result, ensure_ascii=False, default=str) if result is not None else ""
    if len(encoded_result.encode("utf-8")) > 35_000:
        result = {
            "truncated": True,
            "reason": "The diagnostic result exceeded the agent transfer limit.",
            "preview": encoded_result[:20_000],
        }
    request = urllib.request.Request(
        f"{SERVER_URL}/api/agent/jobs/{job_id}/result",
        data=json.dumps({"status": status, "result": result, "error": error}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Agent-Token": AGENT_TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError(f"Unexpected diagnostic result response: {response.status}")
        return json.loads(response.read().decode("utf-8"))


def process_next_diagnostic_job() -> bool:
    job = poll_diagnostic_job()
    if job is None:
        return False
    job_id = int(job["id"])
    job_type = str(job["job_type"])
    collector = DIAGNOSTIC_COLLECTORS.get(job_type)
    if collector is None:
        submit_diagnostic_result(job_id, "FAILED", error="Unsupported diagnostic job type")
        return True
    LOGGER.info("Starting diagnostic job %s (%s)", job_id, job_type)
    try:
        result = collector(job.get("parameters") or {})
        submit_diagnostic_result(job_id, "COMPLETED", result=result)
        LOGGER.info("Diagnostic job %s completed", job_id)
    except Exception as exc:
        # This is the isolation boundary for optional OS diagnostic tools. A
        # collector failure must be reported instead of terminating the agent
        # or leaving the server-side job permanently running.
        LOGGER.warning("Diagnostic job %s failed: %s", job_id, exc)
        submit_diagnostic_result(job_id, "FAILED", error=str(exc)[:1000])
    return True


def configure_logging(log_file: str | None = None) -> None:
    LOGGER.setLevel(logging.INFO)
    LOGGER.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    LOGGER.addHandler(console)
    if log_file:
        path = Path(log_file).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(formatter)
        LOGGER.addHandler(file_handler)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LIIMS authenticated host metrics agent")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Check the agent ingress without sending metrics")
    mode.add_argument("--once", action="store_true", help="Submit one metric sample and exit")
    parser.add_argument("--log-file", help="Write rotating operational logs to this file")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.log_file)
    try:
        health = check_server()
        LOGGER.info("Agent ingress is healthy: %s", health.get("service", "LIIMS"))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, RuntimeError) as exc:
        if args.check or args.once:
            LOGGER.error("Agent ingress check failed: %s", exc)
            return 2
        LOGGER.warning("Initial ingress check failed; background retries will continue: %s", exc)
    if args.check:
        return 0
    if len(AGENT_TOKEN) < 20:
        LOGGER.error("LIIMS_AGENT_TOKEN is missing or invalid")
        return 3
    if args.once:
        try:
            submit()
            LOGGER.info("Metric sample submitted successfully")
            if DIAGNOSTICS_ENABLED:
                process_next_diagnostic_job()
            return 0
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, RuntimeError) as exc:
            LOGGER.error("Metric submission failed: %s", exc)
            return 4

    LOGGER.info("LIIMS agent %s reporting to %s every %ss", AGENT_VERSION, SERVER_URL, INTERVAL_SECONDS)
    consecutive_failures = 0
    while True:
        try:
            submit()
            consecutive_failures = 0
            LOGGER.info("Metric sample submitted")
            if DIAGNOSTICS_ENABLED:
                try:
                    process_next_diagnostic_job()
                except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, RuntimeError) as exc:
                    LOGGER.warning("Diagnostic polling failed: %s", exc)
            delay = INTERVAL_SECONDS
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, RuntimeError) as exc:
            consecutive_failures += 1
            delay = min(INTERVAL_SECONDS, max(5, 2 ** min(consecutive_failures, 8)))
            LOGGER.warning("Metric submission failed; retrying in %ss: %s", delay, exc)
        time.sleep(delay)


if __name__ == "__main__":
    raise SystemExit(main())
