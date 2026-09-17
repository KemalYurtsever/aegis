import ipaddress
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import json
import tempfile
import time

import psutil

from app.config import get_settings
from app.models import Device
from app.schemas import (
    DnsQueryRead,
    FirewallProfileRead,
    FirewallRuleSummary,
    HostNetworkPolicyRead,
    RouteEntryRead,
    TraceRouteHop,
    TraceRouteRead,
    WirelessAdapterRead,
    LabCommandRead,
)
from app.services.discovery_service import discover_responsive_hosts, get_primary_private_network
from app.services.mdns_service import discover_mdns
from app.services.port_scan_service import (
    NMAP_SERVICE_OPTIONS,
    NMAP_VERSION_ARGUMENTS,
    nmap_command_prefix,
    nmap_scan_provenance,
    nmap_tcp_scan_type,
    scan_nmap_top_tcp_ports,
)
from app.services.scan_policy import scan_target_rejection_reason


_WIRELESS_NAME = re.compile(r"wi[ -]?fi|wlan|wireless|802\.11", re.I)
_HOSTNAME = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.I,
)
_ADDRESS_TOKEN = re.compile(r"(?<![0-9a-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{2,})(?![0-9a-f:.])", re.I)
_LATENCY_TOKEN = re.compile(r"<?(\d+(?:\.\d+)?)\s*ms", re.I)
_MAX_TOOL_OUTPUT = 100_000
logger = logging.getLogger(__name__)
_DOCKER_TOOLBOX_COMMANDS = {
    "nmap", "nmap-udp", "arp-scan", "avahi-browse", "curl", "dig", "sslscan",
    "fping", "whatweb", "nikto", "openssl", "smbclient", "smb-audit", "host", "dnsrecon",
}

COMMON_UDP_PORTS = (
    53,
    67,
    69,
    123,
    137,
    161,
    500,
    514,
    520,
    623,
    1434,
    1900,
    4500,
    5060,
    5353,
    5683,
    10001,
    11211,
    20000,
    47808,
)


def tls_scan(address: str, port: int = 443, grep: str | None = None) -> LabCommandRead:
    rejection = scan_target_rejection_reason(address)
    if rejection:
        raise ValueError(rejection)
    if not 1 <= port <= 65535:
        raise ValueError("TLS port must be between 1 and 65535")
    address = str(ipaddress.ip_address(address))
    target = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    return _run_lab_tool(
        "sslscan",
        ["sslscan", "--no-colour", "--no-heartbleed", "--timeout=3", target],
        target=target, grep=grep, timeout=60,
    )


def _registered_address(address: str) -> str:
    rejection = scan_target_rejection_reason(address)
    if rejection:
        raise ValueError(rejection)
    return str(ipaddress.ip_address(address))


def _host_port(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _http_target(address: str, scheme: str, port: int, path: str) -> str:
    if scheme not in {"http", "https"}:
        raise ValueError("Web scheme must be HTTP or HTTPS")
    if not 1 <= port <= 65535:
        raise ValueError("Web port must be between 1 and 65535")
    normalized_path = path if path.startswith("/") else f"/{path}"
    return f"{scheme}://{_host_port(address, port)}{normalized_path}"


def fping_probe(address: str, grep: str | None = None) -> LabCommandRead:
    """Send three bounded ICMP probes to one registered unicast device."""
    target = _registered_address(address)
    return _run_lab_tool(
        "fping", ["fping", "-c", "3", "-p", "250", "-t", "1000", target],
        target=target, grep=grep, timeout=10,
    )


def whatweb_scan(
    address: str,
    scheme: str,
    port: int,
    path: str = "/",
    grep: str | None = None,
) -> LabCommandRead:
    """Fingerprint one registered web endpoint with WhatWeb's lightest profile."""
    target = _http_target(_registered_address(address), scheme, port, path)
    return _run_lab_tool(
        "whatweb",
        [
            "whatweb", "--aggression=1", "--max-threads=2", "--open-timeout=5",
            "--read-timeout=10", "--no-errors", "--colour=never", target,
        ],
        target=target, grep=grep, timeout=30,
    )


def nikto_scan(
    address: str,
    scheme: str,
    port: int,
    path: str = "/",
    grep: str | None = None,
) -> LabCommandRead:
    """Run a short, non-interactive Nikto assessment against one registered endpoint."""
    target = _http_target(_registered_address(address), scheme, port, path)
    return _run_lab_tool(
        "nikto",
        [
            "nikto", "-host", target, "-maxtime", "45s", "-timeout", "5",
            "-nointeractive", "-ask", "no",
        ],
        target=target, grep=grep, timeout=55,
    )


def openssl_probe(address: str, port: int = 443, grep: str | None = None) -> LabCommandRead:
    """Inspect the certificate chain and negotiated TLS parameters without sending application data."""
    target_address = _registered_address(address)
    if not 1 <= port <= 65535:
        raise ValueError("TLS port must be between 1 and 65535")
    target = _host_port(target_address, port)
    return _run_lab_tool(
        "openssl",
        ["openssl", "s_client", "-connect", target, "-brief", "-showcerts", "-no_ign_eof"],
        target=target, grep=grep, timeout=25,
    )


def smbclient_scan(address: str, grep: str | None = None) -> LabCommandRead:
    """List SMB services using an anonymous session; credentials are never accepted."""
    target = _registered_address(address)
    return _run_lab_tool(
        "smbclient",
        ["smbclient", "-L", f"//{target}", "-N", "-g", "--option=client min protocol=SMB2"],
        target=target, grep=grep, timeout=30,
    )


def smb_posture_scan(address: str, grep: str | None = None) -> LabCommandRead:
    """Read SMB protocol and signing posture with non-credentialed Nmap scripts."""
    target = _registered_address(address)
    command = [
        "nmap", "-Pn", "-n", "-p", "445", "--host-timeout", "45s",
        "--script", "smb-protocols,smb2-security-mode,smb2-time", target,
    ]
    if ipaddress.ip_address(target).version == 6:
        command.insert(-1, "-6")
    return _run_lab_tool("smb-audit", command, target=target, grep=grep, timeout=55)


def host_query(query: str, grep: str | None = None) -> LabCommandRead:
    return _run_lab_tool(
        "host", ["host", "-W", "3", query], target=query, grep=grep, timeout=10,
    )


def dnsrecon_standard(query: str, grep: str | None = None) -> LabCommandRead:
    """Run only DNSRecon's standard record enumeration; brute force and reverse ranges are unavailable."""
    return _run_lab_tool(
        "dnsrecon",
        ["dnsrecon", "-d", query, "-t", "std", "--threads", "2", "--lifetime", "3"],
        target=query, grep=grep, timeout=45,
    )


def _filter_output(output: str, grep: str | None) -> str:
    if not grep:
        return output
    needle = grep.casefold()
    return "\n".join(line for line in output.splitlines() if needle in line.casefold())


def _run_lab_tool(
    tool: str,
    command: list[str],
    *,
    target: str | None = None,
    grep: str | None = None,
    timeout: int = 60,
    scanned_port_count: int | None = None,
    environment: dict[str, str] | None = None,
    input_text: str | None = None,
    contain_timeout: bool = False,
) -> LabCommandRead:
    executable = shutil.which(command[0])
    execution_context = "Host-local executable"
    if executable is None:
        container = os.getenv("AEGIS_NETWORK_TOOLBOX_CONTAINER", "").strip()
        docker = shutil.which("docker")
        if tool not in _DOCKER_TOOLBOX_COMMANDS or not container or docker is None:
            raise RuntimeError(f"{command[0]} is not installed on the AEGIS host and no Docker toolbox is available")
        inner_command = (["timeout", "--kill-after=2", f"{max(1, timeout - 3)}s", *command]
                         if contain_timeout else command)
        command = [docker, "exec", *(["-i"] if input_text is not None else []), container, *inner_command]
        executable = command[0]
        execution_context = f"Docker toolbox {container}"
    executed_command = [executable, *command[1:]]
    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as output_file:
        try:
            completed = subprocess.run(
                executed_command, stdout=output_file, stderr=subprocess.STDOUT,
                timeout=timeout, shell=False, check=False,
                **({"stdin": subprocess.DEVNULL} if input_text is None else {"input": input_text.encode("ascii")}),
                env={**os.environ, **(environment or {})},
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
        output_file.seek(0)
        encoded = output_file.read(_MAX_TOOL_OUTPUT + 1)
    truncated = len(encoded) > _MAX_TOOL_OUTPUT
    output = encoded[:_MAX_TOOL_OUTPUT].decode("utf-8", errors="replace").strip()
    if timed_out:
        output = f"{output}\nCommand timed out after {timeout} seconds".strip()
    if truncated:
        output += "\n[output truncated]"
    output = _filter_output(output, grep)
    duration_ms = round((time.monotonic() - started) * 1000, 2)
    logger.info(
        "Network tool completed tool=%s target=%s exit_code=%s duration_ms=%s timed_out=%s",
        tool,
        target,
        exit_code,
        duration_ms,
        timed_out,
    )
    return LabCommandRead(
        tool=tool, target=target, exit_code=exit_code, output=output,
        duration_ms=duration_ms, truncated=truncated,
        scanned_port_count=scanned_port_count if exit_code == 0 else None,
        command=executed_command, execution_context=execution_context,
    )


def _nmap_result_output(
    output: str,
    prefix: list[str] | None,
    commands: list[list[str]],
    grep: str | None,
) -> str:
    if not grep:
        version = re.search(r"Starting Nmap (\S+)", output)
        provenance = nmap_scan_provenance(
            prefix, [*(prefix or ["nmap"]), *commands[0][1:]],
            version.group(1) if version else None,
        )
        lines = [
            "Scan provenance",
            f"Execution: {provenance['execution_context']}",
            "TCP scan: " + " → ".join(dict.fromkeys(
                nmap_scan_provenance(prefix, command)["tcp_scan_type"]
                for command in commands
            )),
        ]
        if "engine_version" in provenance:
            lines.append(f"Engine: Nmap {provenance['engine_version']}")
        for index, command in enumerate(commands, 1):
            actual = [*(prefix or ["nmap"]), *command[1:]]
            caption = nmap_scan_provenance(prefix, actual)["command"]
            lines.append(f"Command {index}: {caption}")
        header = "\n".join(lines)
        output = f"{header}\n\n{output}".strip()
    output = _filter_output(output, grep)
    return output or (f"No Nmap output matched {grep!r}." if grep else output)


def nmap_tcp_scan(
    address: str,
    ports: list[int],
    service_detection: bool,
    grep: str | None = None,
    scan_mode: str = "CUSTOM",
    profile: str = "FAST",
    show_reason: bool = False,
    traffic_policy: str = "IDS_FRIENDLY",
    discovery_profile: str | None = None,
) -> LabCommandRead:
    rejection = scan_target_rejection_reason(address)
    if rejection:
        raise ValueError(rejection)
    profiles = {"FAST", "FAST_VERSION", "DETAILED", "AGGRESSIVE"}
    if profile not in profiles:
        raise ValueError("Unknown Nmap scan profile")
    if traffic_policy not in {"IDS_FRIENDLY", "FAST"}:
        raise ValueError("Unknown Nmap traffic policy")
    if discovery_profile is not None and discovery_profile not in profiles:
        raise ValueError("Unknown Nmap discovery profile")
    traffic_arguments = (
        ["--max-rate", "100", "--scan-delay", "10ms"]
        if traffic_policy == "IDS_FRIENDLY"
        else ["--min-rate", "500"]
    )
    discovery_host_timeout = "15s" if traffic_policy == "IDS_FRIENDLY" else "10s"
    discovery_process_timeout = 25 if traffic_policy == "IDS_FRIENDLY" else 20
    discovery_retry = "0"
    discovery_depth = discovery_profile or profile
    if discovery_depth in {"DETAILED", "AGGRESSIVE"}:
        discovery_retry = "1" if discovery_depth == "DETAILED" else "2"
        discovery_host_timeout = "30s" if discovery_depth == "DETAILED" else "45s"
        discovery_process_timeout = 40 if discovery_depth == "DETAILED" else 55
    if service_detection and profile == "FAST":
        profile = "FAST_VERSION"
    prefix = nmap_command_prefix()
    scan_type = nmap_tcp_scan_type(prefix)
    top_1000 = scan_mode == "TOP_1000"
    if top_1000 and prefix is None:
        result = scan_nmap_top_tcp_ports(address)
        lines = [
            "Nmap-ranked TCP connect scan",
            f"Scanned ports: {len(result.scanned_ports)}",
            "PORT     STATE SERVICE",
        ]
        lines.extend(
            f"{port.port}/tcp  open  {port.service}"
            for port in result.open_ports
        )
        if not result.open_ports:
            lines.append("No open TCP ports found.")
        if profile != "FAST":
            lines.append("Service-version detection requires the Nmap executable; socket results show known service names only.")
        if show_reason:
            lines.append("Port-state reasons require the Nmap executable and are unavailable in the socket fallback.")
        return LabCommandRead(
            tool="nmap",
            target=address,
            exit_code=0,
            output=_filter_output("\n".join(lines), grep),
            duration_ms=result.duration_ms,
            scanned_port_count=len(result.scanned_ports),
        )

    # Version detection is disproportionately expensive when Nmap runs it over
    # every candidate port. Discover open ports first, then fingerprint only the
    # ports that answered. This also preserves useful discovery results if the
    # fingerprinting phase reaches its time limit.
    if top_1000 and profile != "FAST":
        discovery_command = [
            "nmap", "-Pn", scan_type, "-n", "-T4", "--max-retries", discovery_retry,
            *traffic_arguments, "--initial-rtt-timeout", "100ms",
            "--max-rtt-timeout", "500ms", "--host-timeout", discovery_host_timeout,
            "--top-ports", "1000", "--open",
        ]
        if ipaddress.ip_address(address).version == 6:
            discovery_command.append("-6")
        if show_reason:
            discovery_command.append("--reason")
        discovery_command.append(address)
        discovery = _run_lab_tool(
            "nmap", discovery_command, target=address, grep=None,
            timeout=discovery_process_timeout,
            scanned_port_count=1000,
        )
        discovery_incomplete = (
            discovery.exit_code != 0
            or re.search(
                r"(?im)(skipping host .* due to host timeout|command timed out after)",
                discovery.output,
            )
            is not None
        )
        if discovery_incomplete:
            output = (
                f"Phase 1 - fast top-1,000 port discovery\n{discovery.output}\n\n"
                "Discovery did not complete; open-port status is incomplete."
            ).strip()
            output = _nmap_result_output(output, prefix, [discovery_command], grep)
            return discovery.model_copy(
                update={"output": output, "scanned_port_count": None}
            )

        open_ports = sorted(
            {
                int(match)
                for match in re.findall(
                    r"(?m)^(\d+)/tcp\s+open\b", discovery.output
                )
            }
        )
        if not open_ports:
            output = (
                f"Phase 1 - fast top-1,000 port discovery\n{discovery.output}\n\n"
                "No open TCP ports were found among Nmap's top 1,000 ports."
            ).strip()
            output = _nmap_result_output(output, prefix, [discovery_command], grep)
            return discovery.model_copy(update={"output": output})

        selected = NMAP_SERVICE_OPTIONS[profile]
        fingerprint_command = [
            "nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", selected["retry"],
            "--host-timeout", selected["host_timeout"],
        ]
        fingerprint_timeout = selected["process_timeout"]
        fingerprint_command.extend(
            [*traffic_arguments, "-p", ",".join(map(str, open_ports)), "--open"]
        )
        if ipaddress.ip_address(address).version == 6:
            fingerprint_command.append("-6")
        fingerprint_command.extend(["-sV", *NMAP_VERSION_ARGUMENTS[profile]])
        if show_reason:
            fingerprint_command.append("--reason")
        fingerprint_command.append(address)
        fingerprint = _run_lab_tool(
            "nmap", fingerprint_command, target=address, grep=None,
            timeout=fingerprint_timeout, scanned_port_count=len(open_ports),
        )
        fingerprint_incomplete = (
            fingerprint.exit_code != 0
            or re.search(
                r"(?im)(skipping host .* due to host timeout|command timed out after)",
                fingerprint.output,
            )
            is not None
        )
        fingerprint_note = (
            "\n\nService detection reached its time limit; Phase 1 open-port "
            "results remain valid, but service details may be incomplete."
            if fingerprint_incomplete
            else ""
        )
        output = (
            f"Phase 1 - fast top-1,000 port discovery\n{discovery.output}\n\n"
            f"Phase 2 - {profile.replace('_', ' ').title()} service detection "
            f"on {len(open_ports)} open port{'s' if len(open_ports) != 1 else ''}\n"
            f"{fingerprint.output}{fingerprint_note}"
        ).strip()
        output = _nmap_result_output(
            output, prefix, [discovery_command, fingerprint_command], grep,
        )
        return fingerprint.model_copy(
            update={
                "output": output,
                "duration_ms": round(
                    discovery.duration_ms + fingerprint.duration_ms, 2
                ),
                "truncated": discovery.truncated or fingerprint.truncated,
                "scanned_port_count": 1000,
            }
        )

    if profile in {"FAST", "FAST_VERSION"}:
        command = [
            "nmap", "-Pn", scan_type if profile == "FAST" else "-sT", "-n", "-T4", "--max-retries", discovery_retry,
            *traffic_arguments, "--initial-rtt-timeout", "100ms",
            "--max-rtt-timeout", "500ms", "--host-timeout", discovery_host_timeout,
        ]
        timeout = discovery_process_timeout
    else:
        selected = NMAP_SERVICE_OPTIONS[profile]
        command = [
            "nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", selected["retry"],
            *traffic_arguments, "--host-timeout", selected["host_timeout"],
        ]
        timeout = selected["process_timeout"]

    if top_1000:
        command.extend(["--top-ports", "1000", "--open"])
        scanned_port_count = 1000
    else:
        command.extend(["-p", ",".join(map(str, ports))])
        scanned_port_count = len(ports)
    if ipaddress.ip_address(address).version == 6:
        command.append("-6")
    # FAST is the UI's ports-only profile. Keep the legacy service_detection
    # switch compatible by promoting it to FAST_VERSION above, but do not run
    # version probes for an ordinary FAST scan.
    if profile != "FAST":
        command.extend(["-sV", *NMAP_VERSION_ARGUMENTS[profile]])
    if show_reason:
        command.append("--reason")
    command.append(address)
    result = _run_lab_tool(
        "nmap", command, target=address, grep=grep, timeout=timeout,
        scanned_port_count=scanned_port_count,
    )
    if not grep:
        result = result.model_copy(update={
            "output": _nmap_result_output(result.output, prefix, [command], None),
        })
    if (
        not grep
        and re.search(
            r"(?im)(skipping host .* due to host timeout|command timed out after)",
            result.output,
        )
    ):
        incomplete_note = (
            "Discovery did not complete; open-port status is incomplete."
            if profile == "FAST"
            else "Service detection did not complete; port and version evidence is incomplete."
        )
        return result.model_copy(
            update={
                "output": f"{result.output}\n\n{incomplete_note}".strip(),
                "scanned_port_count": None,
            }
        )
    if result.exit_code == 0 and grep and not result.output:
        return result.model_copy(update={"output": f"No Nmap output matched {grep!r}."})
    if (
        result.exit_code == 0
        and top_1000
        and not grep
        and not re.search(
            r"(?im)(skipping host .* due to host timeout|command timed out after)",
            result.output,
        )
        and not re.search(r"(?m)^\d+/tcp\s+open\b", result.output)
    ):
        summary = "No open TCP ports were found among Nmap's top 1,000 ports."
        return result.model_copy(update={"output": f"{result.output}\n\n{summary}".strip()})
    return result


def nmap_udp_scan(
    address: str,
    ports: list[int] | None = None,
    profile: str = "FAST",
    show_reason: bool = True,
    grep: str | None = None,
) -> LabCommandRead:
    rejection = scan_target_rejection_reason(address)
    if rejection:
        raise ValueError(rejection)
    target = str(ipaddress.ip_address(address))
    normalized_ports = list(dict.fromkeys(ports or COMMON_UDP_PORTS))
    if not normalized_ports or len(normalized_ports) > 64:
        raise ValueError("UDP scanning accepts between 1 and 64 ports")
    if any(port < 1 or port > 65535 for port in normalized_ports):
        raise ValueError("Ports must be between 1 and 65535")

    options = {
        "FAST": {"retries": "0", "host_timeout": "15s", "timeout": 25, "version": ()},
        "DETAILED": {
            "retries": "1",
            "host_timeout": "60s",
            "timeout": 70,
            "version": ("-sV", "--version-light"),
        },
        "AGGRESSIVE": {
            "retries": "2",
            "host_timeout": "120s",
            "timeout": 130,
            "version": ("-sV", "--version-all"),
        },
    }.get(profile.upper())
    if options is None:
        raise ValueError("Unknown UDP scan profile")

    command = [
        "nmap", "-Pn", "-sU", "-n", "-T4", "--max-retries", options["retries"],
        "--host-timeout", options["host_timeout"], "--open", "-p",
        ",".join(map(str, normalized_ports)), *options["version"],
    ]
    if show_reason:
        command.append("--reason")
    if ipaddress.ip_address(target).version == 6:
        command.append("-6")
    command.append(target)
    return _run_lab_tool(
        "nmap-udp",
        command,
        target=target,
        grep=grep,
        timeout=options["timeout"],
        scanned_port_count=len(normalized_ports),
    )


def test_connection_ports(
    address: str,
    ports: list[int],
    timeout_seconds: int = 2,
    grep: str | None = None,
) -> LabCommandRead:
    rejection = scan_target_rejection_reason(address)
    if rejection:
        raise ValueError(rejection)
    target = str(ipaddress.ip_address(address))
    normalized_ports = list(dict.fromkeys(ports))
    if not normalized_ports or len(normalized_ports) > 128:
        raise ValueError("Test-Connection accepts between 1 and 128 ports")
    if any(port < 1 or port > 65535 for port in normalized_ports):
        raise ValueError("Ports must be between 1 and 65535")
    if timeout_seconds < 1 or timeout_seconds > 10:
        raise ValueError("Timeout must be between 1 and 10 seconds")

    pwsh = shutil.which("pwsh")
    if pwsh:
        script = (
            "$targetAddress=$env:AEGIS_TCP_TEST_TARGET;"
            "$timeout=[int]$env:AEGIS_TCP_TEST_TIMEOUT;"
            "$rows=($env:AEGIS_TCP_TEST_PORTS -split ',') | ForEach-Object -Parallel {"
            "$port=[int]$_;"
            "$result=Test-Connection -TargetName $using:targetAddress -TcpPort $port -Count 1 -TimeoutSeconds $using:timeout -Detailed -ErrorAction SilentlyContinue;"
            "$detail=if($result){[string]$result.Status}else{'TimedOut'};"
            "$state=if($result -and $result.Connected){'Open'}elseif($detail -eq 'ConnectionRefused'){'Closed'}elseif($detail -eq 'TimedOut'){'NoResponse'}else{'Error'};"
            "$latency=if($state -eq 'Open'){$result.Latency}else{$null};"
            "[pscustomobject]@{Target=$using:targetAddress;Port=$port;State=$state;LatencyMs=$latency;Detail=$detail}} -ThrottleLimit 32;"
            "$openCount=@($rows | Where-Object State -eq 'Open').Count;"
            "$closedCount=@($rows | Where-Object State -eq 'Closed').Count;"
            "$noResponseCount=@($rows | Where-Object State -eq 'NoResponse').Count;"
            "$errorCount=@($rows | Where-Object State -eq 'Error').Count;"
            "Write-Output 'Engine: PowerShell 7 Test-Connection -TcpPort';"
            "Write-Output ('Scan completed: {0} ports checked; {1} open; {2} closed/refused; {3} no response; {4} errors.' -f $rows.Count,$openCount,$closedCount,$noResponseCount,$errorCount);"
            "if($openCount -eq 0){Write-Output 'No open ports were found.'};"
            "Write-Output '';"
            "$rows | Sort-Object @{Expression={if($_.State -eq 'Open'){0}else{1}}},Port | Format-Table Target,Port,State,LatencyMs,Detail -AutoSize"
        )
        command = [pwsh, "-NoProfile", "-NonInteractive", "-Command", script]
        process_timeout = min(60, ((len(normalized_ports) + 31) // 32) * timeout_seconds + 15)
    else:
        powershell = shutil.which("powershell.exe")
        if not powershell:
            raise RuntimeError("PowerShell Test-Connection is not available on the AEGIS host")
        script = (
            "$targetAddress=$env:AEGIS_TCP_TEST_TARGET;"
            "$timeoutMs=1000*[int]$env:AEGIS_TCP_TEST_TIMEOUT;"
            "$probes=foreach($portText in ($env:AEGIS_TCP_TEST_PORTS -split ',')){"
            "$port=[int]$portText;"
            "$client=New-Object System.Net.Sockets.TcpClient;"
            "$timer=[Diagnostics.Stopwatch]::StartNew();"
            "try{$async=$client.BeginConnect($targetAddress,$port,$null,$null);"
            "[pscustomobject]@{Port=$port;Client=$client;Async=$async;Timer=$timer;StartError=$null}}"
            "catch{[pscustomobject]@{Port=$port;Client=$client;Async=$null;Timer=$timer;StartError=$_.Exception.Message}}};"
            "$deadline=[DateTime]::UtcNow.AddMilliseconds($timeoutMs);"
            "$rows=foreach($probe in $probes){"
            "$state='NoResponse';$detail='TimedOut';$latency=$null;"
            "try{if($probe.StartError){$state='Error';$detail=$probe.StartError}else{"
            "$remaining=[Math]::Max(0,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds);"
            "if($probe.Async.AsyncWaitHandle.WaitOne($remaining)){"
            "$probe.Client.EndConnect($probe.Async);"
            "if($probe.Client.Connected){$state='Open';$detail='Success';$latency=[Math]::Round($probe.Timer.Elapsed.TotalMilliseconds,2)}else{$state='Error';$detail='ConnectFailed'}}}}"
            "catch{$exception=$_.Exception;while($exception.InnerException){$exception=$exception.InnerException};"
            "if($exception -is [System.Net.Sockets.SocketException]){$detail=[string]$exception.SocketErrorCode;if($detail -eq 'ConnectionRefused'){$state='Closed'}elseif($detail -eq 'TimedOut'){$state='NoResponse'}else{$state='Error'}}else{$state='Error';$detail=$exception.Message}}"
            "finally{if($probe.Async){$probe.Async.AsyncWaitHandle.Close()};$probe.Client.Close()};"
            "[pscustomobject]@{Target=$targetAddress;Port=$probe.Port;State=$state;LatencyMs=$latency;Detail=$detail}};"
            "$openCount=@($rows | Where-Object State -eq 'Open').Count;"
            "$closedCount=@($rows | Where-Object State -eq 'Closed').Count;"
            "$noResponseCount=@($rows | Where-Object State -eq 'NoResponse').Count;"
            "$errorCount=@($rows | Where-Object State -eq 'Error').Count;"
            "Write-Output 'Engine: Windows PowerShell .NET TcpClient';"
            "Write-Output ('Scan completed: {0} ports checked; {1} open; {2} closed/refused; {3} no response; {4} errors.' -f $rows.Count,$openCount,$closedCount,$noResponseCount,$errorCount);"
            "if($openCount -eq 0){Write-Output 'No open ports were found.'};"
            "Write-Output '';"
            "$rows | Sort-Object @{Expression={if($_.State -eq 'Open'){0}else{1}}},Port | Format-Table Target,Port,State,LatencyMs,Detail -AutoSize"
        )
        command = [powershell, "-NoProfile", "-NonInteractive", "-Command", script]
        process_timeout = timeout_seconds + 12

    return _run_lab_tool(
        "test-connection",
        command,
        target=target,
        grep=grep,
        timeout=process_timeout,
        scanned_port_count=len(normalized_ports),
        environment={
            "AEGIS_TCP_TEST_TARGET": target,
            "AEGIS_TCP_TEST_PORTS": ",".join(map(str, normalized_ports)),
            "AEGIS_TCP_TEST_TIMEOUT": str(timeout_seconds),
        },
    )


def arp_scan(interface_name: str | None = None, grep: str | None = None) -> LabCommandRead:
    if platform.system() == "Windows" and shutil.which("arp-scan") is None:
        started = time.monotonic()
        network = get_primary_private_network()
        if interface_name and interface_name.casefold() != network.interface_name.casefold():
            raise RuntimeError(f"The active physical interface is {network.interface_name}")
        responsive = discover_responsive_hosts(network)
        cached = {address: mac for address, mac in responsive if mac}
        lines = [f"Interface: {network.interface_name}\tNetwork: {network.network}"]
        lines.extend(f"{address}\t{mac}" for address, mac in sorted(cached.items(), key=lambda item: ipaddress.ip_address(item[0])))
        output = _filter_output("\n".join(lines), grep)
        return LabCommandRead(
            tool="arp-scan", target=network.network, exit_code=0, output=output,
            duration_ms=round((time.monotonic() - started) * 1000, 2), truncated=False,
        )
    command = ["arp-scan", "--localnet", "--retry", "2", "--timeout", "500"]
    if interface_name:
        command.extend(["--interface", interface_name])
    return _run_lab_tool("arp-scan", command, grep=grep, timeout=45)


def avahi_browse(grep: str | None = None) -> LabCommandRead:
    """Browse bounded DNS-SD records without publishing an Aegis service."""
    if platform.system() == "Windows":
        started = time.monotonic()
        network = get_primary_private_network()
        records = discover_mdns(
            network,
            get_settings().discovery_mdns_timeout_seconds,
        )
        subnet = ipaddress.ip_network(network.network, strict=True)
        rows = []
        for address, details in sorted(records.items(), key=lambda item: ipaddress.ip_address(item[0])):
            if ipaddress.ip_address(address) not in subnet:
                continue
            rows.append("\t".join([
                address,
                details.get("display_name") or "-",
                details.get("model") or "-",
                details.get("hostname") or "-",
                ",".join(details.get("services") or []) or "-",
            ]))
        if grep:
            output = _filter_output("\n".join(rows), grep)
            if not output:
                output = f"No host-interface mDNS records matched {grep!r}."
        elif rows:
            output = "\n".join([
                f"Interface: {network.interface_name} ({network.local_ip})",
                "ADDRESS\tNAME\tMODEL\tHOSTNAME\tSERVICES",
                *rows,
            ])
        else:
            output = (
                f"No DNS-SD services were observed on {network.interface_name} "
                f"({network.local_ip}) during the bounded host-interface browse."
            )
        return LabCommandRead(
            tool="avahi-browse",
            target=f"{network.interface_name} {network.network}",
            exit_code=0,
            output=output,
            duration_ms=round((time.monotonic() - started) * 1000, 2),
        )

    result = _run_lab_tool(
        "avahi-browse",
        [
            "avahi-browse",
            "--all",
            "--resolve",
            "--terminate",
            "--no-db-lookup",
            "--ignore-local",
        ],
        target="local mDNS",
        grep=grep,
        timeout=12,
    )
    if result.exit_code == 0 and not result.output.strip():
        message = (
            "No Avahi output matched the filter."
            if grep
            else "No DNS-SD services were visible inside Docker. Use Discover network for host-interface mDNS discovery."
        )
        return result.model_copy(update={"output": message})
    return result


def neighbor_table(grep: str | None = None) -> LabCommandRead:
    if platform.system() == "Windows":
        command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-NetNeighbor | Sort-Object InterfaceIndex,IPAddress | Format-Table -AutoSize"]
    else:
        command = ["ip", "neigh", "show"]
    return _run_lab_tool("ip-neigh", command, grep=grep, timeout=15)


def curl_request(url: str, method: str, insecure: bool, grep: str | None = None) -> LabCommandRead:
    command = [
        "curl", "--silent", "--show-error", "--location", "--max-time", "20",
        "--max-filesize", "1048576", "--limit-rate", "1M", "--proto", "=http,https",
        "--proto-redir", "=http,https", "--request", method,
    ]
    if method == "HEAD":
        command.append("--head")
    if insecure:
        command.append("--insecure")
    command.extend(["--", url])
    return _run_lab_tool("curl", command, target=url, grep=grep, timeout=25)


def dig_query(query: str, record_type: str, grep: str | None = None) -> LabCommandRead:
    if platform.system() == "Windows" and shutil.which("dig") is None:
        return _run_lab_tool(
            "dig", ["nslookup", f"-type={record_type}", query],
            target=query, grep=grep, timeout=10,
        )
    return _run_lab_tool("dig", ["dig", "+time=3", "+tries=1", query, record_type], target=query, grep=grep, timeout=10)


def _valid_address_token(line: str) -> str | None:
    for token in _ADDRESS_TOKEN.findall(line):
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return None


def parse_traceroute(output: str) -> list[TraceRouteHop]:
    hops: list[TraceRouteHop] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d{1,2})\s+(.+)$", line)
        if not match:
            continue
        remainder = match.group(2)
        latencies = [float(value) for value in _LATENCY_TOKEN.findall(remainder)]
        hops.append(TraceRouteHop(
            hop=int(match.group(1)),
            address=_valid_address_token(remainder),
            latency_ms=round(min(latencies), 2) if latencies else None,
            timed_out="*" in remainder and not latencies,
        ))
    return hops[:16]


def trace_registered_device(device: Device) -> TraceRouteRead:
    rejection = scan_target_rejection_reason(device.ip_address)
    if rejection:
        raise ValueError(rejection)
    is_windows = platform.system() == "Windows"
    executable = "tracert" if is_windows else "traceroute"
    if shutil.which(executable) is None:
        raise RuntimeError(f"{executable} is not installed on the AEGIS host")
    command = (
        [executable, "-d", "-h", "12", "-w", "750", device.ip_address]
        if is_windows
        else [executable, "-n", "-m", "12", "-w", "1", device.ip_address]
    )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=20,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = "\n".join(part for part in (exc.stdout, exc.stderr) if isinstance(part, str))
        return TraceRouteRead(
            device_id=device.id,
            device_name=device.name,
            target=device.ip_address,
            completed=False,
            hops=parse_traceroute(output),
        )
    return TraceRouteRead(
        device_id=device.id,
        device_name=device.name,
        target=device.ip_address,
        completed=completed.returncode == 0,
        hops=parse_traceroute(f"{completed.stdout}\n{completed.stderr}"),
    )


def query_dns(query: str) -> DnsQueryRead:
    try:
        address = ipaddress.ip_address(query)
    except ValueError:
        ascii_query = query.encode("idna").decode("ascii")
        if not _HOSTNAME.fullmatch(ascii_query):
            raise ValueError("Enter a valid hostname or IP address")
        try:
            records = socket.getaddrinfo(ascii_query, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            records = []
        addresses = sorted({record[4][0] for record in records}, key=lambda item: (":" in item, item))
        canonical = socket.getfqdn(ascii_query) if addresses else None
        return DnsQueryRead(
            query=query,
            canonical_name=canonical if canonical and canonical != ascii_query else None,
            addresses=addresses,
            reverse_name=None,
        )

    try:
        reverse_name = socket.gethostbyaddr(str(address))[0]
    except (socket.herror, socket.gaierror):
        reverse_name = None
    return DnsQueryRead(
        query=query,
        canonical_name=None,
        addresses=[str(address)],
        reverse_name=reverse_name,
    )


def wireless_adapters() -> list[WirelessAdapterRead]:
    active_name = None
    try:
        active_name = get_primary_private_network().interface_name
    except (RuntimeError, ValueError, OSError):
        pass
    addresses_by_name = psutil.net_if_addrs()
    stats_by_name = psutil.net_if_stats()
    adapters: list[WirelessAdapterRead] = []
    for name, addresses in addresses_by_name.items():
        if not _WIRELESS_NAME.search(name):
            continue
        stat = stats_by_name.get(name)
        visible_addresses = sorted({
            item.address.split("%", 1)[0]
            for item in addresses
            if item.family in {socket.AF_INET, socket.AF_INET6}
            and not item.address.lower().startswith("fe80:")
        })
        speed = int(stat.speed) if stat and stat.speed and stat.speed > 0 else None
        adapters.append(WirelessAdapterRead(
            name=name,
            status="UP" if stat and stat.isup else "DOWN",
            addresses=visible_addresses,
            link_speed_mbps=speed,
            active_for_discovery=name == active_name,
        ))
    return sorted(adapters, key=lambda item: (not item.active_for_discovery, item.name.lower()))


def _records(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _run_powershell_json(script: str) -> list[dict]:
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=25,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Windows network-policy examination failed")
    if not completed.stdout.strip():
        return []
    try:
        return _records(json.loads(completed.stdout))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows returned an unreadable network-policy result") from exc


def _windows_host_network_policy() -> HostNetworkPolicyRead:
    profiles = _run_powershell_json(
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction "
        "| ConvertTo-Json -Compress"
    )
    rules = _run_powershell_json(
        "Get-NetFirewallRule -Enabled True | Sort-Object DisplayName "
        "| Select-Object -First 200 DisplayName,Direction,Action,Profile | ConvertTo-Json -Compress"
    )
    routes = _run_powershell_json(
        "Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix,RouteMetric "
        "| Select-Object -First 250 DestinationPrefix,NextHop,InterfaceAlias,RouteMetric "
        "| ConvertTo-Json -Compress"
    )
    parsed_routes = []
    for route in routes:
        prefix = str(route.get("DestinationPrefix") or "")
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        next_hop = str(route.get("NextHop") or "").strip()
        parsed_routes.append(RouteEntryRead(
            destination=str(network.network_address),
            prefix_length=network.prefixlen,
            next_hop=next_hop if next_hop not in {"", "0.0.0.0", "::"} else None,
            interface=str(route.get("InterfaceAlias") or "Unknown"),
            metric=max(0, int(route.get("RouteMetric") or 0)),
            is_default=network.prefixlen == 0,
        ))
    return HostNetworkPolicyRead(
        platform="Windows",
        firewall_source="Windows Defender Firewall",
        firewall_profiles=[FirewallProfileRead(
            name=str(item.get("Name") or "Unknown"),
            enabled=bool(item.get("Enabled")),
            default_inbound_action=str(item.get("DefaultInboundAction") or "Not configured"),
            default_outbound_action=str(item.get("DefaultOutboundAction") or "Not configured"),
        ) for item in profiles],
        enabled_firewall_rule_count=len(rules),
        firewall_rules=[FirewallRuleSummary(
            name=str(item.get("DisplayName") or "Unnamed rule"),
            direction=str(item.get("Direction") or "Unknown"),
            action=str(item.get("Action") or "Unknown"),
            profile=str(item.get("Profile") or "Any"),
        ) for item in rules],
        routes=parsed_routes,
        notes=["Firewall rules are limited to the first 200 enabled rules.", "IPv4 routes are limited to 250 entries."],
    )


def _linux_host_network_policy() -> HostNetworkPolicyRead:
    if shutil.which("ip") is None:
        raise RuntimeError("The ip command is not installed on the AEGIS host")
    completed = subprocess.run(
        ["ip", "-j", "route", "show"], capture_output=True, text=True, errors="replace",
        timeout=15, shell=False, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Linux routing examination failed")
    try:
        records = _records(json.loads(completed.stdout or "[]"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Linux returned an unreadable routing result") from exc
    routes = []
    for item in records[:250]:
        prefix = "0.0.0.0/0" if item.get("dst") == "default" else str(item.get("dst") or "")
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        routes.append(RouteEntryRead(
            destination=str(network.network_address), prefix_length=network.prefixlen,
            next_hop=item.get("gateway"), interface=str(item.get("dev") or "Unknown"),
            metric=max(0, int(item.get("metric") or 0)), is_default=network.prefixlen == 0,
        ))
    source = next((name for name in ("nft", "ufw", "firewall-cmd", "iptables") if shutil.which(name)), "Not detected")
    return HostNetworkPolicyRead(
        platform=platform.system(), firewall_source=source, firewall_profiles=[],
        enabled_firewall_rule_count=0, firewall_rules=[], routes=routes,
        notes=["Structured firewall rule summaries are currently available on Windows hosts.", "IPv4 routes are limited to 250 entries."],
    )


def host_network_policy() -> HostNetworkPolicyRead:
    return _windows_host_network_policy() if platform.system() == "Windows" else _linux_host_network_policy()
