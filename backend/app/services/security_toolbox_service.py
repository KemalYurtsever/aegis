import ipaddress
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
from app.services.port_scan_service import nmap_command_prefix, scan_nmap_top_tcp_ports


_WIRELESS_NAME = re.compile(r"wi[ -]?fi|wlan|wireless|802\.11", re.I)
_HOSTNAME = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.I,
)
_ADDRESS_TOKEN = re.compile(r"(?<![0-9a-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{2,})(?![0-9a-f:.])", re.I)
_LATENCY_TOKEN = re.compile(r"<?(\d+(?:\.\d+)?)\s*ms", re.I)
_MAX_TOOL_OUTPUT = 100_000
_DOCKER_TOOLBOX_COMMANDS = {"nmap", "arp-scan", "curl", "dig"}


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
) -> LabCommandRead:
    executable = shutil.which(command[0])
    if executable is None:
        container = os.getenv("AEGIS_NETWORK_TOOLBOX_CONTAINER", "").strip()
        docker = shutil.which("docker")
        if tool not in _DOCKER_TOOLBOX_COMMANDS or not container or docker is None:
            raise RuntimeError(f"{command[0]} is not installed on the AEGIS host and no Docker toolbox is available")
        command = [docker, "exec", container, *command]
        executable = command[0]
    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as output_file:
        try:
            completed = subprocess.run(
                [executable, *command[1:]], stdout=output_file, stderr=subprocess.STDOUT,
                timeout=timeout, shell=False, check=False,
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
    return LabCommandRead(
        tool=tool, target=target, exit_code=exit_code, output=output,
        duration_ms=round((time.monotonic() - started) * 1000, 2), truncated=truncated,
        scanned_port_count=scanned_port_count if exit_code == 0 else None,
    )


def nmap_tcp_scan(
    address: str,
    ports: list[int],
    service_detection: bool,
    grep: str | None = None,
    scan_mode: str = "CUSTOM",
    profile: str = "FAST",
) -> LabCommandRead:
    profiles = {"FAST", "FAST_VERSION", "DETAILED", "AGGRESSIVE"}
    if profile not in profiles:
        raise ValueError("Unknown Nmap scan profile")
    if service_detection and profile == "FAST":
        profile = "FAST_VERSION"
    top_1000 = scan_mode == "TOP_1000"
    if top_1000 and nmap_command_prefix() is None:
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
        return LabCommandRead(
            tool="nmap",
            target=address,
            exit_code=0,
            output=_filter_output("\n".join(lines), grep),
            duration_ms=result.duration_ms,
            scanned_port_count=len(result.scanned_ports),
        )

    if profile in {"FAST", "FAST_VERSION"}:
        command = [
            "nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", "0",
            "--min-rate", "500", "--initial-rtt-timeout", "100ms",
            "--max-rtt-timeout", "500ms", "--host-timeout", "10s",
        ]
        timeout = 20
    elif profile == "DETAILED":
        command = [
            "nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", "1",
            "--host-timeout", "90s",
        ]
        timeout = 100
    else:
        command = [
            "nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", "2",
            "--host-timeout", "180s",
        ]
        timeout = 200

    if top_1000:
        command.extend(["--top-ports", "1000", "--open"])
        scanned_port_count = 1000
    else:
        command.extend(["-p", ",".join(map(str, ports))])
        scanned_port_count = len(ports)
    if ipaddress.ip_address(address).version == 6:
        command.append("-6")
    if profile == "FAST_VERSION":
        command.extend(["-sV", "--version-intensity", "0"])
    elif profile == "DETAILED":
        command.extend(["-sV", "--version-light"])
    elif profile == "AGGRESSIVE":
        command.extend(["-sV", "--version-all"])
    command.append(address)
    return _run_lab_tool(
        "nmap", command, target=address, grep=grep, timeout=timeout,
        scanned_port_count=scanned_port_count,
    )


def test_connection_ports(
    address: str,
    ports: list[int],
    timeout_seconds: int = 2,
    grep: str | None = None,
) -> LabCommandRead:
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
            "[pscustomobject]@{Target=$using:targetAddress;Port=$port;Open=[bool]$result.Connected;LatencyMs=$result.Latency;Status=if($result){$result.Status}else{'Timeout'}}} -ThrottleLimit 32;"
            "$rows | Sort-Object Port | Format-Table -AutoSize"
        )
        command = [pwsh, "-NoProfile", "-NonInteractive", "-Command", script]
        process_timeout = min(60, ((len(normalized_ports) + 31) // 32) * timeout_seconds + 15)
    else:
        powershell = shutil.which("powershell.exe")
        if not powershell:
            raise RuntimeError("PowerShell Test-Connection is not available on the AEGIS host")
        script = (
            "$targetAddress=$env:AEGIS_TCP_TEST_TARGET;"
            "$rows=foreach($port in ($env:AEGIS_TCP_TEST_PORTS -split ',')){"
            "$result=Test-NetConnection -ComputerName $targetAddress -Port ([int]$port) -InformationLevel Detailed -WarningAction SilentlyContinue;"
            "[pscustomobject]@{Target=$targetAddress;Port=[int]$port;Open=[bool]$result.TcpTestSucceeded;LatencyMs=$null;Status=if($result.TcpTestSucceeded){'Success'}else{'Failed'}}};"
            "$rows | Format-Table -AutoSize"
        )
        command = [powershell, "-NoProfile", "-NonInteractive", "-Command", script]
        process_timeout = min(180, len(normalized_ports) * timeout_seconds + 15)

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
