import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import json

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
)
from app.services.discovery_service import get_primary_private_network


_WIRELESS_NAME = re.compile(r"wi[ -]?fi|wlan|wireless|802\.11", re.I)
_HOSTNAME = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.I,
)
_ADDRESS_TOKEN = re.compile(r"(?<![0-9a-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{2,})(?![0-9a-f:.])", re.I)
_LATENCY_TOKEN = re.compile(r"<?(\d+(?:\.\d+)?)\s*ms", re.I)


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
        raise RuntimeError(f"{executable} is not installed on the LIIMS host")
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
        raise RuntimeError("The ip command is not installed on the LIIMS host")
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
