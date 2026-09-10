import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
from dataclasses import dataclass

import psutil
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.services.ping_service import check_ip
from app.config import get_settings
from app.models import Device
from app.schemas import DeviceRead, DiscoveryNetwork, DiscoveryResult
from app.services.mac_vendor_service import lookup_mac_vendor


@dataclass(frozen=True)
class LocalNetwork:
    interface_name: str
    local_ip: str
    network: str
    gateway: str | None


_WINDOWS_NETWORK_SCRIPT = r"""
$candidates = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
  Sort-Object RouteMetric, InterfaceMetric | ForEach-Object {
    $route = $_
    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    $address = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
    if ($adapter -and $address -and $adapter.Status -eq 'Up') {
      [PSCustomObject]@{
        InterfaceAlias = $address.InterfaceAlias
        InterfaceDescription = $adapter.InterfaceDescription
        IPAddress = $address.IPAddress
        PrefixLength = $address.PrefixLength
        Gateway = $route.NextHop
        RouteMetric = $route.RouteMetric
        InterfaceMetric = $route.InterfaceMetric
      }
    }
  }
ConvertTo-Json -InputObject @($candidates) -Compress
"""

_VIRTUAL_INTERFACE_PATTERN = re.compile(
    r"vpn|tunnel|mullvad|wireguard|\btap\b|\btun\b|hyper-v|virtualbox|vmware|loopback|vethernet",
    re.I,
)

_WINDOWS_DEFAULT_ROUTE_PATTERN = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$"
)


def select_windows_lan_candidate(payload: object) -> dict:
    candidates = payload if isinstance(payload, list) else [payload]
    physical: list[dict] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        try:
            prefix_length = int(candidate["PrefixLength"])
            address = ipaddress.ip_address(candidate["IPAddress"])
        except (KeyError, TypeError, ValueError):
            continue
        identity = f"{candidate.get('InterfaceAlias', '')} {candidate.get('InterfaceDescription', '')}"
        if prefix_length >= 31 or _VIRTUAL_INTERFACE_PATTERN.search(identity) or address.is_loopback:
            continue
        physical.append(candidate)
    if not physical:
        raise RuntimeError("No suitable physical LAN adapter was found; VPN and virtual adapters are excluded")
    return physical[0]


def discovery_address_allowed(address: ipaddress.IPv4Address, allow_public_lan: bool) -> bool:
    return address.is_private or allow_public_lan


def select_windows_route_network(
    route_output: str,
    addresses_by_name: dict,
    stats_by_name: dict,
    allow_public_lan: bool,
) -> LocalNetwork:
    routes = []
    for line in route_output.splitlines():
        match = _WINDOWS_DEFAULT_ROUTE_PATTERN.match(line)
        if match:
            routes.append((int(match.group(3)), match.group(1), match.group(2)))
    for _metric, gateway, local_ip in sorted(routes):
        address = ipaddress.ip_address(local_ip)
        if not discovery_address_allowed(address, allow_public_lan):
            continue
        for interface_name, interface_addresses in addresses_by_name.items():
            stat = stats_by_name.get(interface_name)
            if _VIRTUAL_INTERFACE_PATTERN.search(interface_name) or (stat and not stat.isup):
                continue
            match = next(
                (
                    item
                    for item in interface_addresses
                    if item.family == socket.AF_INET and item.address == local_ip and item.netmask
                ),
                None,
            )
            if match is None:
                continue
            prefix_length = ipaddress.ip_network(f"0.0.0.0/{match.netmask}").prefixlen
            original = ipaddress.ip_network(f"{address}/{prefix_length}", strict=False)
            network = (
                original
                if original.prefixlen >= 24
                else ipaddress.ip_network(f"{address}/24", strict=False)
            )
            return LocalNetwork(interface_name, local_ip, str(network), gateway)
    raise RuntimeError("No suitable physical LAN default route was found")


def get_primary_private_network() -> LocalNetwork:
    if platform.system() != "Windows":
        raise RuntimeError("Automatic discovery currently supports Windows only")
    settings = get_settings()
    try:
        route_result = subprocess.run(
            ["route.exe", "PRINT", "-4", "0.0.0.0"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=5,
            shell=False,
            check=False,
        )
        if route_result.returncode == 0:
            return select_windows_route_network(
                route_result.stdout,
                psutil.net_if_addrs(),
                psutil.net_if_stats(),
                settings.allow_public_lan_discovery,
            )
    except (subprocess.TimeoutExpired, OSError, RuntimeError, ValueError):
        pass
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_NETWORK_SCRIPT],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=20,
            shell=False,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise RuntimeError("Windows network adapter discovery timed out") from exc
    if completed.returncode != 0:
        raise RuntimeError("Unable to identify the active Windows network adapter")
    payload = select_windows_lan_candidate(json.loads(completed.stdout))
    address = ipaddress.ip_address(payload["IPAddress"])
    if not discovery_address_allowed(address, settings.allow_public_lan_discovery):
        raise RuntimeError("Discovery is allowed only on private IPv4 networks")

    original = ipaddress.ip_network(f"{address}/{payload['PrefixLength']}", strict=False)
    # Bound discovery to at most 254 hosts even on a larger corporate/VPN subnet.
    network = original if original.prefixlen >= 24 else ipaddress.ip_network(f"{address}/24", strict=False)
    return LocalNetwork(
        interface_name=payload["InterfaceAlias"],
        local_ip=str(address),
        network=str(network),
        gateway=payload.get("Gateway") or None,
    )


def read_windows_arp_table() -> dict[str, str]:
    completed = subprocess.run(
        ["arp", "-a"], capture_output=True, text=True, errors="replace", timeout=10,
        shell=False, check=False,
    )
    if completed.returncode != 0:
        return {}
    entries: dict[str, str] = {}
    pattern = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+", re.I)
    for line in completed.stdout.splitlines():
        match = pattern.match(line)
        if match:
            entries[match.group(1)] = match.group(2).upper().replace("-", ":")
    return entries


def resolve_hostnames(addresses: list[str]) -> dict[str, str]:
    def resolve(address: str) -> tuple[str, str | None]:
        try:
            hostname = socket.gethostbyaddr(address)[0].strip().rstrip(".")
        except (OSError, UnicodeError):
            return address, None
        if not hostname or hostname == address or is_generic_ptr_hostname(address, hostname):
            return address, None
        return address, hostname[:80]

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        return {address: hostname for address, hostname in executor.map(resolve, addresses) if hostname}


def is_generic_ptr_hostname(address: str, hostname: str) -> bool:
    first_label = hostname.lower().rstrip(".").split(".", 1)[0]
    address_tokens = {address.replace(".", "-"), address.replace(".", "_")}
    return first_label in address_tokens or first_label.startswith(f"{address.replace('.', '-')}-")


def discover_responsive_hosts(network: LocalNetwork) -> list[tuple[str, str | None]]:
    subnet = ipaddress.ip_network(network.network, strict=True)
    addresses = [str(address) for address in subnet.hosts()]
    settings = get_settings()

    def probe(address: str) -> str | None:
        return (
            address
            if check_ip(address, timeout_seconds=settings.discovery_ping_timeout_seconds).status == "ONLINE"
            else None
        )

    def ping_sweep() -> list[str]:
        worker_count = min(settings.discovery_ping_workers, len(addresses))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="aegis-discovery",
        ) as executor:
            return [address for address in executor.map(probe, addresses) if address is not None]

    # Probing every local address also refreshes the OS neighbor cache. Reading
    # that cache captures devices that answer ARP while rejecting ICMP, without
    # allowing a packet-driver stall to hold the discovery request indefinitely.
    responsive = ping_sweep()
    arp_entries = read_windows_arp_table()
    discovered = set(responsive)
    discovered.update(address for address in arp_entries if ipaddress.ip_address(address) in subnet)
    return [(address, arp_entries.get(address)) for address in sorted(discovered, key=ipaddress.ip_address)]


def discover_and_import_devices(db: Session) -> DiscoveryResult:
    """Discover once and merge results into inventory without duplicating router logic."""
    # mDNS uses LocalNetwork from this module; importing it lazily avoids a
    # circular module dependency while keeping one shared discovery workflow.
    from app.services.mdns_service import classify_device, discover_mdns

    network = get_primary_private_network()
    # mDNS listens passively for a bounded period, so overlap it with the host
    # sweep instead of adding its full timeout to every discovery request.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        responsive_future = executor.submit(discover_responsive_hosts, network)
        mdns_future = executor.submit(
            discover_mdns,
            network,
            get_settings().discovery_mdns_timeout_seconds,
        )
        responsive_by_ip = dict(responsive_future.result())
        mdns = mdns_future.result()
    subnet = ipaddress.ip_network(network.network)
    for address in mdns:
        if ipaddress.ip_address(address) in subnet:
            responsive_by_ip.setdefault(address, None)
    responsive = sorted(responsive_by_ip.items(), key=lambda item: ipaddress.ip_address(item[0]))
    existing = {device.ip_address: device for device in db.scalars(select(Device))}
    hostname_candidates = [
        address
        for address, _ in responsive
        if address not in existing
        or existing[address].name == f"Discovered {address}"
        or is_generic_ptr_hostname(address, existing[address].name)
    ]
    hostnames = resolve_hostnames(hostname_candidates)
    for address, details in mdns.items():
        if details.get("hostname"):
            hostnames[address] = details["hostname"]

    added: list[Device] = []
    skipped = 0
    for address, mac_address in responsive:
        services = mdns.get(address, {}).get("services", [])
        if address in existing:
            device = existing[address]
            if mac_address:
                device.mac_address = mac_address
                device.manufacturer = lookup_mac_vendor(mac_address)
            if (device.name == f"Discovered {address}" or is_generic_ptr_hostname(address, device.name)) and address in hostnames:
                device.name = hostnames[address]
            if services:
                device.discovered_services = ",".join(services)
                classification = classify_device(services)
                if classification and device.device_type == "Other":
                    device.device_type = classification
            skipped += 1
            continue
        details = [f"Automatically discovered on {network.interface_name}."]
        if mac_address:
            details.append(f"MAC address: {mac_address}.")
        device = Device(
            name=hostnames.get(address, f"Discovered {address}"),
            ip_address=address,
            mac_address=mac_address,
            manufacturer=lookup_mac_vendor(mac_address),
            discovered_services=",".join(services) or None,
            inventory_source="DISCOVERY",
            device_type=classify_device(services) or "Other",
            description=" ".join(details),
            is_active=True,
        )
        db.add(device)
        added.append(device)
        existing[address] = device
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise RuntimeError("A discovered address was imported concurrently") from exc
    for device in added:
        db.refresh(device)
    return DiscoveryResult(
        network=DiscoveryNetwork(**network.__dict__),
        addresses_scanned=subnet.num_addresses - 2,
        responsive_devices=len(responsive),
        devices_added=len(added),
        devices_skipped=skipped,
        added_devices=[DeviceRead.model_validate(device) for device in added],
    )
