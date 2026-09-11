import re
import socket
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

import psutil


LIMITED_BROADCAST = IPv4Address("255.255.255.255")


def unicast_target_rejection_reason(address: str) -> str | None:
    """Reject address classes that can never identify one scan target."""
    try:
        parsed = ip_address(address)
    except ValueError:
        return "A valid IPv4 or IPv6 target address is required"
    if parsed.is_unspecified:
        return "The unspecified address cannot identify a scan target"
    if parsed.is_multicast:
        return "Multicast addresses cannot be scanned as one device"
    if parsed == LIMITED_BROADCAST:
        return "The limited broadcast address cannot be scanned as one device"
    return None


def mac_target_rejection_reason(mac_address: str | None) -> str | None:
    if not mac_address:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(compact) != 12:
        return "The device MAC address is invalid"
    raw = bytes.fromhex(compact)
    if raw == b"\x00" * 6:
        return "The unspecified MAC address cannot identify one device"
    if raw[0] & 1:
        return "A multicast or broadcast MAC address cannot identify one device"
    return None


def _local_ipv4_networks() -> tuple[IPv4Network, ...]:
    networks: set[IPv4Network] = set()
    for addresses in psutil.net_if_addrs().values():
        for item in addresses:
            if item.family != socket.AF_INET or not item.address or not item.netmask:
                continue
            try:
                networks.add(ip_network(f"{item.address}/{item.netmask}", strict=False))
            except ValueError:
                continue
    return tuple(sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen)))


def is_host_in_network(address: str, network: str | IPv4Network) -> bool:
    try:
        parsed = ip_address(address)
        parsed_network = ip_network(network, strict=False) if isinstance(network, str) else network
        if parsed.version != parsed_network.version:
            return False
    except (AttributeError, TypeError, ValueError):
        return False
    if parsed not in parsed_network:
        return False
    if parsed.version == 4 and parsed_network.prefixlen < 31:
        return parsed not in {parsed_network.network_address, parsed_network.broadcast_address}
    return True


def scan_target_rejection_reason(
    address: str,
    local_networks: Iterable[IPv4Network] | None = None,
    mac_address: str | None = None,
) -> str | None:
    reason = unicast_target_rejection_reason(address)
    if reason:
        return reason
    reason = mac_target_rejection_reason(mac_address)
    if reason:
        return reason
    parsed = ip_address(address)
    if parsed.version != 4:
        return None
    for network in _local_ipv4_networks() if local_networks is None else local_networks:
        if parsed not in network or network.prefixlen >= 31:
            continue
        if parsed == network.network_address:
            return f"{parsed} is the network address of local subnet {network}"
        if parsed == network.broadcast_address:
            return f"{parsed} is the broadcast address of local subnet {network}"
    return None


def scan_target_allowed(address: str, mac_address: str | None = None) -> bool:
    """Allow registered unicast hosts, including administrator-selected public targets."""
    return scan_target_rejection_reason(address, mac_address=mac_address) is None
