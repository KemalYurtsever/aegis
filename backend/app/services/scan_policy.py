from ipaddress import ip_address, ip_network

from app.config import get_settings
from app.services.discovery_service import get_primary_private_network


def scan_target_allowed(address: str) -> bool:
    """Allow local targets and the explicitly enabled, directly connected LAN."""
    target = ip_address(address)
    settings = get_settings()
    # Lab mode removes address-range classification for explicit, registered
    # device actions. Endpoint authentication, rate limiting, bounded port sets,
    # and request validation remain enforced separately.
    if settings.authorized_lab_mode:
        return True
    if target.is_private or target.is_loopback:
        return True
    if not settings.allow_public_lan_discovery:
        return False
    try:
        connected = get_primary_private_network()
    except RuntimeError:
        return False
    return target in ip_network(connected.network)
