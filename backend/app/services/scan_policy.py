from ipaddress import ip_address


def scan_target_allowed(address: str) -> bool:
    """Accept valid IP targets selected by the administrator in this learning lab."""
    ip_address(address)
    return True
