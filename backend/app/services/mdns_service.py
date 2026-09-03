from __future__ import annotations

import threading
import time
from collections import defaultdict

from app.services.discovery_service import LocalNetwork


SERVICE_TYPES = (
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ipp._tcp.local.",
    "_printer._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_raop._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
)


def discover_mdns(network: LocalNetwork, timeout_seconds: float = 3.0) -> dict[str, dict]:
    """Browse a bounded set of mDNS services on only the selected LAN interface."""
    try:
        from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        return {}

    results: dict[str, dict] = defaultdict(lambda: {"hostname": None, "services": set()})
    lock = threading.Lock()

    class Listener(ServiceListener):
        def remove_service(self, zc, type_: str, name: str) -> None:
            return None

        def update_service(self, zc, type_: str, name: str) -> None:
            self.add_service(zc, type_, name)

        def add_service(self, zc, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name, timeout=750)
            if info is None:
                return
            service = type_.split(".", 1)[0].lstrip("_")
            hostname = (info.server or "").rstrip(".") or None
            for address in info.parsed_addresses(IPVersion.V4Only):
                with lock:
                    results[address]["services"].add(service)
                    if hostname:
                        results[address]["hostname"] = hostname[:80]

    zeroconf = Zeroconf(interfaces=[network.local_ip], ip_version=IPVersion.V4Only)
    browsers = [ServiceBrowser(zeroconf, service_type, Listener()) for service_type in SERVICE_TYPES]
    try:
        time.sleep(max(0.5, min(timeout_seconds, 10.0)))
    finally:
        for browser in browsers:
            browser.cancel()
        zeroconf.close()
    return {
        address: {"hostname": value["hostname"], "services": sorted(value["services"])}
        for address, value in results.items()
    }


def classify_device(services: list[str]) -> str | None:
    service_set = set(services)
    if service_set & {"ipp", "printer"}:
        return "Printer"
    if service_set & {"workstation", "smb"}:
        return "Workstation"
    if "ssh" in service_set:
        return "Server"
    return None
