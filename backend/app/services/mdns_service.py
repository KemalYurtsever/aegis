from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Mapping

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

_DISPLAY_NAME_KEYS = ("fn", "friendlyname", "friendly-name", "name", "device-name")
_MODEL_KEYS = ("model", "md", "ty", "am", "product")
_IDENTITY_SERVICES = {"workstation", "device-info", "ipp", "printer", "airplay", "googlecast"}
_MAX_METADATA_LENGTH = 200


def _clean_metadata(value: object) -> str | None:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    cleaned = " ".join(str(value or "").replace("\x00", "").split())
    if len(cleaned) >= 2 and cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1].strip()
    return cleaned[:_MAX_METADATA_LENGTH] or None


def decode_txt_properties(properties: Mapping[object, object] | None) -> dict[str, str]:
    decoded: dict[str, str] = {}
    for raw_key, raw_value in (properties or {}).items():
        key = _clean_metadata(raw_key)
        value = _clean_metadata(raw_value)
        if key and value:
            decoded[key.casefold()] = value
    return decoded


def service_instance_name(name: str, service_type: str) -> str | None:
    suffix = f".{service_type}"
    instance = name[:-len(suffix)] if name.endswith(suffix) else name
    return _clean_metadata(instance.replace("\\032", " "))


def mdns_identity(
    properties: Mapping[object, object] | None,
    instance_name: str | None,
) -> tuple[str | None, str | None]:
    decoded = decode_txt_properties(properties)
    display_name = next((decoded[key] for key in _DISPLAY_NAME_KEYS if key in decoded), None)
    model = next((decoded[key] for key in _MODEL_KEYS if key in decoded), None)
    return display_name or _clean_metadata(instance_name), model


def discover_mdns(network: LocalNetwork, timeout_seconds: float = 3.0) -> dict[str, dict]:
    """Browse a bounded set of mDNS services on only the selected LAN interface."""
    try:
        from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        return {}

    results: dict[str, dict] = defaultdict(
        lambda: {
            "hostnames": set(),
            "display_names": set(),
            "models": set(),
            "services": set(),
        }
    )
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
            properties = decode_txt_properties(info.properties)
            display_name, model = mdns_identity(
                info.properties,
                service_instance_name(name, type_),
            )
            display_priority = next(
                (index for index, key in enumerate(_DISPLAY_NAME_KEYS) if key in properties),
                10 if service in _IDENTITY_SERVICES else 20,
            )
            model_priority = next(
                (index for index, key in enumerate(_MODEL_KEYS) if key in properties),
                len(_MODEL_KEYS),
            )
            for address in info.parsed_addresses(IPVersion.V4Only):
                with lock:
                    results[address]["services"].add(service)
                    if hostname:
                        results[address]["hostnames"].add(hostname[:80])
                    if display_name:
                        results[address]["display_names"].add((display_priority, display_name[:80]))
                    if model:
                        results[address]["models"].add((model_priority, model))

    zeroconf = Zeroconf(interfaces=[network.local_ip], ip_version=IPVersion.V4Only)
    browsers = [ServiceBrowser(zeroconf, service_type, Listener()) for service_type in SERVICE_TYPES]
    try:
        time.sleep(max(0.5, min(timeout_seconds, 10.0)))
    finally:
        for browser in browsers:
            browser.cancel()
        zeroconf.close()
    return {
        address: {
            "hostname": min(value["hostnames"], key=str.casefold) if value["hostnames"] else None,
            "display_name": min(
                value["display_names"],
                key=lambda item: (item[0], len(item[1]), item[1].casefold()),
            )[1] if value["display_names"] else None,
            "model": min(
                value["models"],
                key=lambda item: (item[0], len(item[1]), item[1].casefold()),
            )[1] if value["models"] else None,
            "services": sorted(value["services"]),
        }
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
