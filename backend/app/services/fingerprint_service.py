from __future__ import annotations

import concurrent.futures
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone


FINGERPRINT_PORTS = {
    22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 515: "LPD printing", 554: "RTSP", 631: "IPP printing",
    3389: "RDP", 8000: "HTTP alternate", 8080: "HTTP alternate",
    8554: "RTSP alternate", 9100: "Raw printing",
}


@dataclass(frozen=True)
class FingerprintEvidence:
    open_ports: list[int]
    classification: str | None
    summary: str
    timestamp: datetime


def classify_from_evidence(open_ports: list[int], manufacturer: str | None, mdns_services: str | None) -> tuple[str | None, str]:
    ports = set(open_ports)
    services = set((mdns_services or "").split(",")) - {""}
    signals: list[str] = []
    classification = None
    if ports & {515, 631, 9100} or services & {"ipp", "printer"}:
        classification = "Printer"; signals.append("printing service")
    elif ports & {554, 8554}:
        classification = "Camera"; signals.append("RTSP video service")
    elif 3389 in ports or 445 in ports or services & {"workstation", "smb"}:
        classification = "Workstation"; signals.append("Windows workstation service")
    elif 22 in ports:
        classification = "Server"; signals.append("SSH service")
    if manufacturer:
        signals.append(f"manufacturer: {manufacturer}")
    if ports:
        signals.append("open TCP: " + ", ".join(str(port) for port in open_ports))
    if services:
        signals.append("mDNS: " + ", ".join(sorted(services)))
    return classification, "; ".join(signals) or "No identifying service responded"


def fingerprint_target(address: str, manufacturer: str | None = None, mdns_services: str | None = None, timeout_seconds: float = 0.4) -> FingerprintEvidence:
    def probe(port: int) -> int | None:
        try:
            with socket.create_connection((address, port), timeout=timeout_seconds):
                return port
        except OSError:
            return None

    # Each target has a small, fixed port set. Probe it in one bounded wave so
    # an unreachable device costs one timeout rather than two sequential ones.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(FINGERPRINT_PORTS)) as executor:
        open_ports = sorted(port for port in executor.map(probe, FINGERPRINT_PORTS) if port is not None)
    classification, summary = classify_from_evidence(open_ports, manufacturer, mdns_services)
    return FingerprintEvidence(open_ports, classification, summary[:500], datetime.now(timezone.utc))
