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


def fingerprint_targets(
    targets: list[tuple[str, str | None, str | None]],
    timeout_seconds: float = 0.4,
    max_workers: int = 128,
) -> list[FingerprintEvidence]:
    """Fingerprint targets through one bounded socket pool."""
    if not targets:
        return []

    def probe(job: tuple[int, str, int]) -> tuple[int, int] | None:
        target_index, address, port = job
        try:
            with socket.create_connection((address, port), timeout=timeout_seconds):
                return target_index, port
        except OSError:
            return None

    jobs = [
        (target_index, address, port)
        for target_index, (address, _manufacturer, _services) in enumerate(targets)
        for port in FINGERPRINT_PORTS
    ]
    open_ports_by_target: list[list[int]] = [[] for _target in targets]
    worker_count = min(max_workers, len(jobs))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        for result in executor.map(probe, jobs):
            if result is not None:
                target_index, port = result
                open_ports_by_target[target_index].append(port)

    timestamp = datetime.now(timezone.utc)
    evidence: list[FingerprintEvidence] = []
    for open_ports, (_address, manufacturer, mdns_services) in zip(
        open_ports_by_target,
        targets,
    ):
        open_ports.sort()
        classification, summary = classify_from_evidence(open_ports, manufacturer, mdns_services)
        evidence.append(FingerprintEvidence(open_ports, classification, summary[:500], timestamp))
    return evidence


def fingerprint_target(
    address: str,
    manufacturer: str | None = None,
    mdns_services: str | None = None,
    timeout_seconds: float = 0.4,
) -> FingerprintEvidence:
    return fingerprint_targets(
        [(address, manufacturer, mdns_services)],
        timeout_seconds=timeout_seconds,
    )[0]
