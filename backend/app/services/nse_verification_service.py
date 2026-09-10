from __future__ import annotations

import ipaddress
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from app.services.port_scan_service import OpenPort, nmap_command_prefix


CURATED_NSE_SCRIPTS_BY_PORT = {
    21: ("ftp-anon",),
    22: ("ssh2-enum-algos",),
    53: ("dns-recursion",),
    80: ("http-methods",),
    139: ("smb-protocols", "smb2-security-mode"),
    443: ("http-methods",),
    445: ("smb-protocols", "smb2-security-mode"),
    3389: ("rdp-enum-encryption",),
    8080: ("http-methods",),
    8443: ("http-methods",),
}
_PROFILE_OPTIONS = {
    "FAST": ("0", "6s", "25s", 30),
    "DETAILED": ("1", "12s", "60s", 70),
    "AGGRESSIVE": ("2", "20s", "90s", 100),
}
_MAX_OBSERVATION_LENGTH = 4_000


@dataclass(frozen=True)
class NseObservation:
    script_id: str
    port: int | None
    output: str


@dataclass(frozen=True)
class NseVerificationResult:
    requested_scripts: tuple[str, ...]
    observations: tuple[NseObservation, ...]
    duration_ms: float


def _requested_checks(open_ports: list[OpenPort]) -> tuple[list[int], tuple[str, ...]]:
    ports = sorted({
        item.port
        for item in open_ports
        if item.port in CURATED_NSE_SCRIPTS_BY_PORT
    })
    scripts = tuple(sorted({
        script
        for port in ports
        for script in CURATED_NSE_SCRIPTS_BY_PORT[port]
    }))
    return ports, scripts


def _clean_output(value: str | None) -> str:
    normalized = "\n".join((value or "").replace("\x00", "").splitlines()).strip()
    return normalized[:_MAX_OBSERVATION_LENGTH]


def parse_nse_verification(
    xml_output: str,
    requested_scripts: tuple[str, ...],
    scanned_ports: list[int],
) -> tuple[NseObservation, ...]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned unreadable NSE verification output") from exc

    allowed = set(requested_scripts)
    observations: list[NseObservation] = []
    for port_node in root.findall(".//host/ports/port[@protocol='tcp']"):
        port = int(port_node.get("portid", "0"))
        for script in port_node.findall("script"):
            script_id = script.get("id", "")
            output = _clean_output(script.get("output"))
            if script_id in allowed and output:
                observations.append(NseObservation(script_id, port, output))

    for script in root.findall(".//host/hostscript/script"):
        script_id = script.get("id", "")
        output = _clean_output(script.get("output"))
        matching_ports = [
            port
            for port in scanned_ports
            if script_id in CURATED_NSE_SCRIPTS_BY_PORT.get(port, ())
        ]
        if script_id in allowed and output:
            preferred_port = next(
                (port for port in (445, 139) if port in matching_ports),
                matching_ports[0] if matching_ports else None,
            )
            observations.append(NseObservation(
                script_id,
                preferred_port,
                output,
            ))
    unique = {
        (item.script_id, item.port, item.output): item
        for item in observations
    }
    return tuple(sorted(unique.values(), key=lambda item: (item.port or 0, item.script_id)))


def run_nse_verification(
    target_ip: str,
    open_ports: list[OpenPort],
    profile: str = "FAST",
) -> NseVerificationResult:
    target = str(ipaddress.ip_address(target_ip))
    normalized_profile = profile.upper()
    options = _PROFILE_OPTIONS.get(normalized_profile)
    if options is None:
        raise ValueError("Unknown NSE verification profile")
    ports, scripts = _requested_checks(open_ports)
    if not scripts:
        return NseVerificationResult((), (), 0.0)

    prefix = nmap_command_prefix()
    if prefix is None:
        raise RuntimeError("Nmap NSE verification requires Nmap or the Docker network toolbox")
    retries, script_timeout, host_timeout, process_timeout = options
    command = [
        *prefix,
        "-Pn",
        "-sT",
        "-n",
        "-T4",
        "--max-retries",
        retries,
        "--script-timeout",
        script_timeout,
        "--host-timeout",
        host_timeout,
        "--script",
        ",".join(scripts),
        "-p",
        ",".join(map(str, ports)),
        "--reason",
        "-oX",
        "-",
    ]
    if ipaddress.ip_address(target).version == 6:
        command.append("-6")
    command.append(target)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=process_timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"{normalized_profile.title()} NSE verification reached its {process_timeout}-second budget"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        raise RuntimeError(detail[-1][:300] if detail else "Nmap NSE verification failed")
    return NseVerificationResult(
        requested_scripts=scripts,
        observations=parse_nse_verification(completed.stdout, scripts, ports),
        duration_ms=round((time.monotonic() - started) * 1000, 2),
    )
