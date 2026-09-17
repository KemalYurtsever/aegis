import concurrent.futures
import ipaddress
import os
import shlex
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from app.services.nmap_top_ports import NMAP_TOP_1000_TCP_PORTS


COMMON_TCP_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP alternate",
    9200: "Elasticsearch",
}

NMAP_VERSION_ARGUMENTS = {
    "FAST": ("--version-intensity", "0"),
    "FAST_VERSION": ("--version-intensity", "0"),
    # Internal bounded follow-up for ports that remain anonymous after the
    # fast pass and protocol-specific banner checks.
    "ADAPTIVE": ("--version-light",),
    "DETAILED": ("--version-light",),
    "AGGRESSIVE": ("--version-all",),
}

# Keep CLI and assessment budgets aligned: full version probes often need
# considerably longer than a ports-only pass, especially through Docker NAT.
NMAP_SERVICE_OPTIONS = {
    "FAST": {"retry": "0", "host_timeout": "5s", "process_timeout": 6},
    "FAST_VERSION": {"retry": "0", "host_timeout": "10s", "process_timeout": 20},
    "ADAPTIVE": {"retry": "1", "host_timeout": "20s", "process_timeout": 25},
    "DETAILED": {"retry": "1", "host_timeout": "90s", "process_timeout": 100},
    "AGGRESSIVE": {"retry": "2", "host_timeout": "180s", "process_timeout": 200},
}


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str
    response_time_ms: float | None


@dataclass(frozen=True)
class PortScanResult:
    scanned_ports: list[int]
    open_ports: list[OpenPort]
    scanner: str
    duration_ms: float
    provenance: dict[str, str] | None = None


@dataclass(frozen=True)
class DetectedService:
    port: int
    name: str
    product: str | None
    version: str | None
    extra_info: str | None
    cpes: tuple[str, ...]
    tunnel: str | None = None


def expand_nmap_port_spec(specification: str) -> list[int]:
    ports: set[int] = set()
    for token in specification.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError("Nmap returned an invalid port range")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(token))
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Nmap returned an invalid TCP port")
    return sorted(ports)


def parse_nmap_port_scan(xml_output: str) -> tuple[list[int], list[OpenPort]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned an unreadable scan result") from exc
    if root.find(".//host[@timedout='true']") is not None:
        raise RuntimeError("Nmap host timed out; open-port discovery is incomplete")

    scan_info = root.find("./scaninfo[@protocol='tcp']")
    scanned_ports = expand_nmap_port_spec(scan_info.get("services", "")) if scan_info is not None else []
    open_ports: list[OpenPort] = []
    for element in root.findall(".//host/ports/port[@protocol='tcp']"):
        state = element.find("state")
        if state is None or state.get("state") != "open":
            continue
        port = int(element.get("portid", "0"))
        service = element.find("service")
        service_name = service.get("name", "unknown") if service is not None else "unknown"
        open_ports.append(OpenPort(port=port, service=service_name, response_time_ms=None))
    return scanned_ports, sorted(open_ports, key=lambda item: item.port)


def parse_nmap_service_scan(xml_output: str) -> list[DetectedService]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned unreadable service-detection output") from exc
    if root.find(".//host[@timedout='true']") is not None:
        raise RuntimeError("Nmap host timed out; service-version evidence is incomplete")
    services = []
    for element in root.findall(".//host/ports/port[@protocol='tcp']"):
        state = element.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = element.find("service")
        if service is None:
            continue
        cpes = tuple(
            value
            for value in (node.text.strip() if node.text else "" for node in service.findall("cpe"))
            if value
        )
        product = service.get("product") or None
        version = service.get("version") or None
        # Nmap can emit an application CPE even when the human-readable
        # product/version attributes are absent. Preserve that usable identity
        # instead of discarding an otherwise exact local-mirror lookup key.
        if product is None or version is None:
            for cpe in cpes:
                components = (
                    cpe[7:].split(":")
                    if cpe.startswith("cpe:/a:")
                    else cpe[10:].split(":")
                    if cpe.startswith("cpe:2.3:a:")
                    else []
                )
                if len(components) < 3:
                    continue
                product = product or components[1].replace("_", " ")
                if components[2] not in {"", "*", "-"}:
                    version = version or components[2]
                break
        services.append(DetectedService(
            port=int(element.get("portid", "0")),
            name=service.get("name", "unknown"),
            product=product,
            version=version,
            extra_info=service.get("extrainfo") or None,
            cpes=cpes,
            tunnel=service.get("tunnel") or None,
        ))
    return sorted(services, key=lambda item: item.port)


def nmap_command_prefix() -> list[str] | None:
    executable = shutil.which("nmap")
    if executable:
        return [executable]
    container = os.getenv("AEGIS_NETWORK_TOOLBOX_CONTAINER", "").strip()
    docker = shutil.which("docker")
    if container and docker:
        return [docker, "exec", container, "nmap"]
    return None


def _nmap_uses_docker(prefix: list[str] | None) -> bool:
    return (
        prefix is not None
        and len(prefix) >= 4
        and os.path.basename(prefix[0].replace("\\", "/")).lower() in {"docker", "docker.exe"}
        and prefix[1] == "exec"
    )


def nmap_tcp_scan_type(prefix: list[str] | None) -> str:
    """Use managed NET_RAW for discovery, not for application fingerprints."""
    return "-sS" if _nmap_uses_docker(prefix) else "-sT"


def nmap_scan_provenance(
    prefix: list[str] | None,
    command: list[str],
    engine_version: str | None = None,
) -> dict[str, str]:
    docker = _nmap_uses_docker(prefix)
    result = {
        "execution_context": (
            f"Docker toolbox {prefix[2]}; Docker-managed interface, host routing/NAT may apply"
            if docker else "AEGIS host interface"
        ),
        "tcp_scan_type": next(
            (argument for argument in command if argument in {"-sS", "-sT"}),
            nmap_tcp_scan_type(prefix),
        ),
        "command": shlex.join(command),
    }
    if engine_version:
        result["engine_version"] = engine_version
    return result


def scan_nmap_top_tcp_ports(target_ip: str, top_ports: int = 1000) -> PortScanResult:
    target = str(ipaddress.ip_address(target_ip))
    if top_ports < 1 or top_ports > 1000:
        raise ValueError("Top-port scan size must be between 1 and 1000")
    prefix = nmap_command_prefix()
    if prefix is None:
        started = time.monotonic()
        scanned_ports = list(NMAP_TOP_1000_TCP_PORTS[:top_ports])
        open_ports = scan_tcp_ports(target, scanned_ports)
        return PortScanResult(
            scanned_ports=scanned_ports,
            open_ports=open_ports,
            scanner="Nmap-ranked socket scan",
            duration_ms=round((time.monotonic() - started) * 1000, 2),
        )

    command = [
        *prefix,
        "-Pn",
        nmap_tcp_scan_type(prefix),
        "-n",
        "-T4",
        "--max-retries",
        "0",
        "--min-rate",
        "500",
        "--initial-rtt-timeout",
        "100ms",
        "--max-rtt-timeout",
        "500ms",
        "--host-timeout",
        "10s",
        "--top-ports",
        str(top_ports),
        "--open",
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
            timeout=20,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nmap top-port scan timed out after 20 seconds") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        raise RuntimeError(detail[-1][:300] if detail else "Nmap top-port scan failed")
    scanned_ports, open_ports = parse_nmap_port_scan(completed.stdout)
    if len(scanned_ports) != top_ports:
        raise RuntimeError(
            f"Nmap reported {len(scanned_ports)} scanned ports instead of {top_ports}"
        )
    return PortScanResult(
        scanned_ports=scanned_ports,
        open_ports=open_ports,
        scanner="Nmap top ports",
        duration_ms=round((time.monotonic() - started) * 1000, 2),
        provenance=nmap_scan_provenance(
            prefix, command, ET.fromstring(completed.stdout).get("version"),
        ),
    )


def scan_nmap_service_versions(
    target_ip: str,
    ports: list[int],
    profile: str = "FAST",
) -> list[DetectedService]:
    target = str(ipaddress.ip_address(target_ip))
    normalized_ports = sorted(set(ports))
    if not normalized_ports:
        return []
    if any(port < 1 or port > 65535 for port in normalized_ports):
        raise ValueError("Service-detection ports must be between 1 and 65535")
    prefix = nmap_command_prefix()
    if prefix is None:
        return []
    normalized_profile = profile.upper()
    selected = NMAP_SERVICE_OPTIONS.get(normalized_profile)
    if selected is None:
        raise ValueError("Unknown service-detection profile")
    command = [
        # SYN + version detection can bind and reuse a source port across
        # application probes. In Docker this produced local EADDRNOTAVAIL
        # (99), aborting fingerprints after the first probe. Connect mode lets
        # the kernel select a fresh source port for each connection.
        *prefix, "-Pn", "-sT", "-n", "-T4", "--max-retries", selected["retry"],
        "--host-timeout", selected["host_timeout"], "-sV",
        *NMAP_VERSION_ARGUMENTS[normalized_profile], "--open",
        "-p", ",".join(map(str, normalized_ports)), "-oX", "-",
    ]
    if ipaddress.ip_address(target).version == 6:
        command.append("-6")
    command.append(target)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=selected["process_timeout"],
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"{normalized_profile.title()} Nmap service detection reached its "
            f"{selected['process_timeout']}-second budget"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        raise RuntimeError(detail[-1][:300] if detail else "Nmap service detection failed")
    return parse_nmap_service_scan(completed.stdout)


def _service_name(port: int) -> str:
    known_service = COMMON_TCP_PORTS.get(port)
    if known_service:
        return known_service
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_tcp_ports(
    target_ip: str,
    ports: list[int],
    timeout_seconds: float = 0.4,
    max_workers: int = 128,
) -> list[OpenPort]:
    def probe(port: int) -> OpenPort | None:
        started = time.monotonic()
        try:
            with socket.create_connection((target_ip, port), timeout=timeout_seconds):
                elapsed = round((time.monotonic() - started) * 1000, 2)
                return OpenPort(
                    port=port,
                    service=_service_name(port),
                    response_time_ms=elapsed,
                )
        except OSError:
            return None

    if not ports:
        return []
    worker_count = min(max_workers, len(ports))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = [result for result in executor.map(probe, ports) if result is not None]
    return sorted(results, key=lambda item: item.port)


def scan_common_tcp_ports(target_ip: str, timeout_seconds: float = 0.6) -> list[OpenPort]:
    return scan_tcp_ports(
        target_ip,
        list(COMMON_TCP_PORTS),
        timeout_seconds=timeout_seconds,
        max_workers=len(COMMON_TCP_PORTS),
    )
