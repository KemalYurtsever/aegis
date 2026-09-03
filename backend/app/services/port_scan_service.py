import concurrent.futures
import socket
import time
from dataclasses import dataclass


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


@dataclass(frozen=True)
class OpenPort:
    port: int
    service: str
    response_time_ms: float


def scan_common_tcp_ports(target_ip: str, timeout_seconds: float = 0.6) -> list[OpenPort]:
    def probe(item: tuple[int, str]) -> OpenPort | None:
        port, service = item
        started = time.monotonic()
        try:
            with socket.create_connection((target_ip, port), timeout=timeout_seconds):
                elapsed = round((time.monotonic() - started) * 1000, 2)
                return OpenPort(port=port, service=service, response_time_ms=elapsed)
        except OSError:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(COMMON_TCP_PORTS)) as executor:
        return [result for result in executor.map(probe, COMMON_TCP_PORTS.items()) if result is not None]
