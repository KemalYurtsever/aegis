import math
import platform
import re
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address


@dataclass(frozen=True)
class PingResult:
    status: str
    latency_ms: float | None
    diagnostic_reason: str | None = None


_LATENCY_PATTERN = re.compile(r"time\s*[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)


def build_ping_command(address: str, timeout_seconds: float, system: str | None = None) -> list[str]:
    normalized_address = str(ip_address(address))
    detected_system = system or platform.system()

    if detected_system == "Windows":
        return ["ping", "-n", "1", "-w", str(max(1, math.ceil(timeout_seconds * 1000))), normalized_address]
    if detected_system in {"Linux", "Darwin"}:
        return ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout_seconds))), normalized_address]
    raise RuntimeError(f"Unsupported operating system: {detected_system}")


def parse_latency(output: str) -> float | None:
    match = _LATENCY_PATTERN.search(output)
    if match is None:
        return None
    value = float(match.group(1).replace(",", "."))
    # Windows reports sub-millisecond replies as `time<1ms`.
    return 0.5 if "<" in match.group(0) and value == 1 else value


def check_ip(address: str, timeout_seconds: float = 2.0) -> PingResult:
    command = build_ping_command(address, timeout_seconds)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds + 1.0,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PingResult(status="OFFLINE", latency_ms=None, diagnostic_reason="process_timeout")
    except FileNotFoundError:
        return PingResult(status="OFFLINE", latency_ms=None, diagnostic_reason="ping_not_found")
    except OSError:
        return PingResult(status="OFFLINE", latency_ms=None, diagnostic_reason="command_error")

    combined_output = f"{completed.stdout}\n{completed.stderr}"
    latency = parse_latency(combined_output)
    if completed.returncode == 0 and latency is not None:
        return PingResult(status="ONLINE", latency_ms=latency)
    if completed.returncode == 0:
        return PingResult(status="OFFLINE", latency_ms=None, diagnostic_reason="latency_parse_error")
    return PingResult(status="OFFLINE", latency_ms=None, diagnostic_reason="no_reply")
