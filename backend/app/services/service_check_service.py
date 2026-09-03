import http.client
import socket
import ssl
import time
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import ServiceCheck, ServiceResult


@dataclass(frozen=True)
class ServiceProbeResult:
    status: str
    response_time_ms: float | None
    http_status_code: int | None = None
    diagnostic_reason: str | None = None


def probe_service(check: ServiceCheck, timeout_seconds: float = 3.0) -> ServiceProbeResult:
    started = time.monotonic()
    try:
        if check.check_type == "TCP":
            with socket.create_connection((check.device.ip_address, check.port), timeout=timeout_seconds):
                elapsed = (time.monotonic() - started) * 1000
                return ServiceProbeResult("UP", round(elapsed, 2))

        connection_class = http.client.HTTPSConnection if check.check_type == "HTTPS" else http.client.HTTPConnection
        kwargs = {"host": check.device.ip_address, "port": check.port, "timeout": timeout_seconds}
        if check.check_type == "HTTPS":
            kwargs["context"] = ssl.create_default_context()
        connection = connection_class(**kwargs)
        try:
            connection.request("GET", check.path, headers={"User-Agent": "LIIMS/0.1"})
            response = connection.getresponse()
            response.read(1024)
            elapsed = (time.monotonic() - started) * 1000
            # Any valid HTTP response proves that the service responded. Status
            # semantics remain visible to the operator for later rule support.
            return ServiceProbeResult("UP", round(elapsed, 2), response.status)
        finally:
            connection.close()
    except socket.timeout:
        return ServiceProbeResult("DOWN", None, diagnostic_reason="timeout")
    except ssl.SSLError:
        return ServiceProbeResult("DOWN", None, diagnostic_reason="tls_error")
    except (ConnectionRefusedError, ConnectionResetError):
        return ServiceProbeResult("DOWN", None, diagnostic_reason="connection_refused")
    except OSError:
        return ServiceProbeResult("DOWN", None, diagnostic_reason="network_error")


def run_and_store_service_check(check: ServiceCheck, db: Session) -> ServiceResult:
    probe = probe_service(check)
    result = ServiceResult(
        service_check_id=check.id,
        status=probe.status,
        response_time_ms=probe.response_time_ms,
        http_status_code=probe.http_status_code,
        diagnostic_reason=probe.diagnostic_reason,
    )
    db.add(result)
    db.commit()
    db.refresh(result)
    return result
