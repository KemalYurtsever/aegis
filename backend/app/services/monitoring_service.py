import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Device, MonitorResult
from app.services.alert_service import evaluate_alerts
from app.services.ping_service import PingResult, check_ip

logger = logging.getLogger(__name__)


def store_device_check(device: Device, ping_result: PingResult, db: Session) -> MonitorResult:
    return store_device_checks([(device, ping_result)], db)[0]


def store_device_checks(
    checks: list[tuple[Device, PingResult]],
    db: Session,
) -> list[MonitorResult]:
    """Persist one probe batch with a single flush and transaction."""
    if not checks:
        return []
    results = [
        MonitorResult(
            device_id=device.id,
            status=ping_result.status,
            latency_ms=ping_result.latency_ms,
        )
        for device, ping_result in checks
    ]
    db.add_all(results)
    db.flush()
    for result in results:
        evaluate_alerts(result, db)
    db.commit()
    for (device, ping_result), result in zip(checks, results):
        logger.info(
            "Monitoring check device_id=%s status=%s latency_ms=%s reason=%s",
            device.id,
            result.status,
            result.latency_ms,
            ping_result.diagnostic_reason,
        )
    return results


def check_and_store_device(device: Device, db: Session) -> MonitorResult:
    ping_result = check_ip(device.ip_address, get_settings().ping_timeout_seconds)
    ping_result = apply_neighbor_evidence([device], [ping_result])[0]
    return store_device_check(device, ping_result, db)


def apply_neighbor_evidence(
    devices: list[Device],
    ping_results: list[PingResult],
) -> list[PingResult]:
    """Treat a matching OS neighbor entry as positive local-link evidence."""
    candidates = [
        (index, device)
        for index, (device, result) in enumerate(zip(devices, ping_results))
        if result.status == "OFFLINE" and device.mac_address
    ]
    if not candidates:
        return ping_results

    # Import lazily to keep the monitoring and discovery modules independent.
    from app.services.discovery_service import read_windows_arp_table

    try:
        neighbors = read_windows_arp_table()
    except (OSError, subprocess.SubprocessError):
        return ping_results

    combined = list(ping_results)
    for index, device in candidates:
        observed_mac = neighbors.get(device.ip_address)
        if observed_mac and observed_mac.casefold() == device.mac_address.casefold():
            combined[index] = PingResult(
                status="ONLINE",
                latency_ms=None,
                diagnostic_reason="neighbor_cache",
            )
    return combined


def check_and_store_devices(devices: list[Device], db: Session) -> list[MonitorResult]:
    """Probe a batch concurrently, then persist results on the owning DB thread."""
    if not devices:
        return []

    settings = get_settings()
    addresses = [device.ip_address for device in devices]

    def probe(address: str) -> PingResult:
        return check_ip(address, settings.ping_timeout_seconds)

    worker_count = min(settings.monitor_check_workers, len(addresses))
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="aegis-check") as executor:
        ping_results = list(executor.map(probe, addresses))
    ping_results = apply_neighbor_evidence(devices, ping_results)

    # SQLAlchemy sessions stay on the request thread and the completed probe
    # batch is committed once instead of opening one transaction per device.
    return store_device_checks(list(zip(devices, ping_results)), db)
