import logging

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Device, MonitorResult
from app.services.alert_service import evaluate_alerts
from app.services.ping_service import check_ip

logger = logging.getLogger(__name__)


def check_and_store_device(device: Device, db: Session) -> MonitorResult:
    ping_result = check_ip(device.ip_address, get_settings().ping_timeout_seconds)
    result = MonitorResult(
        device_id=device.id,
        status=ping_result.status,
        latency_ms=ping_result.latency_ms,
    )
    db.add(result)
    db.flush()
    evaluate_alerts(result, db)
    db.commit()
    db.refresh(result)

    logger.info(
        "Monitoring check device_id=%s status=%s latency_ms=%s reason=%s",
        device.id,
        result.status,
        result.latency_ms,
        ping_result.diagnostic_reason,
    )
    return result
