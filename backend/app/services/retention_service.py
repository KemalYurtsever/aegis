from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models import AnomalyEvent, HostMetric, MonitorResult, ServiceResult, SnmpResult, utc_now
from app.schemas import RetentionPreview


RETENTION_MODELS = (
    ("monitor_results", MonitorResult, MonitorResult.timestamp),
    ("service_results", ServiceResult, ServiceResult.timestamp),
    ("host_metrics", HostMetric, HostMetric.timestamp),
    ("snmp_results", SnmpResult, SnmpResult.timestamp),
    ("anomaly_events", AnomalyEvent, AnomalyEvent.detected_at),
)


def preview_retention(retention_days: int, db: Session) -> RetentionPreview:
    cutoff = utc_now() - timedelta(days=retention_days)
    counts = {
        name: int(db.scalar(select(func.count(model.id)).where(timestamp < cutoff)) or 0)
        for name, model, timestamp in RETENTION_MODELS
    }
    return RetentionPreview(
        retention_days=retention_days,
        cutoff=cutoff,
        total_records=sum(counts.values()),
        **counts,
    )


def apply_retention(retention_days: int, db: Session) -> RetentionPreview:
    preview = preview_retention(retention_days, db)
    for _name, model, timestamp in RETENTION_MODELS:
        db.execute(delete(model).where(timestamp < preview.cutoff))
    db.commit()
    return preview
