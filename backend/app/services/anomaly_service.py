from datetime import timedelta
from statistics import median

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnomalyEvent, Device, HostMetric, MonitorResult, utc_now


def _score(latest: float, baseline: list[float]) -> tuple[float, float]:
    center = median(baseline)
    mad = median([abs(value - center) for value in baseline])
    scale = max(mad * 1.4826, max(center * 0.05, 1.0))
    return (latest - center) / scale, center


def detect_device_anomalies(device: Device, db: Session) -> list[AnomalyEvent]:
    candidates = []
    results = list(db.scalars(select(MonitorResult).where(MonitorResult.device_id == device.id, MonitorResult.latency_ms.is_not(None)).order_by(MonitorResult.timestamp.desc()).limit(31)))
    if len(results) >= 21:
        candidates.append(("LATENCY", results[0].latency_ms, [item.latency_ms for item in results[1:]]))
    metrics = list(db.scalars(select(HostMetric).where(HostMetric.device_id == device.id).order_by(HostMetric.timestamp.desc()).limit(31)))
    if len(metrics) >= 21:
        for name, field in (("CPU", "cpu_percent"), ("MEMORY", "memory_percent"), ("DISK", "disk_percent")):
            candidates.append((name, getattr(metrics[0], field), [getattr(item, field) for item in metrics[1:]]))
    created = []
    for metric, observed, baseline in candidates:
        score, center = _score(observed, baseline)
        if score < 3:
            continue
        recent = db.scalar(select(AnomalyEvent).where(AnomalyEvent.device_id == device.id, AnomalyEvent.metric == metric, AnomalyEvent.detected_at >= utc_now() - timedelta(minutes=5)))
        if recent is None:
            event = AnomalyEvent(device_id=device.id, metric=metric, severity="CRITICAL" if score >= 5 else "WARNING", score=round(score, 2), observed_value=observed, baseline_value=round(center, 2), message=f"{metric.title()} value {observed:.2f} is unusually high compared with the local baseline {center:.2f}.")
            db.add(event); created.append(event)
    db.commit()
    for event in created: db.refresh(event)
    return created
