from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models import Device, MonitorResult


@dataclass(frozen=True)
class StatisticsResult:
    device_id: int
    total_checks: int
    online_checks: int
    offline_checks: int
    availability_percent: float | None
    average_latency_ms: float | None
    current_status: str
    last_checked_at: datetime | None


@dataclass(frozen=True)
class StatusEventResult:
    device_id: int
    timestamp: datetime
    previous_status: str
    current_status: str
    event_type: str


DeviceMonitorSnapshot = list[tuple[Device, MonitorResult | None]]


def load_device_monitor_snapshot(db: Session) -> DeviceMonitorSnapshot:
    """Load every device and its latest monitoring result in one reusable query."""
    latest_result_id = (
        select(MonitorResult.id)
        .where(MonitorResult.device_id == Device.id)
        .order_by(MonitorResult.timestamp.desc(), MonitorResult.id.desc())
        .limit(1)
        .correlate(Device)
        .scalar_subquery()
    )
    return [
        (device, result)
        for device, result in db.execute(
            select(Device, MonitorResult)
            .outerjoin(MonitorResult, MonitorResult.id == latest_result_id)
            .order_by(Device.name, Device.id)
        )
    ]


def calculate_device_statistics(device_id: int, db: Session) -> StatisticsResult:
    totals = db.execute(
        select(
            func.count(MonitorResult.id),
            func.sum(case((MonitorResult.status == "ONLINE", 1), else_=0)),
            func.sum(case((MonitorResult.status == "OFFLINE", 1), else_=0)),
            func.avg(MonitorResult.latency_ms),
        ).where(MonitorResult.device_id == device_id)
    ).one()

    total_checks = int(totals[0] or 0)
    online_checks = int(totals[1] or 0)
    offline_checks = int(totals[2] or 0)
    average_latency = float(totals[3]) if totals[3] is not None else None

    latest = db.scalar(
        select(MonitorResult)
        .where(MonitorResult.device_id == device_id)
        .order_by(MonitorResult.timestamp.desc(), MonitorResult.id.desc())
        .limit(1)
    )

    return StatisticsResult(
        device_id=device_id,
        total_checks=total_checks,
        online_checks=online_checks,
        offline_checks=offline_checks,
        availability_percent=round((online_checks / total_checks) * 100, 2) if total_checks else None,
        average_latency_ms=round(average_latency, 2) if average_latency is not None else None,
        current_status=latest.status if latest else "UNKNOWN",
        last_checked_at=latest.timestamp if latest else None,
    )


def derive_status_events(device_id: int, db: Session, limit: int) -> list[StatusEventResult]:
    transitions = select(
        MonitorResult.id.label("id"),
        MonitorResult.device_id.label("device_id"),
        MonitorResult.timestamp.label("timestamp"),
        MonitorResult.status.label("current_status"),
        func.lag(MonitorResult.status).over(
            partition_by=MonitorResult.device_id,
            order_by=(MonitorResult.timestamp.asc(), MonitorResult.id.asc()),
        ).label("previous_status"),
    ).where(MonitorResult.device_id == device_id).subquery()
    rows = db.execute(
        select(transitions)
        .where(
            transitions.c.previous_status.is_not(None),
            transitions.c.previous_status != transitions.c.current_status,
        )
        .order_by(transitions.c.timestamp.desc(), transitions.c.id.desc())
        .limit(limit)
    )
    return [
        StatusEventResult(
            device_id=row.device_id,
            timestamp=row.timestamp,
            previous_status=row.previous_status,
            current_status=row.current_status,
            event_type=f"{row.previous_status}_TO_{row.current_status}",
        )
        for row in rows
    ]
