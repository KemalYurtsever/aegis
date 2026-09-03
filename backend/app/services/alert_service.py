from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AgentEnrollment, AlertEvent, AlertRule, Device, HostMetric, MonitorResult, utc_now
from app.services.agent_health_service import calculate_agent_health
from app.services.automation_service import device_in_maintenance
from app.services.notification_service import queue_alert_notifications


def get_or_create_rule(device_id: int, db: Session) -> AlertRule:
    rule = db.scalar(select(AlertRule).where(AlertRule.device_id == device_id))
    if rule is None:
        rule = AlertRule(device_id=device_id)
        db.add(rule)
        db.flush()
    return rule


def _active_alert(device_id: int, alert_type: str, db: Session) -> AlertEvent | None:
    return db.scalar(
        select(AlertEvent).where(
            AlertEvent.device_id == device_id,
            AlertEvent.alert_type == alert_type,
            AlertEvent.resolved_at.is_(None),
        )
    )


def _resolve(device_id: int, alert_type: str, db: Session) -> None:
    alert = _active_alert(device_id, alert_type, db)
    if alert is not None:
        alert.resolved_at = utc_now()


def evaluate_alerts(result: MonitorResult, db: Session) -> None:
    rule = get_or_create_rule(result.device_id, db)
    if not rule.enabled:
        _resolve(result.device_id, "DEVICE_OFFLINE", db)
        _resolve(result.device_id, "HIGH_LATENCY", db)
        return

    device = db.get(Device, result.device_id)
    maintenance_active = device is not None and device_in_maintenance(device, db)

    if result.status == "OFFLINE":
        _resolve(result.device_id, "HIGH_LATENCY", db)
        if maintenance_active:
            return
        recent_statuses = list(
            db.scalars(
                select(MonitorResult.status)
                .where(MonitorResult.device_id == result.device_id)
                .order_by(MonitorResult.timestamp.desc(), MonitorResult.id.desc())
                .limit(rule.consecutive_failures)
            )
        )
        if (
            len(recent_statuses) >= rule.consecutive_failures
            and all(status == "OFFLINE" for status in recent_statuses)
            and _active_alert(result.device_id, "DEVICE_OFFLINE", db) is None
        ):
            alert = AlertEvent(
                    device_id=result.device_id,
                    alert_type="DEVICE_OFFLINE",
                    severity="CRITICAL",
                    message=f"Device failed {rule.consecutive_failures} consecutive reachability checks.",
                )
            db.add(alert)
            db.flush()
            queue_alert_notifications(alert, db)
        return

    _resolve(result.device_id, "DEVICE_OFFLINE", db)
    threshold = rule.latency_threshold_ms
    if threshold is not None and result.latency_ms is not None and result.latency_ms > threshold:
        if maintenance_active:
            return
        if _active_alert(result.device_id, "HIGH_LATENCY", db) is None:
            alert = AlertEvent(
                    device_id=result.device_id,
                    alert_type="HIGH_LATENCY",
                    severity="WARNING",
                    message=f"Latency {result.latency_ms:.2f} ms exceeded the {threshold:.2f} ms threshold.",
                )
            db.add(alert)
            db.flush()
            queue_alert_notifications(alert, db)
    else:
        _resolve(result.device_id, "HIGH_LATENCY", db)


def evaluate_resource_alerts(metric: HostMetric, db: Session) -> None:
    rule = get_or_create_rule(metric.device_id, db)
    thresholds = {
        "HIGH_CPU": ("CPU", metric.cpu_percent, rule.cpu_threshold_percent),
        "HIGH_MEMORY": ("Memory", metric.memory_percent, rule.memory_threshold_percent),
        "HIGH_DISK": ("Disk", metric.disk_percent, rule.disk_threshold_percent),
    }
    if not rule.enabled:
        for alert_type in thresholds:
            _resolve(metric.device_id, alert_type, db)
        return

    device = db.get(Device, metric.device_id)
    maintenance_active = device is not None and device_in_maintenance(device, db)

    for alert_type, (label, value, threshold) in thresholds.items():
        if threshold is not None and value > threshold:
            if maintenance_active or _active_alert(metric.device_id, alert_type, db) is not None:
                continue
            alert = AlertEvent(
                device_id=metric.device_id,
                alert_type=alert_type,
                severity="WARNING",
                message=f"{label} usage {value:.2f}% exceeded the {threshold:.2f}% threshold.",
            )
            db.add(alert)
            db.flush()
            queue_alert_notifications(alert, db)
        else:
            _resolve(metric.device_id, alert_type, db)


def resolve_agent_alert(device_id: int, db: Session) -> None:
    _resolve(device_id, "AGENT_OFFLINE", db)


def evaluate_agent_health_alerts(db: Session) -> None:
    enrollments = list(db.scalars(
        select(AgentEnrollment).where(AgentEnrollment.enabled.is_(True)).order_by(AgentEnrollment.id)
    ))
    for enrollment in enrollments:
        health = calculate_agent_health(enrollment)
        if health.status != "OFFLINE":
            resolve_agent_alert(enrollment.device_id, db)
            continue
        device = db.get(Device, enrollment.device_id)
        if device is not None and device_in_maintenance(device, db):
            continue
        if _active_alert(enrollment.device_id, "AGENT_OFFLINE", db) is not None:
            continue
        interval = enrollment.report_interval_seconds or 60
        age = health.seconds_since_last_report or 0
        alert = AlertEvent(
            device_id=enrollment.device_id,
            alert_type="AGENT_OFFLINE",
            severity="CRITICAL",
            message=f"Remote agent has not reported for {age} seconds (expected every {interval} seconds).",
        )
        db.add(alert)
        db.flush()
        queue_alert_notifications(alert, db)
