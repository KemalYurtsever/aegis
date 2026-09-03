from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    AgentEnrollment,
    AlertEvent,
    AssetBaseline,
    AutomationEvent,
    AutomationSettings,
    Device,
    DiagnosticJob,
    GeneratedReport,
    Incident,
    MaintenanceWindow,
    NotificationChannel,
    NotificationDelivery,
    ServiceCheck,
    VulnerabilityScan,
    utc_now,
)
from app.schemas import AutomationOverview, AutomationSummary
from app.services.report_service import build_availability_report
from app.services.discovery_service import discover_and_import_devices, get_primary_private_network
from app.services.vulnerability_service import run_vulnerability_scan
from app.services.port_scan_service import scan_common_tcp_ports
from app.services.scan_policy import scan_target_allowed


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def get_automation_settings(db: Session) -> AutomationSettings:
    settings = db.get(AutomationSettings, 1)
    if settings is None:
        settings = AutomationSettings(id=1)
        db.add(settings)
        db.flush()
    return settings


def window_is_active(window: MaintenanceWindow, now: datetime | None = None) -> bool:
    if not window.enabled:
        return False
    current = _aware(now or utc_now())
    starts_at = _aware(window.starts_at)
    ends_at = _aware(window.ends_at)
    if ends_at <= starts_at or current < starts_at:
        return False
    if window.repeat == "NONE":
        return current <= ends_at
    period = timedelta(days=1 if window.repeat == "DAILY" else 7)
    elapsed = current - starts_at
    occurrence_start = starts_at + period * (elapsed // period)
    return occurrence_start <= current <= occurrence_start + (ends_at - starts_at)


def device_in_maintenance(device: Device, db: Session, now: datetime | None = None) -> bool:
    current = _aware(now or utc_now())
    if device.maintenance_until is not None and _aware(device.maintenance_until) > current:
        return True
    windows = db.scalars(select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True)))
    return any(
        window_is_active(window, current)
        and (window.device_group is None or window.device_group == device.device_group)
        for window in windows
    )


def _correlation_key(device: Device) -> str:
    if device.device_group:
        return f"group:{device.device_group.lower()}"
    try:
        address = ipaddress.ip_address(device.ip_address)
        prefix = 24 if address.version == 4 else 64
        return f"network:{ipaddress.ip_network(f'{address}/{prefix}', strict=False)}"
    except ValueError:
        return f"device:{device.id}"


def correlate_incidents(db: Session) -> int:
    config = get_automation_settings(db)
    if not config.incidents_enabled:
        return 0

    grouped: dict[str, list[AlertEvent]] = {}
    active_alerts = db.scalars(
        select(AlertEvent).where(AlertEvent.resolved_at.is_(None)).order_by(AlertEvent.triggered_at)
    )
    for alert in active_alerts:
        if device_in_maintenance(alert.device, db):
            continue
        grouped.setdefault(_correlation_key(alert.device), []).append(alert)

    open_incidents = {
        incident.correlation_key: incident
        for incident in db.scalars(select(Incident).where(Incident.status == "OPEN"))
    }
    changed = 0
    for key, alerts in grouped.items():
        if len(alerts) < 2:
            continue
        incident = open_incidents.pop(key, None)
        alert_ids = [alert.id for alert in alerts]
        device_count = len({alert.device_id for alert in alerts})
        severity = "CRITICAL" if any(alert.severity == "CRITICAL" for alert in alerts) else "WARNING"
        title = f"Correlated outage affecting {device_count} devices"
        summary = f"AEGIS grouped {len(alerts)} active alerts in {key}. Check shared gateway, switch, DNS, or power dependencies first."
        if incident is None:
            incident = Incident(
                correlation_key=key,
                title=title,
                summary=summary,
                severity=severity,
                alert_ids_json=json.dumps(alert_ids),
            )
            db.add(incident)
        else:
            incident.title = title
            incident.summary = summary
            incident.severity = severity
            incident.alert_ids_json = json.dumps(alert_ids)
            incident.updated_at = utc_now()
        changed += 1

    for incident in open_incidents.values():
        incident.status = "RESOLVED"
        incident.resolved_at = utc_now()
        incident.updated_at = incident.resolved_at
        changed += 1
    db.flush()
    return changed


def escalate_stale_alerts(db: Session) -> int:
    config = get_automation_settings(db)
    cutoff = utc_now() - timedelta(minutes=config.alert_escalation_minutes)
    alerts = list(db.scalars(select(AlertEvent).where(
        AlertEvent.resolved_at.is_(None),
        AlertEvent.severity == "WARNING",
        AlertEvent.triggered_at <= cutoff,
    )))
    for alert in alerts:
        if device_in_maintenance(alert.device, db):
            continue
        alert.severity = "CRITICAL"
        if not alert.message.startswith("Escalated: "):
            alert.message = f"Escalated: {alert.message}"[:300]
        db.add(AutomationEvent(
            device_id=alert.device_id,
            event_type="ALERT_ESCALATED",
            severity="CRITICAL",
            message=f"Alert {alert.id} escalated after {config.alert_escalation_minutes} minutes.",
        ))
        for delivery in alert.notification_deliveries:
            delivery.status = "PENDING"
            delivery.attempt_count = 0
            delivery.sent_at = None
            delivery.last_error = None
            delivery.subject = f"AEGIS CRITICAL: {alert.device.name}"
            delivery.message = alert.message
    db.flush()
    return len(alerts)


def queue_incident_diagnostics(db: Session) -> int:
    config = get_automation_settings(db)
    if not config.diagnostics_enabled:
        return 0
    queued = 0
    for incident in db.scalars(select(Incident).where(Incident.status == "OPEN")):
        alert_ids = json.loads(incident.alert_ids_json)
        device_ids = set(db.scalars(select(AlertEvent.device_id).where(AlertEvent.id.in_(alert_ids))))
        for device_id in device_ids:
            enrollment = db.scalar(select(AgentEnrollment).where(
                AgentEnrollment.device_id == device_id,
                AgentEnrollment.enabled.is_(True),
                AgentEnrollment.diagnostics_enabled.is_(True),
            ))
            if enrollment is None:
                continue
            already_queued = db.scalar(select(func.count(DiagnosticJob.id)).where(
                DiagnosticJob.device_id == device_id,
                DiagnosticJob.requested_by == "automation",
                DiagnosticJob.created_at >= incident.opened_at,
            )) or 0
            if already_queued:
                continue
            for job_type in ("NETWORK_CONNECTIONS", "TOP_PROCESSES", "SECURITY_LOG_SUMMARY"):
                db.add(DiagnosticJob(
                    device_id=device_id,
                    job_type=job_type,
                    requested_by="automation",
                    parameters_json="{}",
                    expires_at=utc_now() + timedelta(minutes=15),
                ))
                queued += 1
    db.flush()
    return queued


def _latest_diagnostic_snapshot(device: Device, job_type: str) -> str | None:
    completed = [
        job for job in device.diagnostic_jobs
        if job.job_type == job_type and job.status == "COMPLETED" and job.result_json
    ]
    if not completed:
        return None
    latest = max(completed, key=lambda job: (job.completed_at or job.created_at, job.id))
    return hashlib.sha256(latest.result_json.encode()).hexdigest()


def _asset_snapshot(device: Device) -> dict[str, str | None]:
    enrollment = device.agent_enrollment
    return {
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "manufacturer": device.manufacturer,
        "operating_system": device.operating_system,
        "services": device.discovered_services,
        "fingerprint": device.fingerprint_summary,
        "ports": device.fingerprint_ports,
        "agent_platform": enrollment.platform if enrollment else None,
        "agent_version": enrollment.agent_version if enrollment else None,
        "firewall_rules": _latest_diagnostic_snapshot(device, "FIREWALL_RULES"),
        "network_and_routing_state": _latest_diagnostic_snapshot(device, "NETWORK_CONNECTIONS"),
    }


def refresh_asset_baselines(db: Session) -> int:
    if not get_automation_settings(db).drift_enabled:
        return 0
    changes = 0
    for device in db.scalars(select(Device).where(Device.is_active.is_(True))):
        snapshot = _asset_snapshot(device)
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        signature = hashlib.sha256(encoded.encode()).hexdigest()
        baseline = db.scalar(select(AssetBaseline).where(AssetBaseline.device_id == device.id))
        if baseline is None:
            db.add(AssetBaseline(device_id=device.id, signature=signature, snapshot_json=encoded))
            continue
        if baseline.signature == signature:
            continue
        previous = json.loads(baseline.snapshot_json)
        changed_fields = [key for key, value in snapshot.items() if previous.get(key) != value]
        db.add(AutomationEvent(
            device_id=device.id,
            event_type="CONFIGURATION_DRIFT",
            severity="WARNING",
            message=f"Configuration drift detected for {device.name}: {', '.join(changed_fields)}.",
            details_json=json.dumps({"changed_fields": changed_fields, "before": previous, "after": snapshot}),
        ))
        baseline.signature = signature
        baseline.snapshot_json = encoded
        baseline.updated_at = utc_now()
        changes += 1
    db.flush()
    return changes


def _queue_report_notification(report: GeneratedReport, db: Session) -> None:
    for channel in db.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True))):
        db.add(NotificationDelivery(
            channel_type=channel.channel_type,
            subject=f"AEGIS scheduled {report.period_days}-day availability report",
            message=f"Report {report.filename} was generated locally for {report.device_count} devices.",
        ))


def generate_scheduled_report(db: Session, force: bool = False) -> GeneratedReport | None:
    config = get_automation_settings(db)
    if not config.reports_enabled and not force:
        return None
    if not force and config.last_report_at is not None:
        due_at = _aware(config.last_report_at) + timedelta(hours=config.report_interval_hours)
        if utc_now() < due_at:
            return None
    report = build_availability_report(config.report_days, db)
    directory = Path(get_settings().report_directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    filename = f"aegis-availability-{report.generated_at:%Y%m%d-%H%M%S}.json"
    path = directory / filename
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    generated = GeneratedReport(
        period_days=config.report_days,
        filename=filename,
        device_count=len(report.devices),
        generated_at=report.generated_at,
    )
    db.add(generated)
    db.flush()
    config.last_report_at = report.generated_at
    _queue_report_notification(generated, db)
    return generated


def run_scheduled_discovery(db: Session) -> int:
    config = get_automation_settings(db)
    if not config.discovery_enabled:
        return 0
    try:
        network = get_primary_private_network()
    except (RuntimeError, ValueError) as exc:
        db.add(AutomationEvent(
            event_type="DISCOVERY_SKIPPED",
            severity="INFO",
            message=str(exc)[:500],
        ))
        db.flush()
        return 0
    network_changed = config.last_discovery_network != network.network
    due = config.last_discovery_at is None or utc_now() >= (
        _aware(config.last_discovery_at) + timedelta(hours=config.discovery_interval_hours)
    )
    if not network_changed and not due:
        return 0
    result = discover_and_import_devices(db)
    config = get_automation_settings(db)
    config.last_discovery_at = utc_now()
    config.last_discovery_network = result.network.network
    if result.devices_added:
        db.add(AutomationEvent(
            event_type="DEVICES_DISCOVERED",
            severity="INFO",
            message=f"Automatic discovery added {result.devices_added} devices on {result.network.network}.",
            details_json=json.dumps({"device_ids": [device.id for device in result.added_devices]}),
        ))
    db.flush()
    return result.devices_added


def run_scheduled_vulnerability_scan(db: Session) -> int:
    config = get_automation_settings(db)
    if not config.vulnerability_scans_enabled:
        return 0
    if config.last_vulnerability_at is not None and utc_now() < (
        _aware(config.last_vulnerability_at) + timedelta(hours=config.vulnerability_interval_hours)
    ):
        return 0
    latest_by_device = {
        device_id: completed_at
        for device_id, completed_at in db.execute(
            select(VulnerabilityScan.device_id, func.max(VulnerabilityScan.completed_at)).group_by(
                VulnerabilityScan.device_id
            )
        )
    }
    devices = list(db.scalars(select(Device).where(Device.is_active.is_(True)).order_by(Device.id)))
    devices.sort(key=lambda device: _aware(latest_by_device[device.id]) if latest_by_device.get(device.id) else datetime.min.replace(tzinfo=timezone.utc))
    if not devices:
        return 0
    device = devices[0]
    try:
        run_vulnerability_scan(device, db)
    except (OSError, RuntimeError, ValueError) as exc:
        db.add(AutomationEvent(
            device_id=device.id,
            event_type="VULNERABILITY_SCAN_FAILED",
            severity="WARNING",
            message=str(exc)[:500],
        ))
    config = get_automation_settings(db)
    config.last_vulnerability_at = utc_now()
    db.flush()
    return 1


def discover_service_checks(db: Session) -> int:
    """Create conservative monitors for one unconfigured device per cycle."""
    if not get_automation_settings(db).service_discovery_enabled:
        return 0
    configured_devices = select(ServiceCheck.device_id)
    device = db.scalar(select(Device).where(
        Device.is_active.is_(True),
        Device.id.not_in(configured_devices),
    ).order_by(Device.id).limit(1))
    if device is None or not scan_target_allowed(device.ip_address):
        return 0
    open_ports = scan_common_tcp_ports(device.ip_address)
    for item in open_ports:
        if item.port in {80, 8080}:
            check_type = "HTTP"
        elif item.port == 443:
            check_type = "HTTPS"
        else:
            check_type = "TCP"
        db.add(ServiceCheck(
            device_id=device.id,
            name=item.service,
            check_type=check_type,
            port=item.port,
            path="/",
        ))
    if open_ports:
        device.discovered_services = ",".join(item.service for item in open_ports)
        db.add(AutomationEvent(
            device_id=device.id,
            event_type="SERVICE_CHECKS_CREATED",
            severity="INFO",
            message=f"Created {len(open_ports)} service checks for {device.name}.",
            details_json=json.dumps({"ports": [item.port for item in open_ports]}),
        ))
    db.flush()
    return len(open_ports)


def report_path(filename: str) -> Path:
    safe_name = Path(filename).name
    if safe_name != filename:
        raise ValueError("Invalid report filename")
    path = Path(get_settings().report_directory).resolve() / safe_name
    if not path.is_file():
        raise FileNotFoundError(filename)
    return path


def _built_in_summary(db: Session) -> str:
    active_alerts = db.scalar(select(func.count(AlertEvent.id)).where(AlertEvent.resolved_at.is_(None))) or 0
    incidents = db.scalar(select(func.count(Incident.id)).where(Incident.status == "OPEN")) or 0
    drift = db.scalar(select(func.count(AutomationEvent.id)).where(
        AutomationEvent.event_type == "CONFIGURATION_DRIFT"
    )) or 0
    offline_agents = 0
    now = utc_now()
    for enrollment in db.scalars(select(AgentEnrollment).where(AgentEnrollment.enabled.is_(True))):
        if enrollment.last_seen_at is None or now - _aware(enrollment.last_seen_at) > timedelta(
            seconds=(enrollment.report_interval_seconds or 60) * 3
        ):
            offline_agents += 1
    return (
        f"Current AEGIS health: {active_alerts} active alerts, {incidents} open correlated incidents, "
        f"{offline_agents} agents not reporting, and {drift} recorded configuration-drift events. "
        "Review open incidents first, then agent health and recent drift events."
    )


def local_summary(db: Session) -> AutomationSummary:
    settings = get_settings()
    built_in = _built_in_summary(db)
    if not settings.foundry_local_url or not settings.foundry_local_model:
        return AutomationSummary(source="BUILT_IN", text=built_in, generated_at=utc_now())
    parsed = urlparse(settings.foundry_local_url)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return AutomationSummary(source="BUILT_IN", text=built_in, generated_at=utc_now())
    payload = json.dumps({
        "model": settings.foundry_local_model,
        "messages": [
            {"role": "system", "content": "Summarize this local infrastructure status. Give advice only; never propose executing commands."},
            {"role": "user", "content": built_in},
        ],
        "temperature": 0.1,
    }).encode()
    try:
        endpoint = settings.foundry_local_url.rstrip("/") + "/v1/chat/completions"
        request = Request(endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode())
        text = result["choices"][0]["message"]["content"].strip()
        return AutomationSummary(source="LOCAL_MODEL", text=text[:4000], generated_at=utc_now())
    except (OSError, KeyError, IndexError, TypeError, ValueError):
        return AutomationSummary(source="BUILT_IN", text=built_in, generated_at=utc_now())


def automation_overview(db: Session) -> AutomationOverview:
    config = get_automation_settings(db)
    desired = config.desired_agent_version
    outdated = db.scalar(select(func.count(AgentEnrollment.id)).where(
        AgentEnrollment.enabled.is_(True),
        AgentEnrollment.agent_version.is_not(None),
        AgentEnrollment.agent_version != desired,
    )) or 0
    return AutomationOverview(
        settings=config,
        active_maintenance_windows=sum(
            window_is_active(window) for window in db.scalars(select(MaintenanceWindow))
        ),
        open_incidents=db.scalar(select(func.count(Incident.id)).where(Incident.status == "OPEN")) or 0,
        outdated_agents=outdated,
        drift_events=db.scalar(select(func.count(AutomationEvent.id)).where(
            AutomationEvent.event_type == "CONFIGURATION_DRIFT"
        )) or 0,
        generated_reports=db.scalar(select(func.count(GeneratedReport.id))) or 0,
        foundry_local_configured=bool(get_settings().foundry_local_url and get_settings().foundry_local_model),
    )


def run_automation_cycle(db: Session) -> dict[str, int]:
    result = {
        "discovered_devices": run_scheduled_discovery(db),
        "escalated_alerts": escalate_stale_alerts(db),
        "incidents": correlate_incidents(db),
        "diagnostics": queue_incident_diagnostics(db),
        "drift": refresh_asset_baselines(db),
        "reports": int(generate_scheduled_report(db) is not None),
        "vulnerability_scans": run_scheduled_vulnerability_scan(db),
        "service_checks": discover_service_checks(db),
    }
    db.commit()
    return result
