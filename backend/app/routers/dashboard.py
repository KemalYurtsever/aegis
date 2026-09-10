import os

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    AlertEvent,
    Device,
    MonitorResult,
    NotificationChannel,
    NotificationDelivery,
    SnmpConfig,
)
from app.routers.alerts import serialize_alert
from app.schemas import DashboardDevice, DashboardEvent, DashboardResponse

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardResponse)
def get_dashboard(db: Session = Depends(get_db)) -> DashboardResponse:
    latest_result_id = (
        select(MonitorResult.id)
        .where(MonitorResult.device_id == Device.id)
        .order_by(MonitorResult.timestamp.desc(), MonitorResult.id.desc())
        .limit(1)
        .correlate(Device)
        .scalar_subquery()
    )
    device_result_rows = db.execute(
        select(Device, MonitorResult)
        .outerjoin(MonitorResult, MonitorResult.id == latest_result_id)
        .order_by(Device.name, Device.id)
    ).all()
    devices = [row[0] for row in device_result_rows]
    device_ids = [device.id for device in devices]
    if device_ids:
        totals = {
            row.device_id: row
            for row in db.execute(
                select(
                    MonitorResult.device_id.label("device_id"),
                    func.count(MonitorResult.id).label("total_checks"),
                    func.sum(case((MonitorResult.status == "ONLINE", 1), else_=0)).label("online_checks"),
                )
                .where(MonitorResult.device_id.in_(device_ids))
                .group_by(MonitorResult.device_id)
            )
        }
        latest_by_device = {
            device.id: result
            for device, result in device_result_rows
            if result is not None
        }
        transitions = select(
            MonitorResult.device_id.label("device_id"),
            MonitorResult.timestamp.label("timestamp"),
            MonitorResult.status.label("current_status"),
            func.lag(MonitorResult.status).over(
                partition_by=MonitorResult.device_id,
                order_by=(MonitorResult.timestamp.asc(), MonitorResult.id.asc()),
            ).label("previous_status"),
        ).where(MonitorResult.device_id.in_(device_ids)).subquery()
        names = {device.id: device.name for device in devices}
        events = [
            DashboardEvent(
                device_id=row.device_id,
                device_name=names[row.device_id],
                timestamp=row.timestamp,
                previous_status=row.previous_status,
                current_status=row.current_status,
                event_type=f"{row.previous_status}_TO_{row.current_status}",
            )
            for row in db.execute(
                select(transitions)
                .where(transitions.c.previous_status.is_not(None), transitions.c.previous_status != transitions.c.current_status)
                .order_by(transitions.c.timestamp.desc())
                .limit(10)
            )
        ]
    else:
        totals = {}
        latest_by_device = {}
        events = []
    device_rows: list[DashboardDevice] = []
    latest_latencies: list[float] = []

    for device in devices:
        total = totals.get(device.id)
        latest = latest_by_device.get(device.id)
        latest_latency = latest.latency_ms if latest else None
        if latest_latency is not None:
            latest_latencies.append(latest_latency)

        device_rows.append(
            DashboardDevice(
                id=device.id,
                name=device.name,
                ip_address=device.ip_address,
                mac_address=device.mac_address,
                manufacturer=device.manufacturer,
                discovered_services=device.discovered_services,
                inventory_source=device.inventory_source,
                vlan=device.vlan,
                lease_expires_at=device.lease_expires_at,
                asset_tag=device.asset_tag,
                owner=device.owner,
                location=device.location,
                operating_system=device.operating_system,
                criticality=device.criticality,
                maintenance_until=device.maintenance_until,
                maintenance_reason=device.maintenance_reason,
                device_group=device.device_group,
                tags=device.tags,
                device_type=device.device_type,
                is_active=device.is_active,
                current_status=latest.status if latest else "UNKNOWN",
                latest_latency_ms=latest_latency,
                last_checked_at=latest.timestamp if latest else None,
                availability_percent=(round((total.online_checks / total.total_checks) * 100, 2) if total else None),
                created_at=device.created_at,
            )
        )
    active_alerts = list(
        db.scalars(
            select(AlertEvent)
            .where(
                AlertEvent.resolved_at.is_(None),
                AlertEvent.acknowledged_at.is_(None),
            )
            .order_by(AlertEvent.triggered_at.desc(), AlertEvent.id.desc())
            .limit(10)
        )
    )
    snmp_configs = list(db.scalars(select(SnmpConfig).where(SnmpConfig.enabled.is_(True))))
    snmp_configured = any(
        bool(os.getenv(config.community_env, "").strip()) for config in snmp_configs
    )
    notification_configured = bool(db.scalar(
        select(NotificationChannel.id).where(NotificationChannel.enabled.is_(True)).limit(1)
    ))
    notification_tested = bool(db.scalar(
        select(NotificationDelivery.id).where(
            NotificationDelivery.subject == "AEGIS notification test",
            NotificationDelivery.status == "SENT",
        ).limit(1)
    ))
    return DashboardResponse(
        total_devices=len(devices),
        active_devices=sum(device.is_active for device in devices),
        online_devices=sum(row.current_status == "ONLINE" for row in device_rows),
        offline_devices=sum(row.current_status == "OFFLINE" for row in device_rows),
        unknown_devices=sum(row.current_status == "UNKNOWN" for row in device_rows),
        average_latest_latency_ms=(
            round(sum(latest_latencies) / len(latest_latencies), 2) if latest_latencies else None
        ),
        devices=device_rows,
        recent_events=events,
        active_alert_count=len(active_alerts),
        active_alerts=[serialize_alert(alert) for alert in active_alerts],
        snmp_configured=snmp_configured,
        notification_configured=notification_configured,
        notification_tested=notification_tested,
    )
