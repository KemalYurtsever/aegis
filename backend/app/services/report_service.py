from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Device, MonitorResult, utc_now
from app.schemas import AvailabilityReport, AvailabilityReportDevice


def build_availability_report(days: int, db: Session) -> AvailabilityReport:
    ends_at = utc_now()
    starts_at = ends_at - timedelta(days=days)
    rows: list[AvailabilityReportDevice] = []

    for device in db.scalars(select(Device).order_by(Device.name, Device.id)):
        results = list(db.scalars(
            select(MonitorResult)
            .where(
                MonitorResult.device_id == device.id,
                MonitorResult.timestamp >= starts_at,
                MonitorResult.timestamp <= ends_at,
            )
            .order_by(MonitorResult.timestamp, MonitorResult.id)
        ))
        online = sum(result.status == "ONLINE" for result in results)
        latencies = [
            result.latency_ms for result in results
            if result.status == "ONLINE" and result.latency_ms is not None
        ]
        incidents = 0
        longest_streak = 0
        current_streak = 0
        previous_status = None
        for result in results:
            if result.status == "OFFLINE":
                current_streak += 1
                longest_streak = max(longest_streak, current_streak)
                incidents += previous_status != "OFFLINE"
            else:
                current_streak = 0
            previous_status = result.status

        rows.append(AvailabilityReportDevice(
            device_id=device.id,
            device_name=device.name,
            ip_address=device.ip_address,
            criticality=device.criticality,
            total_checks=len(results),
            online_checks=online,
            offline_checks=len(results) - online,
            availability_percent=round(online / len(results) * 100, 2) if results else None,
            average_latency_ms=round(sum(latencies) / len(latencies), 2) if latencies else None,
            offline_incidents=incidents,
            longest_offline_streak=longest_streak,
            current_status=results[-1].status if results else "UNKNOWN",
        ))

    return AvailabilityReport(
        days=days,
        starts_at=starts_at,
        ends_at=ends_at,
        generated_at=utc_now(),
        devices=rows,
    )
