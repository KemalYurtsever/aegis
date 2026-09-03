import os
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from app.models import AlertEvent, Device, HostMetric, MonitorResult, ServiceCheck, ServiceResult

router = APIRouter(tags=["observability"])


def _expected_token() -> str:
    direct = os.getenv("AEGIS_PROMETHEUS_TOKEN", "").strip()
    token_file = os.getenv("AEGIS_PROMETHEUS_TOKEN_FILE", "").strip()
    if direct:
        return direct
    if token_file:
        try:
            return Path(token_file).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def _label(value) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics(request: Request, authorization: str | None = Header(default=None)) -> PlainTextResponse:
    expected = _expected_token()
    supplied = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else ""
    if not expected:
        raise HTTPException(status_code=503, detail="Prometheus token is not configured")
    if supplied != expected:
        raise HTTPException(status_code=401, detail="Invalid Prometheus token")

    lines = [
        "# HELP aegis_devices_total Number of registered devices.",
        "# TYPE aegis_devices_total gauge",
    ]
    with request.app.state.session_factory() as db:
        devices = list(db.scalars(select(Device).order_by(Device.id)))
        lines.append(f"aegis_devices_total {len(devices)}")
        lines.extend(["# HELP aegis_device_status Device status (1 online, 0 offline, -1 unknown).", "# TYPE aegis_device_status gauge"])
        lines.extend(["# HELP aegis_device_latency_milliseconds Latest device latency.", "# TYPE aegis_device_latency_milliseconds gauge"])
        for device in devices:
            result = db.scalar(select(MonitorResult).where(MonitorResult.device_id == device.id).order_by(MonitorResult.timestamp.desc(), MonitorResult.id.desc()).limit(1))
            labels = f'device_id="{device.id}",device_name="{_label(device.name)}",ip_address="{_label(device.ip_address)}"'
            status = -1 if result is None else (1 if result.status == "ONLINE" else 0)
            lines.append(f"aegis_device_status{{{labels}}} {status}")
            if result is not None and result.latency_ms is not None:
                lines.append(f"aegis_device_latency_milliseconds{{{labels}}} {result.latency_ms}")
        active_alerts = db.scalar(select(func.count(AlertEvent.id)).where(AlertEvent.resolved_at.is_(None))) or 0
        lines.extend(["# HELP aegis_active_alerts Number of unresolved alerts.", "# TYPE aegis_active_alerts gauge", f"aegis_active_alerts {active_alerts}"])
        lines.extend(["# HELP aegis_service_status Latest service status (1 up, 0 down, -1 unknown).", "# TYPE aegis_service_status gauge"])
        for check in db.scalars(select(ServiceCheck).order_by(ServiceCheck.id)):
            result = db.scalar(select(ServiceResult).where(ServiceResult.service_check_id == check.id).order_by(ServiceResult.timestamp.desc(), ServiceResult.id.desc()).limit(1))
            labels = f'service_id="{check.id}",service_name="{_label(check.name)}",device_id="{check.device_id}"'
            lines.append(f"aegis_service_status{{{labels}}} {-1 if result is None else (1 if result.status == 'UP' else 0)}")
        lines.extend(["# HELP aegis_host_resource_percent Latest host resource utilization.", "# TYPE aegis_host_resource_percent gauge"])
        for device in devices:
            metric = db.scalar(select(HostMetric).where(HostMetric.device_id == device.id).order_by(HostMetric.timestamp.desc(), HostMetric.id.desc()).limit(1))
            if metric:
                for resource, value in (("cpu", metric.cpu_percent), ("memory", metric.memory_percent), ("disk", metric.disk_percent)):
                    lines.append(f'aegis_host_resource_percent{{device_id="{device.id}",device_name="{_label(device.name)}",resource="{resource}"}} {value}')
    scheduler = request.app.state.monitor_scheduler
    lines.extend(["# HELP aegis_scheduler_running Whether automatic monitoring is running.", "# TYPE aegis_scheduler_running gauge", f"aegis_scheduler_running {1 if scheduler.is_running else 0}", "# EOF"])
    return PlainTextResponse("\n".join(lines) + "\n", media_type="application/openmetrics-text; version=1.0.0; charset=utf-8")
