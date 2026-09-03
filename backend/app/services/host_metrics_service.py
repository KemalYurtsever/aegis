from ipaddress import ip_address

import psutil
from sqlalchemy.orm import Session

from app.models import Device, HostMetric


def is_local_device(device: Device) -> bool:
    return ip_address(device.ip_address).is_loopback


def collect_and_store_host_metrics(device: Device, db: Session) -> HostMetric:
    if not is_local_device(device):
        raise ValueError("Built-in host metrics are available only for loopback devices")
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    metric = HostMetric(
        device_id=device.id,
        cpu_percent=round(psutil.cpu_percent(interval=0.1), 2),
        memory_percent=round(memory.percent, 2),
        disk_percent=round(disk.percent, 2),
        memory_used_bytes=memory.used,
        memory_total_bytes=memory.total,
        disk_used_bytes=disk.used,
        disk_total_bytes=disk.total,
    )
    db.add(metric)
    db.flush()
    from app.services.alert_service import evaluate_resource_alerts
    evaluate_resource_alerts(metric, db)
    db.commit(); db.refresh(metric)
    return metric
