import concurrent.futures
import os
import platform
import shutil
import socket
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AgentEnrollment, Device, MonitorResult, utc_now
from app.routers.auth import require_admin
from app.schemas import SystemComponentRead, SystemReadiness


router = APIRouter(
    prefix="/api/system",
    tags=["system"],
    dependencies=[Depends(require_admin)],
)


def _component(name: str, status: str, message: str) -> SystemComponentRead:
    return SystemComponentRead(name=name, status=status, message=message)


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return "0 B"


def database_readiness_component(db: Session) -> SystemComponentRead:
    """Return a fast liveness/readiness view without scanning the full database.

    Full SQLite integrity checks are intentionally reserved for backup
    verification and the prototype verification command. Running quick_check
    here made every System Status view scan the rebuildable CVE corpus.
    """
    try:
        db.execute(text("SELECT 1")).scalar_one()
        sqlite = db.get_bind().dialect.name == "sqlite"
        foreign_keys_enabled = (
            bool(db.execute(text("PRAGMA foreign_keys")).scalar_one())
            if sqlite else True
        )
        active_devices = db.scalar(
            select(func.count(Device.id)).where(Device.is_active.is_(True))
        ) or 0
        latest_check = db.scalar(select(func.max(MonitorResult.timestamp)))
        latest = latest_check.isoformat() if latest_check else "no checks recorded"
        enforcement = "enabled" if foreign_keys_enabled else "disabled"
        return _component(
            "Database",
            "HEALTHY" if foreign_keys_enabled else "WARNING",
            f"Connection ready; foreign-key enforcement {enforcement}; "
            f"{active_devices} active devices; latest result {latest}. "
            "Deep integrity is checked by backup verification and verify-prototype.ps1.",
        )
    except SQLAlchemyError as exc:
        return _component("Database", "WARNING", f"Database readiness check failed: {exc}")


@router.get("/readiness", response_model=SystemReadiness)
def system_readiness(request: Request, db: Session = Depends(get_db)) -> SystemReadiness:
    components: list[SystemComponentRead] = []

    components.append(_component(
        "Runtime",
        "HEALTHY",
        f"Python {platform.python_version()} on {platform.system()} {platform.release()} "
        f"({sys.maxsize.bit_length() + 1}-bit).",
    ))

    docker_toolbox = bool(os.getenv("AEGIS_NETWORK_TOOLBOX_CONTAINER", "").strip() and shutil.which("docker"))
    tool_states = {
        "Nmap": bool(shutil.which("nmap")) or docker_toolbox,
        "ARP scan": bool(shutil.which("arp-scan")) or bool(os.name == "nt" and (Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/Npcap/wpcap.dll").exists()),
        "curl": bool(shutil.which("curl")),
        "DNS query CLI": bool(shutil.which("dig")) or bool(os.name == "nt" and shutil.which("nslookup")) or docker_toolbox,
        "DNSRecon": bool(shutil.which("dnsrecon")) or docker_toolbox,
        "fping": bool(shutil.which("fping")) or docker_toolbox,
        "Web scanners": bool(shutil.which("whatweb") and shutil.which("nikto")) or docker_toolbox,
        "TLS inspection": bool(shutil.which("sslscan") and shutil.which("openssl")) or docker_toolbox,
        "SMB posture": bool(shutil.which("smbclient") and shutil.which("nmap")) or docker_toolbox,
        "Traceroute": bool(shutil.which("tracert" if os.name == "nt" else "traceroute")),
        "Neighbor table": bool(shutil.which("powershell.exe" if os.name == "nt" else "ip")),
        "Docker CLI": bool(shutil.which("docker")),
        "Npcap": bool(
            os.name == "nt"
            and (Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/Npcap/wpcap.dll").exists()
        ),
    }
    missing_tools = [name for name, available in tool_states.items() if not available]
    components.append(_component(
        "Optional tools",
        "WARNING" if missing_tools else "HEALTHY",
        "Missing: " + ", ".join(missing_tools)
        if missing_tools else "Network lab tools are available locally or through the Docker toolbox; Npcap and Docker CLI detected.",
    ))

    components.append(database_readiness_component(db))

    scheduler = request.app.state.monitor_scheduler
    scheduler_status = "HEALTHY" if scheduler.is_running else (
        "WARNING" if scheduler.enabled else "DISABLED"
    )
    scheduler_message = (
        f"Runs every {scheduler.interval_seconds:g} seconds."
        if scheduler.is_running else
        ("Enabled but not running." if scheduler.enabled else "Disabled by server configuration.")
    )
    components.append(_component("Monitoring scheduler", scheduler_status, scheduler_message))

    service_ports = {
        "frontend": 5173,
        "API": 8001,
        "agent ingress": 8002,
        "Grafana": 3000,
        "Prometheus": 9090,
    }
    listening: list[str] = []
    missing_ports: list[str] = []

    def check_port(item: tuple[str, int]) -> tuple[str, bool]:
        name, port = item
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return name, True
        except OSError:
            return name, False

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(service_ports),
    ) as executor:
        port_states = list(executor.map(check_port, service_ports.items()))
    listening.extend(name for name, available in port_states if available)
    missing_ports.extend(name for name, available in port_states if not available)
    components.append(_component(
        "Local services",
        "WARNING" if missing_ports else "HEALTHY",
        f"Listening: {', '.join(listening) or 'none'}; "
        f"unavailable: {', '.join(missing_ports) or 'none'}.",
    ))

    observability: list[str] = []
    unavailable: list[str] = []
    observability_endpoints = (
        ("Grafana", "http://127.0.0.1:3000/api/health"),
        ("Prometheus", "http://127.0.0.1:9090/-/ready"),
    )

    def check_endpoint(item: tuple[str, str]) -> tuple[str, bool]:
        name, url = item
        try:
            with urlopen(url, timeout=0.5) as response:
                return name, response.status < 400
        except (OSError, URLError):
            return name, False

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(observability_endpoints),
    ) as executor:
        endpoint_states = list(executor.map(check_endpoint, observability_endpoints))
    observability.extend(name for name, available in endpoint_states if available)
    unavailable.extend(name for name, available in endpoint_states if not available)
    components.append(_component(
        "Observability",
        "WARNING" if unavailable else "HEALTHY",
        f"Ready: {', '.join(observability) or 'none'}; "
        f"unavailable: {', '.join(unavailable) or 'none'}.",
    ))

    secret_groups = {
        "Prometheus token": "AEGIS_PROMETHEUS_TOKEN",
        "SNMP community": "AEGIS_SNMP_COMMUNITY",
    }
    configured = [
        label for label, variable in secret_groups.items()
        if os.getenv(variable, "").strip()
    ]
    components.append(_component(
        "Environment",
        "HEALTHY" if configured else "WARNING",
        f"Configured server-side secrets: {', '.join(configured) or 'none'}. "
        "Values are never returned.",
    ))

    agent_total = db.scalar(select(func.count(AgentEnrollment.id))) or 0
    agent_enabled = db.scalar(
        select(func.count(AgentEnrollment.id)).where(AgentEnrollment.diagnostics_enabled.is_(True))
    ) or 0
    components.append(_component(
        "Agent connectivity",
        "HEALTHY" if agent_total else "WARNING",
        f"{agent_total} enrolled agents; {agent_enabled} allowlisted for remote diagnostics.",
    ))

    backup_scheduler = request.app.state.backup_scheduler
    backup_status = "HEALTHY" if backup_scheduler.is_running else (
        "WARNING" if backup_scheduler.enabled else "DISABLED"
    )
    backups = request.app.state.backup_service.list_backups()
    latest_backup = backups[0].created_at.isoformat() if backups else "none created"
    backup_message = (
        f"Latest backup: {latest_backup}."
        if backup_scheduler.is_running else
        ("Enabled but not running." if backup_scheduler.enabled else "Automatic backups disabled.")
    )
    components.append(_component("Backup scheduler", backup_status, backup_message))

    try:
        database_directory = request.app.state.backup_service.database_path.parent
        usage = shutil.disk_usage(database_directory)
        storage_status = "WARNING" if usage.free < 512 * 1024 * 1024 else "HEALTHY"
        components.append(_component(
            "Storage",
            storage_status,
            f"{_format_bytes(usage.free)} free of {_format_bytes(usage.total)}.",
        ))
    except OSError as exc:
        components.append(_component("Storage", "WARNING", f"Storage check failed: {exc}"))

    core_components = {"Database", "Monitoring scheduler", "Backup scheduler", "Storage"}
    overall = "WARNING" if any(
        item.name in core_components and item.status == "WARNING" for item in components
    ) else "HEALTHY"
    return SystemReadiness(status=overall, checked_at=utc_now(), components=components)
