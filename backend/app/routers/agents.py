import hashlib
import hmac
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AgentEnrollment, Device, HostMetric, utc_now
from app.routers.devices import get_device_or_404
from app.schemas import AgentEnrollmentCreated, AgentEnrollmentRead, AgentFleetItem, AgentFleetOverview, AgentMetricSubmission, HostMetricRead
from app.services.agent_health_service import calculate_agent_health

router = APIRouter(prefix="/api", tags=["agents"])
ingest_router = APIRouter(prefix="/api", tags=["agent ingestion"])


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticated_enrollment(token: str, db: Session) -> AgentEnrollment:
    digest = token_digest(token)
    enrollment = db.scalar(select(AgentEnrollment).where(AgentEnrollment.token_hash == digest))
    if enrollment is None or not enrollment.enabled or not hmac.compare_digest(enrollment.token_hash, digest):
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    return enrollment


def serialize_enrollment(enrollment: AgentEnrollment, now: datetime | None = None) -> AgentEnrollmentRead:
    health = calculate_agent_health(enrollment, now)
    return AgentEnrollmentRead(
        device_id=enrollment.device_id,
        enabled=enrollment.enabled,
        created_at=enrollment.created_at,
        last_seen_at=enrollment.last_seen_at,
        hostname=enrollment.hostname,
        platform=enrollment.platform,
        agent_version=enrollment.agent_version,
        report_interval_seconds=enrollment.report_interval_seconds or 60,
        diagnostics_enabled=bool(enrollment.diagnostics_enabled),
        health_status=health.status,
        seconds_since_last_report=health.seconds_since_last_report,
    )


@router.get("/agents/overview", response_model=AgentFleetOverview)
def get_agent_overview(db: Session = Depends(get_db)) -> AgentFleetOverview:
    enrollments = list(db.scalars(
        select(AgentEnrollment).join(AgentEnrollment.device).order_by(Device.name, AgentEnrollment.id)
    ))
    rows = [
        AgentFleetItem(
            **serialize_enrollment(enrollment).model_dump(),
            device_name=enrollment.device.name,
            ip_address=enrollment.device.ip_address,
        )
        for enrollment in enrollments
    ]
    return AgentFleetOverview(
        total_agents=len(rows),
        reporting_agents=sum(row.health_status == "REPORTING" for row in rows),
        delayed_agents=sum(row.health_status == "DELAYED" for row in rows),
        offline_agents=sum(row.health_status == "OFFLINE" for row in rows),
        waiting_agents=sum(row.health_status == "WAITING" for row in rows),
        agents=rows,
    )


@router.post("/devices/{device_id}/agent/enroll", response_model=AgentEnrollmentCreated, status_code=201)
def enroll_agent(device_id: int, db: Session = Depends(get_db)):
    get_device_or_404(device_id, db)
    token = secrets.token_urlsafe(32)
    enrollment = db.scalar(select(AgentEnrollment).where(AgentEnrollment.device_id == device_id))
    if enrollment is None:
        enrollment = AgentEnrollment(device_id=device_id, token_hash=token_digest(token))
        db.add(enrollment)
    else:
        enrollment.token_hash = token_digest(token)
        enrollment.enabled = True
        enrollment.last_seen_at = None
        enrollment.hostname = None
        enrollment.platform = None
        enrollment.agent_version = None
        enrollment.diagnostics_enabled = False
    db.commit(); db.refresh(enrollment)
    return AgentEnrollmentCreated(token=token, **serialize_enrollment(enrollment).model_dump())


@router.get("/devices/{device_id}/agent", response_model=AgentEnrollmentRead | None)
def get_agent_enrollment(device_id: int, db: Session = Depends(get_db)):
    get_device_or_404(device_id, db)
    enrollment = db.scalar(select(AgentEnrollment).where(AgentEnrollment.device_id == device_id))
    return serialize_enrollment(enrollment) if enrollment is not None else None


@router.delete("/devices/{device_id}/agent", status_code=204)
def revoke_agent(device_id: int, db: Session = Depends(get_db)):
    get_device_or_404(device_id, db)
    enrollment = db.scalar(select(AgentEnrollment).where(AgentEnrollment.device_id == device_id))
    if enrollment is not None:
        from app.services.alert_service import resolve_agent_alert
        resolve_agent_alert(device_id, db)
        db.delete(enrollment); db.commit()
    return Response(status_code=204)


@ingest_router.post("/agent/metrics", response_model=HostMetricRead, status_code=201)
def submit_agent_metrics(
    payload: AgentMetricSubmission,
    x_agent_token: str = Header(min_length=20),
    db: Session = Depends(get_db),
):
    enrollment = authenticated_enrollment(x_agent_token, db)
    metric = HostMetric(
        device_id=enrollment.device_id,
        cpu_percent=payload.cpu_percent,
        memory_percent=payload.memory_percent,
        disk_percent=payload.disk_percent,
        memory_used_bytes=payload.memory_used_bytes,
        memory_total_bytes=payload.memory_total_bytes,
        disk_used_bytes=payload.disk_used_bytes,
        disk_total_bytes=payload.disk_total_bytes,
    )
    enrollment.last_seen_at = utc_now()
    enrollment.hostname = payload.hostname
    enrollment.platform = payload.platform
    enrollment.agent_version = payload.agent_version
    enrollment.report_interval_seconds = payload.report_interval_seconds
    enrollment.diagnostics_enabled = payload.diagnostics_enabled
    db.add(metric)
    db.flush()
    from app.services.alert_service import evaluate_resource_alerts
    evaluate_resource_alerts(metric, db)
    db.commit(); db.refresh(metric)
    return metric
