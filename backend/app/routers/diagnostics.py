import json
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AgentEnrollment, DiagnosticJob, User, utc_now
from app.routers.agents import authenticated_enrollment
from app.routers.auth import require_admin
from app.routers.devices import get_device_or_404
from app.schemas import (
    DiagnosticJobAgentRead,
    DiagnosticJobCreate,
    DiagnosticJobRead,
    DiagnosticJobResultSubmission,
)

router = APIRouter(prefix="/api", tags=["remote diagnostics"])
ingest_router = APIRouter(prefix="/api", tags=["agent diagnostics"])

MAX_RESULT_BYTES = 50_000
ACTIVE_STATUSES = ("PENDING", "RUNNING")


def serialize_job(job: DiagnosticJob) -> DiagnosticJobRead:
    return DiagnosticJobRead(
        id=job.id,
        device_id=job.device_id,
        job_type=job.job_type,
        status=job.status,
        requested_by=job.requested_by,
        parameters=json.loads(job.parameters_json),
        result=json.loads(job.result_json) if job.result_json else None,
        error=job.error,
        created_at=job.created_at,
        claimed_at=job.claimed_at,
        completed_at=job.completed_at,
        expires_at=job.expires_at,
    )


def expire_jobs(db: Session, device_id: int | None = None) -> None:
    statement = select(DiagnosticJob).where(
        DiagnosticJob.status.in_(ACTIVE_STATUSES),
        DiagnosticJob.expires_at <= utc_now(),
    )
    if device_id is not None:
        statement = statement.where(DiagnosticJob.device_id == device_id)
    expired = list(db.scalars(statement))
    for job in expired:
        job.status = "EXPIRED"
        job.completed_at = utc_now()
        job.error = "The agent did not complete this diagnostic before it expired."
    if expired:
        db.commit()


@router.post(
    "/devices/{device_id}/diagnostic-jobs",
    response_model=DiagnosticJobRead,
    status_code=201,
)
def create_diagnostic_job(
    device_id: int,
    payload: DiagnosticJobCreate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DiagnosticJobRead:
    get_device_or_404(device_id, db)
    enrollment = db.scalar(select(AgentEnrollment).where(AgentEnrollment.device_id == device_id))
    if enrollment is None or not enrollment.enabled:
        raise HTTPException(status_code=409, detail="An active remote agent is required")
    if not enrollment.diagnostics_enabled:
        raise HTTPException(
            status_code=409,
            detail="Remote diagnostics are not enabled on this agent. Reinstall it with -EnableDiagnostics.",
        )
    expire_jobs(db, device_id)
    queued = db.scalar(
        select(func.count(DiagnosticJob.id)).where(
            DiagnosticJob.device_id == device_id,
            DiagnosticJob.status.in_(ACTIVE_STATUSES),
        )
    ) or 0
    if queued >= 5:
        raise HTTPException(status_code=409, detail="This agent already has five active diagnostic jobs")

    parameters = {"max_records": payload.max_records}
    if payload.job_type == "PACKET_CAPTURE":
        parameters["duration_seconds"] = payload.duration_seconds
    job = DiagnosticJob(
        device_id=device_id,
        job_type=payload.job_type,
        requested_by=admin.username,
        parameters_json=json.dumps(parameters, separators=(",", ":")),
        expires_at=utc_now() + timedelta(minutes=15),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return serialize_job(job)


@router.get("/devices/{device_id}/diagnostic-jobs", response_model=list[DiagnosticJobRead])
def list_diagnostic_jobs(
    device_id: int,
    limit: int = Query(default=20, ge=1, le=100),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[DiagnosticJobRead]:
    get_device_or_404(device_id, db)
    expire_jobs(db, device_id)
    jobs = db.scalars(
        select(DiagnosticJob)
        .where(DiagnosticJob.device_id == device_id)
        .order_by(DiagnosticJob.created_at.desc(), DiagnosticJob.id.desc())
        .limit(limit)
    )
    return [serialize_job(job) for job in jobs]


@router.post("/diagnostic-jobs/{job_id}/cancel", response_model=DiagnosticJobRead)
def cancel_diagnostic_job(
    job_id: int,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DiagnosticJobRead:
    job = db.get(DiagnosticJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Diagnostic job not found")
    if job.status != "PENDING":
        raise HTTPException(status_code=409, detail="Only a pending diagnostic job can be cancelled")
    job.status = "CANCELLED"
    job.completed_at = utc_now()
    db.commit()
    db.refresh(job)
    return serialize_job(job)


@ingest_router.get("/agent/jobs/next", response_model=DiagnosticJobAgentRead | None)
def next_diagnostic_job(
    response: Response,
    x_agent_token: str = Header(min_length=20),
    db: Session = Depends(get_db),
):
    enrollment = authenticated_enrollment(x_agent_token, db)
    expire_jobs(db, enrollment.device_id)
    job = db.scalar(
        select(DiagnosticJob)
        .where(
            DiagnosticJob.device_id == enrollment.device_id,
            DiagnosticJob.status == "PENDING",
        )
        .order_by(DiagnosticJob.created_at, DiagnosticJob.id)
        .limit(1)
    )
    if job is None:
        response.status_code = 204
        return None
    job.status = "RUNNING"
    job.claimed_at = utc_now()
    db.commit()
    return DiagnosticJobAgentRead(
        id=job.id,
        job_type=job.job_type,
        parameters=json.loads(job.parameters_json),
    )


@ingest_router.post("/agent/jobs/{job_id}/result", response_model=DiagnosticJobRead)
def submit_diagnostic_result(
    job_id: int,
    payload: DiagnosticJobResultSubmission,
    x_agent_token: str = Header(min_length=20),
    db: Session = Depends(get_db),
) -> DiagnosticJobRead:
    enrollment = authenticated_enrollment(x_agent_token, db)
    job = db.get(DiagnosticJob, job_id)
    if job is None or job.device_id != enrollment.device_id:
        raise HTTPException(status_code=404, detail="Diagnostic job not found")
    if job.status in {"COMPLETED", "FAILED"}:
        return serialize_job(job)
    if job.status != "RUNNING":
        raise HTTPException(status_code=409, detail=f"Diagnostic job is {job.status.lower()}")

    encoded_result = None
    if payload.result is not None:
        encoded_result = json.dumps(payload.result, ensure_ascii=False, separators=(",", ":"))
        if len(encoded_result.encode("utf-8")) > MAX_RESULT_BYTES:
            raise HTTPException(status_code=413, detail="Diagnostic result is too large")
    job.status = payload.status
    job.result_json = encoded_result
    job.error = payload.error
    if payload.status == "FAILED" and not payload.error:
        job.error = "The remote diagnostic failed without an error message."
    job.completed_at = utc_now()
    db.commit()
    db.refresh(job)
    return serialize_job(job)
