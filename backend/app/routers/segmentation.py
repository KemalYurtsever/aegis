import json

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, DiagnosticJob, SegmentationCheck, SegmentationPolicy, User
from app.routers.auth import require_admin
from app.routers.devices import get_device_or_404
from app.routers.diagnostics import create_diagnostic_job, expire_jobs
from app.schemas import (
    DiagnosticJobCreate,
    SegmentationCheckCreate,
    SegmentationCheckRead,
    SegmentationPolicyCreate,
    SegmentationPolicyRead,
)
from app.services.scan_policy import scan_target_rejection_reason


router = APIRouter(
    prefix="/api/segmentation-policies",
    tags=["segmentation validation"],
    dependencies=[Depends(require_admin)],
)


def get_policy_or_404(policy_id: int, db: Session) -> SegmentationPolicy:
    policy = db.get(SegmentationPolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Segmentation policy not found")
    return policy


def serialize_policy(policy: SegmentationPolicy, db: Session) -> SegmentationPolicyRead:
    source = db.get(Device, policy.source_device_id)
    target = db.get(Device, policy.target_device_id)
    return SegmentationPolicyRead(
        id=policy.id,
        source_device_id=policy.source_device_id,
        target_device_id=policy.target_device_id,
        target_port=policy.target_port,
        expected_reachability=policy.expected_reachability,
        description=policy.description,
        source_name=source.name,
        source_ip=source.ip_address,
        target_name=target.name,
        target_ip=target.ip_address,
        created_by=policy.created_by,
        created_at=policy.created_at,
    )


def serialize_check(check: SegmentationCheck) -> SegmentationCheckRead:
    job = check.job
    observed = None
    error_type = None
    if job.status in {"PENDING", "RUNNING"}:
        status = "PENDING"
        interpretation = "Waiting for the source agent to report its TCP connection attempt."
    elif job.status != "COMPLETED" or not job.result_json:
        status = "INCONCLUSIVE"
        interpretation = f"Agent check ended as {job.status.lower()} without usable reachability evidence."
    else:
        try:
            result = json.loads(job.result_json)
            parameters = json.loads(job.parameters_json)
        except (TypeError, ValueError):
            result = None
            parameters = None
        valid = (
            isinstance(result, dict)
            and isinstance(parameters, dict)
            and job.job_type == "VALIDATION_SIMULATION"
            and job.device_id == check.policy.source_device_id
            and parameters.get("simulation_type") == "SEGMENTATION_PROBE"
            and parameters.get("target_address") == check.target_ip
            and parameters.get("target_port") == check.target_port
            and result.get("simulation_type") == "SEGMENTATION_PROBE"
            and result.get("target_device_id") == parameters.get("target_device_id")
            and result.get("target_address") == check.target_ip
            and result.get("target_port") == check.target_port
            and result.get("application_data_sent") is False
            and type(result.get("connected")) is bool
        )
        if not valid:
            status = "INCONCLUSIVE"
            interpretation = "The agent result did not match the queued target and probe format."
        else:
            observed = result["connected"]
            error_type = str(result.get("error_type") or "")[:80] or None
            expected_connected = check.expected_reachability == "ALLOW"
            status = "MATCH" if observed == expected_connected else "DEVIATION"
            if observed:
                interpretation = "Source agent reported a successful TCP handshake; this compares observed reachability with the expectation."
            else:
                interpretation = (
                    "Source agent reported no TCP handshake; this compares observed reachability with the expectation. A firewall decision cannot be "
                    "distinguished from an unavailable service or route."
                )
    return SegmentationCheckRead(
        id=check.id,
        policy_id=check.policy_id,
        diagnostic_job_id=check.diagnostic_job_id,
        expected_reachability=check.expected_reachability,
        source_ip=check.source_ip,
        target_ip=check.target_ip,
        target_port=check.target_port,
        status=status,
        observed_connected=observed,
        error_type=error_type,
        interpretation=interpretation,
        created_at=check.created_at,
        completed_at=job.completed_at,
    )


@router.post("", response_model=SegmentationPolicyRead, status_code=201)
def create_policy(
    payload: SegmentationPolicyCreate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> SegmentationPolicyRead:
    if payload.source_device_id == payload.target_device_id:
        raise HTTPException(status_code=422, detail="Source and destination must be different devices")
    get_device_or_404(payload.source_device_id, db)
    target = get_device_or_404(payload.target_device_id, db)
    rejection = scan_target_rejection_reason(target.ip_address, mac_address=target.mac_address)
    if rejection:
        raise HTTPException(status_code=400, detail=rejection)
    policy = SegmentationPolicy(**payload.model_dump(), created_by=admin.username)
    db.add(policy)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A policy for this source, destination and port already exists") from exc
    db.refresh(policy)
    return serialize_policy(policy, db)


@router.get("", response_model=list[SegmentationPolicyRead])
def list_policies(
    source_device_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
) -> list[SegmentationPolicyRead]:
    statement = select(SegmentationPolicy).order_by(SegmentationPolicy.id.desc()).limit(200)
    if source_device_id is not None:
        statement = statement.where(SegmentationPolicy.source_device_id == source_device_id)
    return [serialize_policy(policy, db) for policy in db.scalars(statement)]


@router.delete("/{policy_id}", status_code=204)
def delete_policy(policy_id: int, db: Session = Depends(get_db)) -> Response:
    policy = get_policy_or_404(policy_id, db)
    db.delete(policy)
    db.commit()
    return Response(status_code=204)


@router.post("/{policy_id}/checks", response_model=SegmentationCheckRead, status_code=201)
def run_policy_check(
    policy_id: int,
    payload: SegmentationCheckCreate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> SegmentationCheckRead:
    policy = get_policy_or_404(policy_id, db)
    source = get_device_or_404(policy.source_device_id, db)
    target = get_device_or_404(policy.target_device_id, db)
    job = create_diagnostic_job(
        source.id,
        DiagnosticJobCreate(
            job_type="VALIDATION_SIMULATION",
            simulation_type="SEGMENTATION_PROBE",
            target_device_id=target.id,
            target_port=policy.target_port,
            authorization_phrase=payload.authorization_phrase,
        ),
        admin,
        db,
    )
    check = SegmentationCheck(
        policy_id=policy.id,
        diagnostic_job_id=job.id,
        expected_reachability=policy.expected_reachability,
        source_ip=source.ip_address,
        target_ip=target.ip_address,
        target_port=policy.target_port,
    )
    db.add(check)
    db.commit()
    db.refresh(check)
    return serialize_check(check)


@router.get("/{policy_id}/checks", response_model=list[SegmentationCheckRead])
def list_policy_checks(
    policy_id: int,
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[SegmentationCheckRead]:
    policy = get_policy_or_404(policy_id, db)
    expire_jobs(db, policy.source_device_id)
    checks = db.scalars(select(SegmentationCheck).where(
        SegmentationCheck.policy_id == policy_id,
    ).order_by(SegmentationCheck.id.desc()).limit(limit))
    return [serialize_check(check) for check in checks]
