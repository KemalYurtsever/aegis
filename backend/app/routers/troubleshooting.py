import json
import socket

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ServiceCheck, TroubleshootingRun, User
from app.routers.auth import require_admin
from app.routers.devices import get_device_or_404
from app.schemas import TroubleshootingRunCreate, TroubleshootingRunRead, TroubleshootingStepRead
from app.services.ping_service import check_ip
from app.services.scan_policy import scan_target_rejection_reason
from app.services.security_toolbox_service import query_dns, trace_registered_device
from app.services.service_check_service import probe_service


router = APIRouter(prefix="/api/devices/{device_id}/troubleshooting-runs", tags=["troubleshooting"])


def serialize_run(run: TroubleshootingRun) -> TroubleshootingRunRead:
    return TroubleshootingRunRead(
        id=run.id,
        device_id=run.device_id,
        target_ip=run.target_ip,
        requested_by=run.requested_by,
        source="AEGIS_HOST",
        steps=[TroubleshootingStepRead.model_validate(step) for step in json.loads(run.steps_json)],
        created_at=run.created_at,
    )


@router.post("", response_model=TroubleshootingRunRead, status_code=201)
def run_troubleshooting(
    device_id: int,
    payload: TroubleshootingRunCreate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> TroubleshootingRunRead:
    device = get_device_or_404(device_id, db)
    rejection = scan_target_rejection_reason(device.ip_address, mac_address=device.mac_address)
    if rejection:
        raise HTTPException(status_code=400, detail=rejection)

    service = None
    if payload.service_check_id is not None:
        service = db.scalar(select(ServiceCheck).where(
            ServiceCheck.id == payload.service_check_id,
            ServiceCheck.device_id == device_id,
        ))
        if service is None:
            raise HTTPException(status_code=404, detail="Service check not found on this device")
    if service is not None and payload.tcp_port is not None and payload.tcp_port != service.port:
        raise HTTPException(status_code=422, detail="TCP port must match the selected service check")
    port = payload.tcp_port or (service.port if service else None)

    steps: list[dict[str, str]] = []

    def add(key: str, status: str, observation: str) -> None:
        steps.append({"key": key, "status": status, "observation": observation})

    if device.prefix_length is None:
        add("CONFIG", "INFO", "Subnet prefix is not configured; network membership cannot be confirmed.")
    else:
        add("CONFIG", "PASS", f"Configured target {device.ip_address}/{device.prefix_length}; gateway {device.gateway_ip or 'unknown'}; VLAN {device.vlan or 'unknown'}.")

    if device.gateway_ip:
        result = check_ip(device.gateway_ip, timeout_seconds=2)
        add("GATEWAY", "PASS" if result.status == "ONLINE" else "FAIL",
            f"ICMP from Aegis host to configured gateway {device.gateway_ip}: {result.status.lower()}"
            + (f" ({result.diagnostic_reason})" if result.diagnostic_reason else "")
            + ". A failed ICMP check does not prove the gateway is down.")
    else:
        add("GATEWAY", "SKIP", "No gateway is configured for this device.")

    if payload.dns_name:
        try:
            answer = query_dns(payload.dns_name)
            matched = device.ip_address in answer.addresses
            add("DNS", "PASS" if matched else "FAIL",
                f"{payload.dns_name} resolved to {', '.join(answer.addresses[:8]) or 'no addresses'}; "
                + ("target IP is present." if matched else "target IP is absent."))
        except (ValueError, OSError) as exc:
            add("DNS", "FAIL", f"DNS lookup failed ({type(exc).__name__}).")
    else:
        add("DNS", "SKIP", "Enter a DNS hostname to compare its answer with the target IP.")

    if payload.include_route:
        try:
            route = trace_registered_device(device)
            add("ROUTE", "PASS" if route.completed else "INFO",
                f"Traceroute from Aegis host observed {len(route.hops)} hop(s); "
                + ("target reached." if route.completed else "target was not confirmed."))
        except RuntimeError as exc:
            add("ROUTE", "SKIP", str(exc))
    else:
        add("ROUTE", "SKIP", "Route trace was not requested.")

    target = check_ip(device.ip_address, timeout_seconds=2)
    add("TARGET", "PASS" if target.status == "ONLINE" else "FAIL",
        f"ICMP from Aegis host to target: {target.status.lower()}"
        + (f" ({target.diagnostic_reason})" if target.diagnostic_reason else "")
        + ". ICMP filtering can affect this result.")

    if port is not None:
        try:
            with socket.create_connection((device.ip_address, port), timeout=2):
                pass
            add("PORT", "PASS", f"TCP/{port} accepted a connection from Aegis host; no application data was sent.")
        except OSError as exc:
            add("PORT", "FAIL", f"TCP/{port} connection from Aegis host failed ({type(exc).__name__}); filtering and service state are not distinguished.")
    else:
        add("PORT", "SKIP", "Enter a TCP port or select a configured service check.")

    if service is not None:
        result = probe_service(service, timeout_seconds=3)
        detail = f"{service.name} ({service.check_type}/{service.port}): {result.status.lower()}"
        if result.http_status_code is not None:
            detail += f", HTTP {result.http_status_code}"
        if result.diagnostic_reason:
            detail += f" ({result.diagnostic_reason})"
        add("SERVICE", "PASS" if result.status == "UP" else "FAIL", detail + ".")
    else:
        add("SERVICE", "SKIP", "Select a configured service check for application-level evidence.")

    run = TroubleshootingRun(
        device_id=device_id,
        target_ip=device.ip_address,
        requested_by=admin.username,
        steps_json=json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return serialize_run(run)


@router.get("", response_model=list[TroubleshootingRunRead])
def list_troubleshooting_runs(
    device_id: int,
    limit: int = Query(default=10, ge=1, le=50),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[TroubleshootingRunRead]:
    get_device_or_404(device_id, db)
    runs = db.scalars(select(TroubleshootingRun).where(
        TroubleshootingRun.device_id == device_id,
    ).order_by(TroubleshootingRun.id.desc()).limit(limit))
    return [serialize_run(run) for run in runs]
