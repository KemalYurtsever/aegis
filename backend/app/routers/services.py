import concurrent.futures
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, ServiceCheck, ServiceResult
from app.routers.devices import get_device_or_404
from app.schemas import DeviceFingerprintRead, FingerprintBatchResponse, PortScanResponse, ServiceCheckCreate, ServiceCheckRead, ServiceOverview, ServiceOverviewItem, ServiceResultRead, ServiceStatistics
from app.services.fingerprint_service import FingerprintEvidence, fingerprint_target
from app.services.port_scan_service import COMMON_TCP_PORTS, scan_common_tcp_ports
from app.services.scan_policy import scan_target_allowed
from app.services.service_check_service import run_and_store_service_check

router = APIRouter(prefix="/api", tags=["services"])


def ensure_scan_target_allowed(address: str) -> None:
    if not scan_target_allowed(address):
        raise HTTPException(status_code=400, detail="Scanning is restricted to the connected authorized LAN")


def store_fingerprint(device, evidence: FingerprintEvidence, db: Session) -> DeviceFingerprintRead:
    result = apply_fingerprint(device, evidence)
    db.commit(); db.refresh(device)
    return result


def apply_fingerprint(device, evidence: FingerprintEvidence) -> DeviceFingerprintRead:
    device.fingerprint_ports = ",".join(str(port) for port in evidence.open_ports) or None
    device.fingerprint_summary = evidence.summary
    device.fingerprinted_at = evidence.timestamp
    if evidence.classification and device.device_type == "Other":
        device.device_type = evidence.classification
    return DeviceFingerprintRead(
        device_id=device.id, classification=evidence.classification, open_ports=evidence.open_ports,
        summary=evidence.summary, fingerprinted_at=evidence.timestamp,
    )


def get_check_or_404(check_id: int, db: Session) -> ServiceCheck:
    check = db.get(ServiceCheck, check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="Service check not found")
    return check


def serialize_check(check: ServiceCheck, db: Session) -> ServiceCheckRead:
    latest = db.scalar(
        select(ServiceResult)
        .where(ServiceResult.service_check_id == check.id)
        .order_by(ServiceResult.timestamp.desc(), ServiceResult.id.desc()).limit(1)
    )
    return ServiceCheckRead(
        id=check.id, device_id=check.device_id, name=check.name, check_type=check.check_type,
        port=check.port, path=check.path, is_active=check.is_active, created_at=check.created_at,
        current_status=latest.status if latest else "UNKNOWN",
        last_response_time_ms=latest.response_time_ms if latest else None,
        last_checked_at=latest.timestamp if latest else None,
    )


@router.get("/service-checks/overview", response_model=ServiceOverview)
def get_service_overview(db: Session = Depends(get_db)) -> ServiceOverview:
    latest_result_id = (
        select(ServiceResult.id)
        .where(ServiceResult.service_check_id == ServiceCheck.id)
        .order_by(ServiceResult.timestamp.desc(), ServiceResult.id.desc())
        .limit(1)
        .correlate(ServiceCheck)
        .scalar_subquery()
    )
    rows = db.execute(
        select(ServiceCheck, Device, ServiceResult)
        .join(Device, Device.id == ServiceCheck.device_id)
        .outerjoin(ServiceResult, ServiceResult.id == latest_result_id)
    ).all()
    services = [
        ServiceOverviewItem(
            id=check.id,
            device_id=device.id,
            device_name=device.name,
            ip_address=device.ip_address,
            name=check.name,
            check_type=check.check_type,
            port=check.port,
            path=check.path,
            is_active=check.is_active,
            current_status=result.status if result else "UNKNOWN",
            last_response_time_ms=result.response_time_ms if result else None,
            last_checked_at=result.timestamp if result else None,
            diagnostic_reason=result.diagnostic_reason if result else None,
        )
        for check, device, result in rows
    ]
    priority = {"DOWN": 0, "UNKNOWN": 1, "UP": 2}
    services.sort(key=lambda item: (
        not item.is_active,
        priority[item.current_status],
        item.device_name.casefold(),
        item.name.casefold(),
    ))
    active = [service for service in services if service.is_active]
    return ServiceOverview(
        total_services=len(services),
        active_services=len(active),
        up_services=sum(service.current_status == "UP" for service in active),
        down_services=sum(service.current_status == "DOWN" for service in active),
        unknown_services=sum(service.current_status == "UNKNOWN" for service in active),
        services=services,
    )
@router.get("/devices/{device_id}/service-checks", response_model=list[ServiceCheckRead])
def list_service_checks(device_id: int, db: Session = Depends(get_db)):
    get_device_or_404(device_id, db)
    checks = db.scalars(select(ServiceCheck).where(ServiceCheck.device_id == device_id).order_by(ServiceCheck.id))
    return [serialize_check(check, db) for check in checks]


@router.post("/devices/{device_id}/service-checks", response_model=ServiceCheckRead, status_code=201)
def create_service_check(device_id: int, payload: ServiceCheckCreate, db: Session = Depends(get_db)):
    get_device_or_404(device_id, db)
    check = ServiceCheck(device_id=device_id, **payload.model_dump())
    db.add(check); db.commit(); db.refresh(check)
    return serialize_check(check, db)


@router.post("/devices/{device_id}/scan-ports", response_model=PortScanResponse)
def scan_device_ports(device_id: int, db: Session = Depends(get_db)) -> PortScanResponse:
    device = get_device_or_404(device_id, db)
    # The endpoint already limits targets to registered AEGIS devices. When
    # public-LAN discovery is enabled, also permit addresses inside the bounded
    # network of the active physical adapter (for example, 198.19.4.0/24).
    ensure_scan_target_allowed(device.ip_address)
    open_ports = scan_common_tcp_ports(device.ip_address)
    return PortScanResponse(
        device_id=device.id,
        target_ip=device.ip_address,
        scanned_ports=list(COMMON_TCP_PORTS),
        open_ports=[port.__dict__ for port in open_ports],
    )


@router.post("/devices/{device_id}/fingerprint", response_model=DeviceFingerprintRead)
def fingerprint_device(device_id: int, db: Session = Depends(get_db)) -> DeviceFingerprintRead:
    device = get_device_or_404(device_id, db)
    ensure_scan_target_allowed(device.ip_address)
    evidence = fingerprint_target(device.ip_address, device.manufacturer, device.discovered_services)
    return store_fingerprint(device, evidence, db)


@router.post("/devices/fingerprint-all", response_model=FingerprintBatchResponse)
def fingerprint_all_devices(db: Session = Depends(get_db)) -> FingerprintBatchResponse:
    devices = list(db.scalars(select(Device).where(Device.is_active.is_(True))))
    allowed = []
    for device in devices:
        try:
            ensure_scan_target_allowed(device.ip_address)
            allowed.append(device)
        except HTTPException:
            continue
    jobs = [(device.ip_address, device.manufacturer, device.discovered_services) for device in allowed]

    def fingerprint(job):
        return fingerprint_target(*job)

    worker_count = min(8, len(allowed))
    if worker_count:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            evidence_rows = list(executor.map(fingerprint, jobs))
    else:
        evidence_rows = []
    results = [apply_fingerprint(device, evidence) for device, evidence in zip(allowed, evidence_rows)]
    if results:
        db.commit()
    return FingerprintBatchResponse(
        fingerprinted_devices=len(results),
        classified_devices=sum(result.classification is not None for result in results),
        results=results,
    )


@router.put("/service-checks/{check_id}", response_model=ServiceCheckRead)
def update_service_check(check_id: int, payload: ServiceCheckCreate, db: Session = Depends(get_db)):
    check = get_check_or_404(check_id, db)
    for field, value in payload.model_dump().items(): setattr(check, field, value)
    db.commit(); db.refresh(check)
    return serialize_check(check, db)


@router.delete("/service-checks/{check_id}", status_code=204)
def delete_service_check(check_id: int, db: Session = Depends(get_db)):
    db.delete(get_check_or_404(check_id, db)); db.commit()
    return Response(status_code=204)


@router.post("/service-checks/{check_id}/run", response_model=ServiceResultRead, status_code=201)
def run_service_check(check_id: int, db: Session = Depends(get_db)):
    return run_and_store_service_check(get_check_or_404(check_id, db), db)


@router.get("/service-checks/{check_id}/statistics", response_model=ServiceStatistics)
def get_service_statistics(check_id: int, db: Session = Depends(get_db)) -> ServiceStatistics:
    get_check_or_404(check_id, db)
    total = db.scalar(select(func.count(ServiceResult.id)).where(ServiceResult.service_check_id == check_id)) or 0
    up = db.scalar(select(func.count(ServiceResult.id)).where(ServiceResult.service_check_id == check_id, ServiceResult.status == "UP")) or 0
    average = db.scalar(select(func.avg(ServiceResult.response_time_ms)).where(ServiceResult.service_check_id == check_id, ServiceResult.response_time_ms.is_not(None)))
    latest = db.scalar(select(ServiceResult).where(ServiceResult.service_check_id == check_id).order_by(ServiceResult.timestamp.desc(), ServiceResult.id.desc()).limit(1))
    return ServiceStatistics(
        service_check_id=check_id,
        total_checks=total,
        up_checks=up,
        down_checks=total - up,
        availability_percent=round(up / total * 100, 2) if total else None,
        average_response_time_ms=round(float(average), 2) if average is not None else None,
        current_status=latest.status if latest else "UNKNOWN",
        last_checked_at=latest.timestamp if latest else None,
    )


@router.get("/service-checks/{check_id}/history", response_model=list[ServiceResultRead])
def get_service_history(check_id: int, limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    get_check_or_404(check_id, db)
    return list(db.scalars(select(ServiceResult).where(ServiceResult.service_check_id == check_id).order_by(ServiceResult.timestamp.desc(), ServiceResult.id.desc()).limit(limit)))
