from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models import Device, SecurityPlaybookRun, utc_now
from app.routers.auth import require_admin
from app.routers.devices import get_device_or_404
from app.schemas import (
    AttackPathOverview,
    DnsQueryRead,
    DnsQueryRequest,
    HostNetworkPolicyRead,
    TraceRouteRead,
    TraceRouteRequest,
    WirelessAdapterRead,
    LabCommandRead,
    LabCommandFilter,
    NmapTcpScanRequest,
    NmapUdpScanRequest,
    TestConnectionPortRequest,
    ArpScanRequest,
    NeighborTableRequest,
    CurlRequest,
    DigRequest,
    SecurityPlaybookRunCreate,
    SecurityPlaybookRunIndexRead,
    SecurityPlaybookRunRead,
)
from app.services.attack_path_service import build_attack_paths
from app.services.security_playbook_service import (
    TERMINAL_RUN_STATUSES,
    build_playbook_run,
    load_playbook_run,
)
from app.services.scan_policy import scan_target_rejection_reason
from app.services.security_toolbox_service import (
    arp_scan,
    avahi_browse,
    curl_request,
    dig_query,
    host_network_policy,
    neighbor_table,
    nmap_tcp_scan,
    nmap_udp_scan,
    query_dns,
    test_connection_ports,
    trace_registered_device,
    wireless_adapters,
)


router = APIRouter(
    prefix="/api/security",
    tags=["security analysis"],
    dependencies=[Depends(require_admin)],
)


def ensure_device_scan_target_allowed(device: Device) -> None:
    rejection = scan_target_rejection_reason(
        device.ip_address,
        mac_address=device.mac_address,
    )
    if rejection:
        raise HTTPException(status_code=400, detail=rejection)


@router.get("/attack-paths", response_model=AttackPathOverview)
def attack_paths(
    limit: int = Query(default=100, ge=1, le=250),
    db: Session = Depends(get_db),
) -> AttackPathOverview:
    return build_attack_paths(db, limit=limit)


@router.post("/playbooks/runs", response_model=SecurityPlaybookRunRead, status_code=202)
def create_playbook_run(
    payload: SecurityPlaybookRunCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> SecurityPlaybookRun:
    device = get_device_or_404(payload.device_id, db)
    user = getattr(request.state, "user", None)
    try:
        run = build_playbook_run(device, payload.profile, getattr(user, "username", "administrator"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.add(run)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This target already has an active security playbook",
        ) from exc
    db.refresh(run)
    runner = getattr(request.app.state, "playbook_runner", None)
    if runner is None or not runner.submit(run.id):
        run.status = "FAILED"
        run.active_slot = None
        run.completed_at = utc_now()
        run.error = "The security playbook queue is unavailable"
        for step in run.steps:
            step.status = "CANCELLED"
            step.completed_at = run.completed_at
        db.commit()
        raise HTTPException(status_code=503, detail=run.error)
    loaded = load_playbook_run(run.id, db)
    if loaded is None:
        raise HTTPException(status_code=500, detail="The queued security playbook could not be loaded")
    return loaded


@router.get("/playbooks/runs", response_model=list[SecurityPlaybookRunRead])
def list_playbook_runs(
    device_id: int | None = Query(default=None, gt=0),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[SecurityPlaybookRun]:
    statement = (
        select(SecurityPlaybookRun)
        .options(selectinload(SecurityPlaybookRun.steps))
        .order_by(SecurityPlaybookRun.created_at.desc(), SecurityPlaybookRun.id.desc())
        .limit(limit)
    )
    if device_id is not None:
        get_device_or_404(device_id, db)
        statement = statement.where(SecurityPlaybookRun.device_id == device_id)
    return list(db.scalars(statement))


@router.get("/playbooks/run-index", response_model=list[SecurityPlaybookRunIndexRead])
def list_playbook_run_index(
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[SecurityPlaybookRun]:
    return list(db.scalars(
        select(SecurityPlaybookRun)
        .order_by(SecurityPlaybookRun.created_at.desc(), SecurityPlaybookRun.id.desc())
        .limit(limit)
    ))


@router.get("/playbooks/runs/{run_id}", response_model=SecurityPlaybookRunRead)
def get_playbook_run(run_id: int, db: Session = Depends(get_db)) -> SecurityPlaybookRun:
    run = load_playbook_run(run_id, db)
    if run is None:
        raise HTTPException(status_code=404, detail="Security playbook run not found")
    return run


@router.post("/playbooks/runs/{run_id}/cancel", response_model=SecurityPlaybookRunRead)
def cancel_playbook_run(
    run_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> SecurityPlaybookRun:
    run = load_playbook_run(run_id, db)
    if run is None:
        raise HTTPException(status_code=404, detail="Security playbook run not found")
    if run.status in TERMINAL_RUN_STATUSES:
        raise HTTPException(status_code=409, detail="This security playbook has already finished")
    runner = getattr(request.app.state, "playbook_runner", None)
    if runner is None or not runner.cancel(run_id):
        raise HTTPException(status_code=409, detail="This security playbook can no longer be cancelled")
    db.expire_all()
    updated = load_playbook_run(run_id, db)
    if updated is None:
        raise HTTPException(status_code=404, detail="Security playbook run not found")
    return updated


@router.post("/toolbox/traceroute", response_model=TraceRouteRead)
def traceroute(payload: TraceRouteRequest, db: Session = Depends(get_db)) -> TraceRouteRead:
    device = get_device_or_404(payload.device_id, db)
    ensure_device_scan_target_allowed(device)
    try:
        return trace_registered_device(device)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/dns-query", response_model=DnsQueryRead)
def dns_query(payload: DnsQueryRequest) -> DnsQueryRead:
    try:
        return query_dns(payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/toolbox/wireless", response_model=list[WirelessAdapterRead])
def wireless() -> list[WirelessAdapterRead]:
    return wireless_adapters()


@router.get("/toolbox/host-network-policy", response_model=HostNetworkPolicyRead)
def inspect_host_network_policy() -> HostNetworkPolicyRead:
    try:
        return host_network_policy()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/nmap", response_model=LabCommandRead)
def nmap_scan(payload: NmapTcpScanRequest, db: Session = Depends(get_db)) -> LabCommandRead:
    device = get_device_or_404(payload.device_id, db)
    ensure_device_scan_target_allowed(device)
    try:
        return nmap_tcp_scan(
            device.ip_address,
            payload.ports,
            payload.service_detection,
            grep=payload.grep,
            scan_mode=payload.scan_mode,
            profile=payload.profile,
            show_reason=payload.show_reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/nmap-udp", response_model=LabCommandRead)
def nmap_udp_scan_endpoint(
    payload: NmapUdpScanRequest,
    db: Session = Depends(get_db),
) -> LabCommandRead:
    device = get_device_or_404(payload.device_id, db)
    ensure_device_scan_target_allowed(device)
    try:
        return nmap_udp_scan(
            device.ip_address,
            payload.ports,
            profile=payload.profile,
            show_reason=payload.show_reason,
            grep=payload.grep,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/test-connection", response_model=LabCommandRead)
def test_connection_scan(payload: TestConnectionPortRequest, db: Session = Depends(get_db)) -> LabCommandRead:
    device = get_device_or_404(payload.device_id, db)
    ensure_device_scan_target_allowed(device)
    try:
        return test_connection_ports(
            device.ip_address,
            payload.ports,
            payload.timeout_seconds,
            payload.grep,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/arp-scan", response_model=LabCommandRead)
def run_arp_scan(payload: ArpScanRequest) -> LabCommandRead:
    try:
        return arp_scan(payload.interface_name, payload.grep)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/neighbors", response_model=LabCommandRead)
def show_neighbors(payload: NeighborTableRequest) -> LabCommandRead:
    try:
        return neighbor_table(payload.grep)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/avahi-browse", response_model=LabCommandRead)
def browse_mdns(payload: LabCommandFilter) -> LabCommandRead:
    try:
        return avahi_browse(payload.grep)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/curl", response_model=LabCommandRead)
def run_curl(payload: CurlRequest) -> LabCommandRead:
    try:
        return curl_request(payload.url, payload.method, payload.insecure, payload.grep)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/toolbox/dig", response_model=LabCommandRead)
def run_dig(payload: DigRequest) -> LabCommandRead:
    try:
        return dig_query(payload.query, payload.record_type, payload.grep)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
