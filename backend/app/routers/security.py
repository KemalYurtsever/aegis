from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
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
    NmapTcpScanRequest,
    ArpScanRequest,
    NeighborTableRequest,
    CurlRequest,
    DigRequest,
)
from app.services.attack_path_service import build_attack_paths
from app.services.security_toolbox_service import arp_scan, curl_request, dig_query, host_network_policy, neighbor_table, nmap_tcp_scan, query_dns, trace_registered_device, wireless_adapters


router = APIRouter(
    prefix="/api/security",
    tags=["security analysis"],
    dependencies=[Depends(require_admin)],
)


@router.get("/attack-paths", response_model=AttackPathOverview)
def attack_paths(
    limit: int = Query(default=100, ge=1, le=250),
    db: Session = Depends(get_db),
) -> AttackPathOverview:
    return build_attack_paths(db, limit=limit)


@router.post("/toolbox/traceroute", response_model=TraceRouteRead)
def traceroute(payload: TraceRouteRequest, db: Session = Depends(get_db)) -> TraceRouteRead:
    device = get_device_or_404(payload.device_id, db)
    try:
        return trace_registered_device(device)
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
    try:
        return nmap_tcp_scan(device.ip_address, payload.ports, payload.service_detection, payload.grep)
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
