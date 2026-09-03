from collections import defaultdict
from ipaddress import ip_address, ip_network

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, TopologyLink
from app.schemas import TopologyDevice, TopologyLinkCreate, TopologyLinkRead, TopologyNetwork, TopologyResponse
from app.services.discovery_service import LocalNetwork, get_primary_private_network
from app.services.statistics_service import calculate_device_statistics

router = APIRouter(prefix="/api/topology", tags=["topology"])


def serialize_link(link: TopologyLink, devices: dict[int, Device]) -> TopologyLinkRead:
    return TopologyLinkRead(
        id=link.id,
        source_device_id=link.source_device_id,
        target_device_id=link.target_device_id,
        relationship_type=link.relationship_type,
        description=link.description,
        source_name=devices[link.source_device_id].name,
        target_name=devices[link.target_device_id].name,
        created_at=link.created_at,
    )


@router.post("/links", response_model=TopologyLinkRead, status_code=status.HTTP_201_CREATED)
def create_topology_link(payload: TopologyLinkCreate, db: Session = Depends(get_db)) -> TopologyLinkRead:
    if payload.source_device_id == payload.target_device_id:
        raise HTTPException(status_code=422, detail="A device cannot link to itself")
    devices = {
        device.id: device for device in db.scalars(
            select(Device).where(Device.id.in_([payload.source_device_id, payload.target_device_id]))
        )
    }
    if len(devices) != 2:
        raise HTTPException(status_code=404, detail="Source or target device not found")
    link = TopologyLink(**payload.model_dump())
    db.add(link)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="This topology relationship already exists") from exc
    db.refresh(link)
    return serialize_link(link, devices)


@router.delete("/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_topology_link(link_id: int, db: Session = Depends(get_db)) -> Response:
    link = db.get(TopologyLink, link_id)
    if link is None:
        raise HTTPException(status_code=404, detail="Topology relationship not found")
    db.delete(link)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def device_subnet(address: str) -> str:
    parsed = ip_address(address)
    prefix = 24 if parsed.version == 4 else 64
    return str(ip_network(f"{parsed}/{prefix}", strict=False))


def connected_network() -> LocalNetwork | None:
    try:
        return get_primary_private_network()
    except (RuntimeError, OSError, ValueError):
        return None


@router.get("", response_model=TopologyResponse)
def get_topology(db: Session = Depends(get_db)) -> TopologyResponse:
    active_network = connected_network()
    grouped: dict[tuple[str | None, str], list[Device]] = defaultdict(list)
    for device in db.scalars(select(Device).order_by(Device.name, Device.id)):
        grouped[(device.vlan, device_subnet(device.ip_address))].append(device)

    groups: list[TopologyNetwork] = []
    for (vlan, subnet), devices in grouped.items():
        subnet_network = ip_network(subnet)
        gateway_ip = None
        if active_network and active_network.gateway:
            candidate = ip_address(active_network.gateway)
            if candidate in subnet_network:
                gateway_ip = active_network.gateway
        gateway_device = next(
            (device for device in devices if gateway_ip and device.ip_address == gateway_ip),
            None,
        ) or next((device for device in devices if device.device_type == "Router"), None)
        if gateway_ip is None and gateway_device is not None:
            gateway_ip = gateway_device.ip_address

        rows: list[TopologyDevice] = []
        for device in devices:
            if gateway_device is not None and device.id == gateway_device.id:
                role = "GATEWAY"
            elif device.device_type in {"Router", "Switch", "Access Point"}:
                role = "INFRASTRUCTURE"
            else:
                role = "ENDPOINT"
            rows.append(TopologyDevice(
                device_id=device.id,
                name=device.name,
                ip_address=device.ip_address,
                device_type=device.device_type,
                status=calculate_device_statistics(device.id, db).current_status,
                role=role,
            ))
        rows.sort(key=lambda row: ({"GATEWAY": 0, "INFRASTRUCTURE": 1, "ENDPOINT": 2}[row.role], row.name.lower()))
        label = f"VLAN {vlan} · {subnet}" if vlan else subnet
        groups.append(TopologyNetwork(
            key=f"{vlan or 'untagged'}:{subnet}",
            label=label,
            subnet=subnet,
            vlan=vlan,
            gateway_ip=gateway_ip,
            gateway_device_id=gateway_device.id if gateway_device else None,
            device_count=len(rows),
            online_devices=sum(row.status == "ONLINE" for row in rows),
            offline_devices=sum(row.status == "OFFLINE" for row in rows),
            unknown_devices=sum(row.status == "UNKNOWN" for row in rows),
            devices=rows,
        ))
    groups.sort(key=lambda group: (group.vlan or "", ip_network(group.subnet).version, group.subnet))
    all_devices = {device.id: device for devices in grouped.values() for device in devices}
    links = [
        serialize_link(link, all_devices)
        for link in db.scalars(select(TopologyLink).order_by(TopologyLink.id))
        if link.source_device_id in all_devices and link.target_device_id in all_devices
    ]
    return TopologyResponse(
        interface_name=active_network.interface_name if active_network else None,
        local_ip=active_network.local_ip if active_network else None,
        groups=groups,
        links=links,
    )
