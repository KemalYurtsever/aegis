from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, utc_now
from app.routers.auth import require_admin
from app.schemas import DhcpLeaseImport, DhcpLeaseImportResult, InventoryHealthIssue, InventoryHealthResponse, validate_device_network
from app.services.discovery_service import is_generic_ptr_hostname
from app.services.mac_vendor_service import lookup_mac_vendor
from app.services.statistics_service import (
    DeviceMonitorSnapshot,
    load_device_monitor_snapshot,
)


router = APIRouter(
    prefix="/api/inventory",
    tags=["inventory"],
)


def _may_replace_name(device: Device) -> bool:
    return (
        device.inventory_source == "DHCP_IMPORT"
        or device.name in {f"Discovered {device.ip_address}", f"DHCP {device.ip_address}"}
        or is_generic_ptr_hostname(device.ip_address, device.name)
    )


@router.post(
    "/dhcp-leases/import",
    response_model=DhcpLeaseImportResult,
    dependencies=[Depends(require_admin)],
)
def import_dhcp_leases(payload: DhcpLeaseImport, db: Session = Depends(get_db)) -> DhcpLeaseImportResult:
    devices = list(db.scalars(select(Device).order_by(Device.id)))
    by_ip = {device.ip_address: device for device in devices}
    by_mac = {device.mac_address.upper(): device for device in devices if device.mac_address}
    added = 0
    updated = 0
    skipped = 0
    conflicts: list[str] = []

    for row_number, row in enumerate(payload.rows, start=1):
        device_by_mac = by_mac.get(row.mac_address) if row.mac_address else None
        device_by_ip = by_ip.get(row.ip_address)
        if device_by_mac is not None and device_by_ip is not None and device_by_mac is not device_by_ip:
            skipped += 1
            conflicts.append(
                f"Row {row_number}: MAC {row.mac_address} belongs to {device_by_mac.ip_address}, "
                f"but {row.ip_address} belongs to another device."
            )
            continue

        device = device_by_mac or device_by_ip
        if device is None:
            device = Device(
                name=row.hostname or f"DHCP {row.ip_address}",
                ip_address=row.ip_address,
                mac_address=row.mac_address,
                manufacturer=lookup_mac_vendor(row.mac_address),
                inventory_source="DHCP_IMPORT",
                vlan=row.vlan,
                prefix_length=row.prefix_length,
                gateway_ip=row.gateway_ip,
                lease_expires_at=row.lease_expires_at,
                device_type="Other",
                description="Imported from an administrator-provided DHCP lease inventory.",
                is_active=True,
            )
            db.add(device)
            by_ip[row.ip_address] = device
            if row.mac_address:
                by_mac[row.mac_address] = device
            added += 1
            continue

        old_ip = device.ip_address
        replace_name = bool(row.hostname and _may_replace_name(device))
        if device_by_mac is device and old_ip != row.ip_address:
            by_ip.pop(old_ip, None)
            device.ip_address = row.ip_address
            device.prefix_length = row.prefix_length
            device.gateway_ip = row.gateway_ip
            by_ip[row.ip_address] = device
        elif row.prefix_length is not None:
            if row.prefix_length != device.prefix_length and row.gateway_ip is None:
                device.gateway_ip = None
            device.prefix_length = row.prefix_length
        if row.gateway_ip is not None:
            device.gateway_ip = row.gateway_ip
        try:
            validate_device_network(device.ip_address, device.prefix_length, device.gateway_ip)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=422, detail=f"Row {row_number}: {exc}") from exc
        if row.mac_address:
            if device.mac_address:
                by_mac.pop(device.mac_address.upper(), None)
            device.mac_address = row.mac_address
            device.manufacturer = lookup_mac_vendor(row.mac_address)
            by_mac[row.mac_address] = device
        if replace_name:
            device.name = row.hostname
        device.inventory_source = "DHCP_IMPORT"
        device.vlan = row.vlan
        device.lease_expires_at = row.lease_expires_at
        updated += 1

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="The import conflicts with existing inventory data") from exc

    return DhcpLeaseImportResult(
        rows_received=len(payload.rows),
        devices_added=added,
        devices_updated=updated,
        rows_skipped=skipped,
        conflicts=conflicts[:100],
    )


def _aware(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def build_inventory_health(
    stale_hours: int,
    db: Session,
    device_result_rows: DeviceMonitorSnapshot | None = None,
) -> InventoryHealthResponse:
    now = utc_now()
    stale_before = now - timedelta(hours=stale_hours)
    expiring_before = now + timedelta(hours=24)
    if device_result_rows is None:
        device_result_rows = load_device_monitor_snapshot(db)
    devices = [row[0] for row in device_result_rows]
    latest_by_device = {
        device.id: result.timestamp
        for device, result in device_result_rows
        if result is not None
    }
    issues: list[InventoryHealthIssue] = []

    for device in devices:
        lease_expiry = _aware(device.lease_expires_at)
        if lease_expiry is not None and lease_expiry < now:
            issues.append(InventoryHealthIssue(
                device_id=device.id, device_name=device.name, ip_address=device.ip_address,
                issue_type="LEASE_EXPIRED", detail=f"DHCP lease expired at {lease_expiry.isoformat()}.",
            ))
        elif lease_expiry is not None and lease_expiry <= expiring_before:
            issues.append(InventoryHealthIssue(
                device_id=device.id, device_name=device.name, ip_address=device.ip_address,
                issue_type="LEASE_EXPIRING", detail=f"DHCP lease expires at {lease_expiry.isoformat()}.",
            ))

        latest_timestamp = latest_by_device.get(device.id)
        if latest_timestamp is None:
            issues.append(InventoryHealthIssue(
                device_id=device.id, device_name=device.name, ip_address=device.ip_address,
                issue_type="NEVER_CHECKED", detail="This device has no monitoring results.",
            ))
        elif _aware(latest_timestamp) < stale_before:
            issues.append(InventoryHealthIssue(
                device_id=device.id, device_name=device.name, ip_address=device.ip_address,
                issue_type="STALE_CHECK", detail=f"Last monitoring result was {latest_timestamp.isoformat()}.",
            ))

    mac_groups: dict[str, list[Device]] = {}
    for device in devices:
        if device.mac_address:
            key = device.mac_address.replace("-", ":").upper()
            mac_groups.setdefault(key, []).append(device)
    for mac_address, matches in mac_groups.items():
        if len(matches) < 2:
            continue
        addresses = ", ".join(item.ip_address for item in matches)
        for device in matches:
            issues.append(InventoryHealthIssue(
                device_id=device.id, device_name=device.name, ip_address=device.ip_address,
                issue_type="DUPLICATE_MAC", detail=f"MAC {mac_address} is also assigned within: {addresses}.",
            ))

    counts = {issue_type: sum(issue.issue_type == issue_type for issue in issues) for issue_type in (
        "LEASE_EXPIRED", "LEASE_EXPIRING", "NEVER_CHECKED", "STALE_CHECK", "DUPLICATE_MAC"
    )}
    return InventoryHealthResponse(
        total_issues=len(issues),
        expired_leases=counts["LEASE_EXPIRED"],
        expiring_leases=counts["LEASE_EXPIRING"],
        never_checked=counts["NEVER_CHECKED"],
        stale_checks=counts["STALE_CHECK"],
        duplicate_mac_records=counts["DUPLICATE_MAC"],
        issues=issues,
    )


@router.get("/health", response_model=InventoryHealthResponse)
def inventory_health(
    stale_hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
) -> InventoryHealthResponse:
    return build_inventory_health(stale_hours, db)
