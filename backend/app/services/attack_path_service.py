import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import Device, VulnerabilityFinding, VulnerabilityScan, utc_now
from app.schemas import AttackPathOverview, AttackPathRead


PIVOT_PORTS = {21, 22, 23, 445, 3389, 5900}
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CRITICALITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _network_key(address: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    prefix = 24 if parsed.version == 4 else 64
    return str(ipaddress.ip_network(f"{parsed}/{prefix}", strict=False))


def _shared_scope(entry: Device, target: Device) -> str | None:
    if entry.device_group and entry.device_group == target.device_group:
        return f"shared device group {entry.device_group}"
    entry_network = _network_key(entry.ip_address)
    if entry_network and entry_network == _network_key(target.ip_address):
        return f"shared subnet {entry_network}"
    return None


def _path_severity(finding: VulnerabilityFinding, target: Device) -> str:
    rank = max(
        SEVERITY_RANK.get(finding.severity, 1),
        CRITICALITY_RANK.get(target.criticality, 1),
    )
    return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[rank]


def _latest_completed_scans(db: Session) -> dict[int, VulnerabilityScan]:
    scans = db.scalars(
        select(VulnerabilityScan)
        .options(selectinload(VulnerabilityScan.findings))
        .where(VulnerabilityScan.status == "COMPLETED")
        .order_by(
            VulnerabilityScan.device_id,
            VulnerabilityScan.started_at.desc(),
            VulnerabilityScan.id.desc(),
        )
    )
    latest: dict[int, VulnerabilityScan] = {}
    for scan in scans:
        latest.setdefault(scan.device_id, scan)
    return latest


def build_attack_paths(db: Session, limit: int = 100) -> AttackPathOverview:
    devices = list(db.scalars(
        select(Device).where(Device.is_active.is_(True)).order_by(Device.id)
    ))
    device_by_id = {device.id: device for device in devices}
    scans = _latest_completed_scans(db)
    paths: list[AttackPathRead] = []

    for entry_id, scan in scans.items():
        entry = device_by_id.get(entry_id)
        if entry is None:
            continue
        pivot_findings = [
            finding for finding in scan.findings
            if finding.port in PIVOT_PORTS and finding.severity in SEVERITY_RANK
        ]
        if not pivot_findings:
            continue
        finding = max(
            pivot_findings,
            key=lambda item: (SEVERITY_RANK[item.severity], -(item.port or 0)),
        )
        targets = [
            (target, _shared_scope(entry, target))
            for target in devices
            if target.id != entry.id
        ]
        targets = [(target, scope) for target, scope in targets if scope]
        targets.sort(
            key=lambda item: (-CRITICALITY_RANK.get(item[0].criticality, 1), item[0].name, item[0].id)
        )
        if not targets:
            targets = [(entry, "direct exposure of the assessed asset")]

        for target, scope in targets[:5]:
            paths.append(AttackPathRead(
                entry_device_id=entry.id,
                entry_device_name=entry.name,
                entry_ip_address=entry.ip_address,
                entry_port=finding.port,
                entry_finding=finding.title,
                target_device_id=target.id,
                target_device_name=target.name,
                target_ip_address=target.ip_address,
                severity=_path_severity(finding, target),
                rationale=(
                    f"{finding.title} on TCP {finding.port} is a possible entry point; "
                    f"{scope} may permit access toward this {target.criticality.lower()}-criticality asset."
                ),
            ))

    paths.sort(key=lambda item: (
        -SEVERITY_RANK[item.severity],
        item.entry_device_name,
        item.target_device_name,
    ))
    paths = paths[:limit]
    return AttackPathOverview(
        generated_at=utc_now(),
        assessed_devices=len(scans),
        candidate_paths=len(paths),
        paths=paths,
    )
