import asyncio
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Device, SnmpConfig, SnmpResult

OIDS = {
    "description": "1.3.6.1.2.1.1.1.0",
    "uptime_ticks": "1.3.6.1.2.1.1.3.0",
    "system_name": "1.3.6.1.2.1.1.5.0",
    "location": "1.3.6.1.2.1.1.6.0",
    "interface_count": "1.3.6.1.2.1.2.1.0",
}


def get_or_create_config(device_id: int, db: Session) -> SnmpConfig:
    config = db.scalar(select(SnmpConfig).where(SnmpConfig.device_id == device_id))
    if config is None:
        config = SnmpConfig(device_id=device_id)
        db.add(config); db.flush()
    return config


async def query_snmp(host: str, port: int, community: str, timeout: float = 2.0) -> dict:
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, get_cmd
    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=0)
        response = await get_cmd(engine, CommunityData(community), target, ContextData(), *[ObjectType(ObjectIdentity(oid)) for oid in OIDS.values()])
        error_indication, error_status, error_index, var_binds = response
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(f"{error_status.prettyPrint()} at index {error_index}")
        values = [value.prettyPrint() for _, value in var_binds]
        result = dict(zip(OIDS, values, strict=True))
        for field in ("uptime_ticks", "interface_count"):
            try: result[field] = int(result[field])
            except (TypeError, ValueError): result[field] = None
        return result
    finally:
        engine.close_dispatcher()


def poll_device(device: Device, config: SnmpConfig, db: Session) -> SnmpResult:
    community = os.getenv(config.community_env, "").strip()
    if not community:
        result = SnmpResult(device_id=device.id, status="FAILED", error=f"Environment variable {config.community_env} is not configured")
    else:
        try:
            values = asyncio.run(query_snmp(device.ip_address, config.port, community))
            result = SnmpResult(device_id=device.id, status="SUCCESS", **values)
        except Exception as exc:
            result = SnmpResult(device_id=device.id, status="FAILED", error=str(exc)[:500])
    db.add(result); db.commit(); db.refresh(result)
    return result
