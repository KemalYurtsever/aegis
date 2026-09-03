import os
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import SnmpConfig, SnmpResult
from app.routers.devices import get_device_or_404
from app.schemas import SnmpConfigRead, SnmpConfigUpdate, SnmpResultRead
from app.services.snmp_service import get_or_create_config, poll_device

router = APIRouter(prefix="/api/devices/{device_id}/snmp", tags=["snmp"])

def serialize_config(config: SnmpConfig) -> SnmpConfigRead:
    return SnmpConfigRead(id=config.id, device_id=config.device_id, enabled=config.enabled, port=config.port, community_env=config.community_env, secret_configured=bool(os.getenv(config.community_env, "").strip()), updated_at=config.updated_at)

@router.get("", response_model=SnmpConfigRead)
def get_config(device_id: int, db: Session = Depends(get_db)) -> SnmpConfigRead:
    get_device_or_404(device_id, db); config = get_or_create_config(device_id, db); db.commit(); return serialize_config(config)

@router.put("", response_model=SnmpConfigRead)
def update_config(device_id: int, payload: SnmpConfigUpdate, db: Session = Depends(get_db)) -> SnmpConfigRead:
    get_device_or_404(device_id, db); config = get_or_create_config(device_id, db)
    config.enabled = payload.enabled; config.port = payload.port; config.community_env = payload.community_env
    db.commit(); db.refresh(config); return serialize_config(config)

@router.post("/poll", response_model=SnmpResultRead, status_code=201)
def poll(device_id: int, db: Session = Depends(get_db)) -> SnmpResult:
    device = get_device_or_404(device_id, db); config = get_or_create_config(device_id, db); db.commit()
    return poll_device(device, config, db)

@router.get("/history", response_model=list[SnmpResultRead])
def history(device_id: int, limit: int = Query(default=20, ge=1, le=200), db: Session = Depends(get_db)) -> list[SnmpResult]:
    get_device_or_404(device_id, db)
    return list(db.scalars(select(SnmpResult).where(SnmpResult.device_id == device_id).order_by(SnmpResult.timestamp.desc()).limit(limit)))
