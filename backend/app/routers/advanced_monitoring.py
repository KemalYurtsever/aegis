from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.database import get_db
from app.models import AnomalyEvent, PacketCapture
from app.routers.auth import require_admin
from app.routers.devices import get_device_or_404
from app.schemas import AnomalyEventRead, PacketCaptureInterface, PacketCaptureRead, PacketCaptureRequest
from app.services.anomaly_service import detect_device_anomalies
from app.services.packet_capture_service import available_interfaces, run_capture

router = APIRouter(prefix="/api", tags=["advanced monitoring"])

@router.get("/packet-captures/interfaces", response_model=list[PacketCaptureInterface], dependencies=[Depends(require_admin)])
def interfaces() -> list[dict]: return available_interfaces()

@router.post("/packet-captures", response_model=PacketCaptureRead, status_code=201, dependencies=[Depends(require_admin)])
def create_capture(payload: PacketCaptureRequest, db: Session = Depends(get_db)) -> PacketCapture:
    return run_capture(payload.interface_name, payload.duration_seconds, payload.max_packets, db)

@router.get("/packet-captures", response_model=list[PacketCaptureRead], dependencies=[Depends(require_admin)])
def captures(limit: int = Query(default=10, ge=1, le=50), db: Session = Depends(get_db)) -> list[PacketCapture]:
    return list(db.scalars(select(PacketCapture).options(selectinload(PacketCapture.packets)).order_by(PacketCapture.started_at.desc()).limit(limit)))

@router.post("/devices/{device_id}/anomalies/detect", response_model=list[AnomalyEventRead])
def detect(device_id: int, db: Session = Depends(get_db)) -> list[AnomalyEvent]:
    return detect_device_anomalies(get_device_or_404(device_id, db), db)

@router.get("/devices/{device_id}/anomalies", response_model=list[AnomalyEventRead])
def anomalies(device_id: int, limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)) -> list[AnomalyEvent]:
    get_device_or_404(device_id, db)
    return list(db.scalars(select(AnomalyEvent).where(AnomalyEvent.device_id == device_id).order_by(AnomalyEvent.detected_at.desc()).limit(limit)))
