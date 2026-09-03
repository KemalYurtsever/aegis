from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import HostMetric
from app.routers.devices import get_device_or_404
from app.schemas import HostMetricRead
from app.services.host_metrics_service import collect_and_store_host_metrics, is_local_device

router = APIRouter(prefix="/api", tags=["host metrics"])


@router.post("/devices/{device_id}/metrics/collect", response_model=HostMetricRead, status_code=201)
def collect_host_metrics(device_id: int, db: Session = Depends(get_db)):
    device = get_device_or_404(device_id, db)
    if not is_local_device(device):
        raise HTTPException(status_code=400, detail="Built-in collection supports only loopback devices")
    return collect_and_store_host_metrics(device, db)


@router.get("/devices/{device_id}/metrics", response_model=list[HostMetricRead])
def get_host_metrics(device_id: int, limit: int = Query(default=100, ge=1, le=1000), db: Session = Depends(get_db)):
    get_device_or_404(device_id, db)
    return list(db.scalars(select(HostMetric).where(HostMetric.device_id == device_id).order_by(HostMetric.timestamp.desc(), HostMetric.id.desc()).limit(limit)))
