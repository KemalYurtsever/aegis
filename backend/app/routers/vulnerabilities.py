from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.database import get_db
from app.models import VulnerabilityScan
from app.routers.devices import get_device_or_404
from app.routers.auth import require_admin
from app.schemas import AttackSurfaceComparison, VulnerabilityScanRead
from app.services.vulnerability_service import compare_attack_surface, run_vulnerability_scan

router = APIRouter(
    prefix="/api/devices/{device_id}/vulnerability-scans",
    tags=["vulnerability scanning"],
)

@router.post(
    "",
    response_model=VulnerabilityScanRead,
    status_code=201,
    dependencies=[Depends(require_admin)],
)
def create_scan(device_id: int, db: Session = Depends(get_db)) -> VulnerabilityScan:
    device = get_device_or_404(device_id, db)
    try: return run_vulnerability_scan(device, db)
    except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.get("", response_model=list[VulnerabilityScanRead])
def list_scans(device_id: int, limit: int = Query(default=10, ge=1, le=100), db: Session = Depends(get_db)) -> list[VulnerabilityScan]:
    get_device_or_404(device_id, db)
    return list(db.scalars(select(VulnerabilityScan).options(selectinload(VulnerabilityScan.findings)).where(VulnerabilityScan.device_id == device_id).order_by(VulnerabilityScan.started_at.desc()).limit(limit)))


@router.get("/comparison", response_model=AttackSurfaceComparison)
def compare_scans(device_id: int, db: Session = Depends(get_db)) -> AttackSurfaceComparison:
    get_device_or_404(device_id, db)
    return compare_attack_surface(device_id, db)
