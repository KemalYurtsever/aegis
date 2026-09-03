from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import DiscoveryNetwork, DiscoveryResult
from app.services.discovery_service import discover_and_import_devices, get_primary_private_network

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


@router.get("/network", response_model=DiscoveryNetwork)
def get_discovery_network() -> DiscoveryNetwork:
    try:
        return DiscoveryNetwork(**get_primary_private_network().__dict__)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/import", response_model=DiscoveryResult)
def discover_and_import(db: Session = Depends(get_db)) -> DiscoveryResult:
    try:
        return discover_and_import_devices(db)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
