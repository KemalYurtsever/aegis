from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import AvailabilityReport
from app.services.report_service import build_availability_report


router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/availability", response_model=AvailabilityReport)
def availability_report(
    days: int = Query(default=30, ge=7, le=365),
    db: Session = Depends(get_db),
) -> AvailabilityReport:
    return build_availability_report(days, db)
