from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import AlertEvent, AlertRule, Device, utc_now
from app.routers.devices import get_device_or_404
from app.schemas import (
    AlertAcknowledgementSummary,
    AlertEventRead,
    AlertRuleRead,
    AlertRuleUpdate,
)
from app.services.alert_service import get_or_create_rule

router = APIRouter(prefix="/api", tags=["alerts"])


def serialize_alert(alert: AlertEvent) -> AlertEventRead:
    return AlertEventRead(
        id=alert.id,
        device_id=alert.device_id,
        device_name=alert.device.name,
        alert_type=alert.alert_type,
        severity=alert.severity,
        message=alert.message,
        triggered_at=alert.triggered_at,
        resolved_at=alert.resolved_at,
        acknowledged_at=alert.acknowledged_at,
    )


@router.get("/devices/{device_id}/alert-rule", response_model=AlertRuleRead)
def get_alert_rule(device_id: int, db: Session = Depends(get_db)) -> AlertRule:
    get_device_or_404(device_id, db)
    rule = get_or_create_rule(device_id, db)
    db.commit()
    db.refresh(rule)
    return rule


@router.put("/devices/{device_id}/alert-rule", response_model=AlertRuleRead)
def update_alert_rule(
    device_id: int, payload: AlertRuleUpdate, db: Session = Depends(get_db)
) -> AlertRule:
    get_device_or_404(device_id, db)
    rule = get_or_create_rule(device_id, db)
    for field, value in payload.model_dump().items():
        setattr(rule, field, value)
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/alerts", response_model=list[AlertEventRead])
def list_alerts(
    active_only: bool = True,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[AlertEventRead]:
    statement = (
        select(AlertEvent)
        .options(joinedload(AlertEvent.device))
        .order_by(AlertEvent.triggered_at.desc(), AlertEvent.id.desc())
    )
    if active_only:
        statement = statement.where(AlertEvent.resolved_at.is_(None))
    return [serialize_alert(alert) for alert in db.scalars(statement.limit(limit))]


@router.post("/alerts/acknowledge-all", response_model=AlertAcknowledgementSummary)
def acknowledge_all_alerts(db: Session = Depends(get_db)) -> AlertAcknowledgementSummary:
    alerts = list(
        db.scalars(
            select(AlertEvent).where(
                AlertEvent.resolved_at.is_(None),
                AlertEvent.acknowledged_at.is_(None),
            )
        )
    )
    acknowledged_at = utc_now()
    for alert in alerts:
        alert.acknowledged_at = acknowledged_at
    if alerts:
        db.commit()
    return AlertAcknowledgementSummary(acknowledged_count=len(alerts))


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertEventRead)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertEventRead:
    alert = db.get(AlertEvent, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.acknowledged_at is None:
        alert.acknowledged_at = utc_now()
        db.commit()
        db.refresh(alert)
    return serialize_alert(alert)
