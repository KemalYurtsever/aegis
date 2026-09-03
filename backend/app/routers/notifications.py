from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import NotificationChannel, NotificationDelivery
from app.routers.auth import require_admin
from app.schemas import NotificationChannelRead, NotificationChannelUpdate, NotificationDeliveryRead
from app.services.notification_service import create_test_delivery, dispatch_delivery, get_or_create_channel, secret_configured

router = APIRouter(prefix="/api/notifications", tags=["notifications"], dependencies=[Depends(require_admin)])


def serialize_channel(channel: NotificationChannel) -> NotificationChannelRead:
    return NotificationChannelRead(**{key: getattr(channel, key) for key in (
        "id", "channel_type", "enabled", "smtp_host", "smtp_port", "smtp_username", "email_from", "email_to", "sms_from", "sms_to", "use_tls", "updated_at"
    )}, secret_configured=secret_configured(channel.channel_type))


@router.get("/channels", response_model=list[NotificationChannelRead])
def list_channels(db: Session = Depends(get_db)) -> list[NotificationChannelRead]:
    channels = [get_or_create_channel(kind, db) for kind in ("EMAIL", "TEAMS", "SMS")]
    db.commit()
    return [serialize_channel(channel) for channel in channels]


@router.put("/channels/{channel_type}", response_model=NotificationChannelRead)
def update_channel(channel_type: str, payload: NotificationChannelUpdate, db: Session = Depends(get_db)) -> NotificationChannelRead:
    channel_type = channel_type.upper()
    if channel_type not in {"EMAIL", "TEAMS", "SMS"}:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    channel = get_or_create_channel(channel_type, db)
    for field, value in payload.model_dump().items():
        setattr(channel, field, value.strip() or None if isinstance(value, str) else value)
    db.commit(); db.refresh(channel)
    return serialize_channel(channel)


@router.post("/channels/{channel_type}/test", response_model=NotificationDeliveryRead)
def test_channel(channel_type: str, db: Session = Depends(get_db)) -> NotificationDelivery:
    channel_type = channel_type.upper()
    if channel_type not in {"EMAIL", "TEAMS", "SMS"}:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    get_or_create_channel(channel_type, db); db.commit()
    return dispatch_delivery(create_test_delivery(channel_type, db), db)


@router.get("/deliveries", response_model=list[NotificationDeliveryRead])
def list_deliveries(db: Session = Depends(get_db)) -> list[NotificationDelivery]:
    return list(db.scalars(select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(200)))


@router.post("/deliveries/{delivery_id}/retry", response_model=NotificationDeliveryRead)
def retry_delivery(delivery_id: int, db: Session = Depends(get_db)) -> NotificationDelivery:
    delivery = db.get(NotificationDelivery, delivery_id)
    if delivery is None:
        raise HTTPException(status_code=404, detail="Notification delivery not found")
    return dispatch_delivery(delivery, db)
