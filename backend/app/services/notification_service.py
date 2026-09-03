import json
import os
import smtplib
import base64
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AlertEvent, AutomationSettings, NotificationChannel, NotificationDelivery, utc_now

MAX_ATTEMPTS = 3


def notification_window_open(db: Session, now: datetime | None = None) -> bool:
    settings = db.get(AutomationSettings, 1)
    if settings is None or not settings.notification_window_enabled:
        return True
    hour = (now or datetime.now()).hour
    start, end = settings.notification_start_hour, settings.notification_end_hour
    if start == end:
        return True
    return start <= hour < end if start < end else hour >= start or hour < end


def get_or_create_channel(channel_type: str, db: Session) -> NotificationChannel:
    channel = db.scalar(select(NotificationChannel).where(NotificationChannel.channel_type == channel_type))
    if channel is None:
        channel = NotificationChannel(channel_type=channel_type)
        db.add(channel)
        db.flush()
    return channel


def secret_configured(channel_type: str) -> bool:
    variables = {"EMAIL": ("LIIMS_SMTP_PASSWORD",), "TEAMS": ("LIIMS_TEAMS_WEBHOOK_URL",), "SMS": ("LIIMS_TWILIO_ACCOUNT_SID", "LIIMS_TWILIO_AUTH_TOKEN")}
    return all(os.getenv(variable, "").strip() for variable in variables[channel_type])


def queue_alert_notifications(alert: AlertEvent, db: Session) -> list[NotificationDelivery]:
    queued = []
    for channel in db.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True))):
        exists = db.scalar(select(NotificationDelivery).where(
            NotificationDelivery.alert_event_id == alert.id,
            NotificationDelivery.channel_type == channel.channel_type,
        ))
        if exists is None:
            delivery = NotificationDelivery(
                alert_event_id=alert.id,
                channel_type=channel.channel_type,
                subject=f"LIIMS {alert.severity}: {alert.device.name}",
                message=f"{alert.message}\nDevice: {alert.device.name} ({alert.device.ip_address})\nTriggered: {alert.triggered_at.isoformat()}",
            )
            db.add(delivery)
            queued.append(delivery)
    return queued


def create_test_delivery(channel_type: str, db: Session) -> NotificationDelivery:
    delivery = NotificationDelivery(
        channel_type=channel_type,
        subject="LIIMS notification test",
        message="This is a test notification from your LIIMS dashboard.",
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    return delivery


def _send_email(channel: NotificationChannel, delivery: NotificationDelivery) -> None:
    password = os.getenv("LIIMS_SMTP_PASSWORD", "")
    if not all([channel.smtp_host, channel.smtp_port, channel.email_from, channel.email_to, password]):
        raise RuntimeError("Email settings or LIIMS_SMTP_PASSWORD are incomplete")
    message = EmailMessage()
    message["Subject"] = delivery.subject
    message["From"] = channel.email_from
    message["To"] = channel.email_to
    message.set_content(delivery.message)
    with smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=10) as smtp:
        if channel.use_tls:
            smtp.starttls()
        if channel.smtp_username:
            smtp.login(channel.smtp_username, password)
        smtp.send_message(message)


def _send_teams(delivery: NotificationDelivery) -> None:
    webhook = os.getenv("LIIMS_TEAMS_WEBHOOK_URL", "").strip()
    if not webhook:
        raise RuntimeError("LIIMS_TEAMS_WEBHOOK_URL is not configured")
    payload = json.dumps({"text": f"**{delivery.subject}**\n\n{delivery.message}"}).encode()
    request = Request(webhook, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=10) as response:
        if response.status >= 300:
            raise RuntimeError(f"Teams webhook returned HTTP {response.status}")


def _send_sms(channel: NotificationChannel, delivery: NotificationDelivery) -> None:
    sid = os.getenv("LIIMS_TWILIO_ACCOUNT_SID", "").strip()
    token = os.getenv("LIIMS_TWILIO_AUTH_TOKEN", "").strip()
    if not all([sid, token, channel.sms_from, channel.sms_to]):
        raise RuntimeError("SMS settings or Twilio environment credentials are incomplete")
    authorization = base64.b64encode(f"{sid}:{token}".encode()).decode()
    endpoint = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    for recipient in [item.strip() for item in channel.sms_to.split(",") if item.strip()]:
        body = urlencode({"From": channel.sms_from, "To": recipient, "Body": f"{delivery.subject}: {delivery.message}"[:1500]}).encode()
        request = Request(endpoint, data=body, headers={"Authorization": f"Basic {authorization}", "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        with urlopen(request, timeout=10) as response:
            if response.status >= 300:
                raise RuntimeError(f"SMS provider returned HTTP {response.status}")


def dispatch_delivery(delivery: NotificationDelivery, db: Session) -> NotificationDelivery:
    if delivery.status == "SENT" or delivery.attempt_count >= MAX_ATTEMPTS:
        return delivery
    channel = get_or_create_channel(delivery.channel_type, db)
    delivery.attempt_count += 1
    delivery.last_attempt_at = utc_now()
    try:
        if delivery.channel_type == "EMAIL":
            _send_email(channel, delivery)
        elif delivery.channel_type == "TEAMS":
            _send_teams(delivery)
        else:
            _send_sms(channel, delivery)
        delivery.status = "SENT"
        delivery.sent_at = utc_now()
        delivery.last_error = None
    except Exception as exc:
        delivery.status = "FAILED"
        delivery.last_error = str(exc)[:500]
    db.commit()
    db.refresh(delivery)
    return delivery


def dispatch_pending(db: Session, limit: int = 20) -> int:
    if not notification_window_open(db):
        return 0
    deliveries = list(db.scalars(select(NotificationDelivery).where(
        NotificationDelivery.status.in_(["PENDING", "FAILED"]),
        NotificationDelivery.attempt_count < MAX_ATTEMPTS,
    ).order_by(NotificationDelivery.created_at).limit(limit)))
    for delivery in deliveries:
        dispatch_delivery(delivery, db)
    return len(deliveries)
