import base64
import binascii
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import AlertEvent, AutomationEvent, Device, DeviceAttachment, DeviceNote, DiagnosticJob, MonitorResult
from app.schemas import (
    BatchCheckResponse,
    BulkDeviceIds,
    BulkDeviceUpdateResponse,
    BulkGroupRequest,
    BulkMonitoringRequest,
    ClearDevicesRequest,
    ClearDevicesResponse,
    DeviceCreate,
    DeviceRead,
    DeviceNoteCreate,
    DeviceNoteRead,
    DeviceAttachmentCreate,
    DeviceAttachmentRead,
    DeviceActivityItem,
    DeviceStatistics,
    DeviceUpdate,
    MonitorResultRead,
    StatusEvent,
)
from app.routers.auth import require_admin
from app.services.monitoring_service import check_and_store_device
from app.services.statistics_service import calculate_device_statistics, derive_status_events

router = APIRouter(prefix="/api/devices", tags=["devices"])
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024


def attachment_directory() -> Path:
    directory = Path(get_settings().attachment_directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def validate_attachment(payload: DeviceAttachmentCreate) -> bytes:
    try:
        content = base64.b64decode(payload.content_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="Attachment content is not valid base64") from exc
    if not content or len(content) > MAX_ATTACHMENT_BYTES:
        raise HTTPException(status_code=413, detail="Attachment must be between 1 byte and 5 MiB")
    signatures = {
        "application/pdf": lambda value: value.startswith(b"%PDF-"),
        "image/png": lambda value: value.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": lambda value: value.startswith(b"\xff\xd8\xff"),
    }
    if payload.media_type == "text/plain":
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail="Text attachments must be UTF-8") from exc
        if b"\x00" in content:
            raise HTTPException(status_code=422, detail="Text attachments cannot contain NUL bytes")
    elif not signatures[payload.media_type](content):
        raise HTTPException(status_code=422, detail="Attachment content does not match its declared type")
    return content


def get_device_or_404(device_id: int, db: Session) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


def commit_device(db: Session, device: Device) -> Device:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A device with this IP address already exists") from exc
    db.refresh(device)
    return device


@router.post("", response_model=DeviceRead, status_code=status.HTTP_201_CREATED)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db)) -> Device:
    device = Device(**payload.model_dump(), inventory_source="MANUAL")
    db.add(device)
    return commit_device(db, device)


@router.get("", response_model=list[DeviceRead])
def list_devices(db: Session = Depends(get_db)) -> list[Device]:
    return list(db.scalars(select(Device).order_by(Device.id)))


@router.post(
    "/actions/clear-all",
    response_model=ClearDevicesResponse,
    dependencies=[Depends(require_admin)],
)
def clear_all_devices(payload: ClearDevicesRequest, db: Session = Depends(get_db)) -> ClearDevicesResponse:
    if payload.confirmation != "CLEAR ALL DEVICES":
        raise HTTPException(status_code=400, detail="Type CLEAR ALL DEVICES to confirm")

    devices = list(db.scalars(select(Device).order_by(Device.id)))
    attachments = list(db.scalars(select(DeviceAttachment).order_by(DeviceAttachment.id)))
    attachment_paths = [attachment_directory() / item.storage_name for item in attachments]
    for device in devices:
        db.delete(device)
    db.commit()
    for path in attachment_paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            # The database reset is authoritative. A locked orphaned blob can
            # be removed later without restoring any device data.
            pass
    return ClearDevicesResponse(
        deleted_devices=len(devices),
        deleted_attachments=len(attachments),
    )


@router.post("/check-all", response_model=BatchCheckResponse, status_code=status.HTTP_201_CREATED)
def check_all_devices(db: Session = Depends(get_db)) -> BatchCheckResponse:
    devices = list(
        db.scalars(select(Device).where(Device.is_active.is_(True)).order_by(Device.id))
    )
    results = [check_and_store_device(device, db) for device in devices]
    return BatchCheckResponse(
        checked_devices=len(results),
        online_devices=sum(result.status == "ONLINE" for result in results),
        offline_devices=sum(result.status == "OFFLINE" for result in results),
        results=results,
    )


def get_bulk_devices(device_ids: list[int], db: Session) -> list[Device]:
    devices = list(db.scalars(select(Device).where(Device.id.in_(device_ids))))
    by_id = {device.id: device for device in devices}
    missing = [device_id for device_id in device_ids if device_id not in by_id]
    if missing:
        raise HTTPException(status_code=404, detail=f"Devices not found: {', '.join(map(str, missing))}")
    return [by_id[device_id] for device_id in device_ids]


@router.post("/bulk/check", response_model=BatchCheckResponse, status_code=status.HTTP_201_CREATED)
def check_selected_devices(payload: BulkDeviceIds, db: Session = Depends(get_db)) -> BatchCheckResponse:
    devices = get_bulk_devices(payload.device_ids, db)
    results = [check_and_store_device(device, db) for device in devices]
    return BatchCheckResponse(
        checked_devices=len(results),
        online_devices=sum(result.status == "ONLINE" for result in results),
        offline_devices=sum(result.status == "OFFLINE" for result in results),
        results=results,
    )


@router.put("/bulk/monitoring", response_model=BulkDeviceUpdateResponse)
def update_selected_monitoring(
    payload: BulkMonitoringRequest,
    db: Session = Depends(get_db),
) -> BulkDeviceUpdateResponse:
    devices = get_bulk_devices(payload.device_ids, db)
    enabled = payload.action == "ENABLE"
    for device in devices:
        device.is_active = enabled
    db.commit()
    return BulkDeviceUpdateResponse(updated_devices=len(devices), devices=devices)


@router.put("/bulk/group", response_model=BulkDeviceUpdateResponse)
def update_selected_group(
    payload: BulkGroupRequest,
    db: Session = Depends(get_db),
) -> BulkDeviceUpdateResponse:
    devices = get_bulk_devices(payload.device_ids, db)
    for device in devices:
        device.device_group = payload.device_group
    db.commit()
    return BulkDeviceUpdateResponse(updated_devices=len(devices), devices=devices)


@router.get("/{device_id}", response_model=DeviceRead)
def get_device(device_id: int, db: Session = Depends(get_db)) -> Device:
    return get_device_or_404(device_id, db)


@router.get("/{device_id}/notes", response_model=list[DeviceNoteRead])
def list_device_notes(device_id: int, db: Session = Depends(get_db)) -> list[DeviceNote]:
    get_device_or_404(device_id, db)
    return list(
        db.scalars(
            select(DeviceNote)
            .where(DeviceNote.device_id == device_id)
            .order_by(DeviceNote.created_at.desc(), DeviceNote.id.desc())
        )
    )


@router.post("/{device_id}/notes", response_model=DeviceNoteRead, status_code=status.HTTP_201_CREATED)
def create_device_note(
    device_id: int,
    payload: DeviceNoteCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> DeviceNote:
    get_device_or_404(device_id, db)
    user = getattr(request.state, "user", None)
    note = DeviceNote(
        device_id=device_id,
        author=user.username if user is not None else "local-user",
        body=payload.body,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.delete("/{device_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device_note(
    device_id: int,
    note_id: int,
    db: Session = Depends(get_db),
) -> Response:
    get_device_or_404(device_id, db)
    note = db.get(DeviceNote, note_id)
    if note is None or note.device_id != device_id:
        raise HTTPException(status_code=404, detail="Device note not found")
    db.delete(note)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{device_id}/attachments", response_model=list[DeviceAttachmentRead])
def list_device_attachments(device_id: int, db: Session = Depends(get_db)) -> list[DeviceAttachment]:
    get_device_or_404(device_id, db)
    return list(db.scalars(
        select(DeviceAttachment).where(DeviceAttachment.device_id == device_id)
        .order_by(DeviceAttachment.created_at.desc(), DeviceAttachment.id.desc())
    ))


@router.post("/{device_id}/attachments", response_model=DeviceAttachmentRead, status_code=status.HTTP_201_CREATED)
def create_device_attachment(
    device_id: int,
    payload: DeviceAttachmentCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> DeviceAttachment:
    get_device_or_404(device_id, db)
    content = validate_attachment(payload)
    storage_name = f"{uuid4().hex}.blob"
    destination = attachment_directory() / storage_name
    try:
        with destination.open("xb") as stream:
            stream.write(content)
        user = getattr(request.state, "user", None)
        attachment = DeviceAttachment(
            device_id=device_id,
            original_name=payload.original_name,
            media_type=payload.media_type,
            size_bytes=len(content),
            storage_name=storage_name,
            uploaded_by=user.username if user is not None else "local-user",
        )
        db.add(attachment)
        db.commit()
        db.refresh(attachment)
        return attachment
    except Exception:
        destination.unlink(missing_ok=True)
        raise


@router.get("/{device_id}/attachments/{attachment_id}/download")
def download_device_attachment(
    device_id: int,
    attachment_id: int,
    db: Session = Depends(get_db),
) -> FileResponse:
    get_device_or_404(device_id, db)
    attachment = db.get(DeviceAttachment, attachment_id)
    if attachment is None or attachment.device_id != device_id:
        raise HTTPException(status_code=404, detail="Device attachment not found")
    path = attachment_directory() / attachment.storage_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Attachment file is missing")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=attachment.original_name,
        content_disposition_type="attachment",
    )


@router.delete("/{device_id}/attachments/{attachment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device_attachment(
    device_id: int,
    attachment_id: int,
    db: Session = Depends(get_db),
) -> Response:
    get_device_or_404(device_id, db)
    attachment = db.get(DeviceAttachment, attachment_id)
    if attachment is None or attachment.device_id != device_id:
        raise HTTPException(status_code=404, detail="Device attachment not found")
    path = attachment_directory() / attachment.storage_name
    db.delete(attachment)
    db.commit()
    path.unlink(missing_ok=True)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{device_id}/activity", response_model=list[DeviceActivityItem])
def get_device_activity(
    device_id: int,
    limit: int = Query(default=100, ge=1, le=250),
    db: Session = Depends(get_db),
) -> list[DeviceActivityItem]:
    device = get_device_or_404(device_id, db)
    items: list[DeviceActivityItem] = []
    for note in db.scalars(select(DeviceNote).where(DeviceNote.device_id == device_id)):
        items.append(DeviceActivityItem(
            id=f"note-{note.id}", category="NOTE", title="Technician note",
            description=note.body, timestamp=note.created_at, actor=note.author,
        ))
    for attachment in db.scalars(select(DeviceAttachment).where(DeviceAttachment.device_id == device_id)):
        items.append(DeviceActivityItem(
            id=f"attachment-{attachment.id}", category="ATTACHMENT",
            title=f"Attachment added: {attachment.original_name}",
            description=f"{attachment.media_type} · {attachment.size_bytes} bytes",
            timestamp=attachment.created_at, actor=attachment.uploaded_by,
        ))
    for event in derive_status_events(device_id, db, limit=50):
        items.append(DeviceActivityItem(
            id=f"status-{event.timestamp.isoformat()}", category="STATUS",
            title=f"Status changed to {event.current_status}",
            description=f"Previous status: {event.previous_status}", timestamp=event.timestamp,
            severity="CRITICAL" if event.current_status == "OFFLINE" else "INFO",
        ))
    for result in db.scalars(
        select(MonitorResult).where(MonitorResult.device_id == device_id)
        .order_by(MonitorResult.timestamp.desc(), MonitorResult.id.desc()).limit(25)
    ):
        items.append(DeviceActivityItem(
            id=f"check-{result.id}", category="CHECK", title=f"Reachability check: {result.status}",
            description=(f"Latency {result.latency_ms:g} ms" if result.latency_ms is not None else "No response received"),
            timestamp=result.timestamp, severity="WARNING" if result.status == "OFFLINE" else "INFO",
        ))
    for alert in db.scalars(select(AlertEvent).where(AlertEvent.device_id == device_id)):
        state = "resolved" if alert.resolved_at else ("acknowledged" if alert.acknowledged_at else "opened")
        items.append(DeviceActivityItem(
            id=f"alert-{alert.id}", category="ALERT", title=f"Alert {state}: {alert.alert_type}",
            description=alert.message, timestamp=alert.resolved_at or alert.acknowledged_at or alert.triggered_at,
            severity=alert.severity,
        ))
    for event in db.scalars(select(AutomationEvent).where(AutomationEvent.device_id == device_id)):
        items.append(DeviceActivityItem(
            id=f"change-{event.id}", category="CHANGE", title=event.event_type.replace("_", " ").title(),
            description=event.message, timestamp=event.created_at, severity=event.severity,
        ))
    for job in db.scalars(select(DiagnosticJob).where(DiagnosticJob.device_id == device_id)):
        items.append(DeviceActivityItem(
            id=f"diagnostic-{job.id}", category="DIAGNOSTIC",
            title=f"{job.job_type.replace('_', ' ').title()}: {job.status}",
            description=job.error, timestamp=job.completed_at or job.created_at, actor=job.requested_by,
            severity="WARNING" if job.status == "FAILED" else "INFO",
        ))
    if device.maintenance_until:
        items.append(DeviceActivityItem(
            id=f"maintenance-{device.id}", category="MAINTENANCE", title="Maintenance scheduled",
            description=device.maintenance_reason, timestamp=device.maintenance_until,
        ))
    return sorted(items, key=lambda item: item.timestamp, reverse=True)[:limit]


@router.put("/{device_id}", response_model=DeviceRead)
def update_device(device_id: int, payload: DeviceUpdate, db: Session = Depends(get_db)) -> Device:
    device = get_device_or_404(device_id, db)
    for field, value in payload.model_dump().items():
        setattr(device, field, value)
    device.inventory_source = "MANUAL"
    return commit_device(db, device)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(device_id: int, db: Session = Depends(get_db)) -> Response:
    device = get_device_or_404(device_id, db)
    attachment_paths = [
        attachment_directory() / item.storage_name
        for item in db.scalars(select(DeviceAttachment).where(DeviceAttachment.device_id == device_id))
    ]
    db.delete(device)
    db.commit()
    for path in attachment_paths:
        path.unlink(missing_ok=True)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{device_id}/check", response_model=MonitorResultRead, status_code=status.HTTP_201_CREATED)
def check_device(device_id: int, db: Session = Depends(get_db)):
    device = get_device_or_404(device_id, db)
    return check_and_store_device(device, db)


@router.get("/{device_id}/history", response_model=list[MonitorResultRead])
def get_device_history(
    device_id: int,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> list[MonitorResult]:
    get_device_or_404(device_id, db)
    return list(
        db.scalars(
            select(MonitorResult)
            .where(MonitorResult.device_id == device_id)
            .order_by(MonitorResult.timestamp.desc(), MonitorResult.id.desc())
            .limit(limit)
        )
    )


@router.get("/{device_id}/statistics", response_model=DeviceStatistics)
def get_device_statistics(device_id: int, db: Session = Depends(get_db)):
    get_device_or_404(device_id, db)
    return calculate_device_statistics(device_id, db)


@router.get("/{device_id}/status-events", response_model=list[StatusEvent])
def get_device_status_events(
    device_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    get_device_or_404(device_id, db)
    return derive_status_events(device_id, db, limit)
