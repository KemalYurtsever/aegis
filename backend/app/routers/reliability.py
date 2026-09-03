from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.routers.auth import require_admin
from app.schemas import BackupRead, BackupStatus, BackupVerification, RetentionApplyRequest, RetentionPreview
from app.services.backup_service import BackupService
from app.services.retention_service import apply_retention, preview_retention


router = APIRouter(prefix="/api", tags=["reliability"], dependencies=[Depends(require_admin)])


def backup_service(request: Request) -> BackupService:
    return request.app.state.backup_service


@router.get("/backups", response_model=list[BackupRead])
def list_backups(request: Request) -> list[BackupRead]:
    return backup_service(request).list_backups()


@router.get("/backups/status", response_model=BackupStatus)
def backup_status(request: Request) -> BackupStatus:
    scheduler = request.app.state.backup_scheduler
    return BackupStatus(
        enabled=scheduler.enabled,
        running=scheduler.is_running,
        interval_hours=scheduler.interval_hours,
        keep_count=scheduler.service.keep_count,
        history_retention_days=get_settings().history_retention_days,
    )


@router.post("/backups", response_model=BackupVerification, status_code=201)
def create_backup(request: Request) -> BackupVerification:
    try:
        return backup_service(request).create_backup()
    except (FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/backups/{filename}/verify", response_model=BackupVerification)
def verify_backup(filename: str, request: Request) -> BackupVerification:
    try:
        return backup_service(request).verify_backup(filename)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Backup not found") from exc


@router.get("/backups/{filename}/download")
def download_backup(filename: str, request: Request) -> FileResponse:
    try:
        path = backup_service(request).download_path(filename)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Backup not found") from exc
    return FileResponse(path, media_type="application/vnd.sqlite3", filename=path.name)


@router.get("/retention/preview", response_model=RetentionPreview)
def retention_preview(
    days: int | None = Query(default=None, ge=7, le=3650),
    db: Session = Depends(get_db),
) -> RetentionPreview:
    return preview_retention(days or get_settings().history_retention_days, db)


@router.post("/retention/apply", response_model=RetentionPreview)
def retention_apply(
    payload: RetentionApplyRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> RetentionPreview:
    try:
        backup_service(request).create_backup()
    except (FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=f"Cleanup cancelled because the safety backup failed: {exc}") from exc
    return apply_retention(payload.retention_days, db)
