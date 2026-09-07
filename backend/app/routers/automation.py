import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    AssetBaseline,
    AutomationEvent,
    AutomationSettings,
    GeneratedReport,
    Incident,
    MaintenanceWindow,
    utc_now,
)
from app.routers.auth import require_admin
from app.schemas import (
    AssetBaselineRead,
    AutomationEventRead,
    AutomationOverview,
    AutomationSettingsRead,
    AutomationSettingsUpdate,
    AutomationSummary,
    GeneratedReportRead,
    IncidentRead,
    IncidentUpdate,
    MaintenanceWindowCreate,
    MaintenanceWindowRead,
    MaintenanceWindowUpdate,
)
from app.services.automation_service import (
    automation_overview,
    generate_scheduled_report,
    get_automation_settings,
    local_summary,
    refresh_asset_baselines,
    report_path,
    run_automation_cycle,
    window_is_active,
)


router = APIRouter(
    prefix="/api/automation",
    tags=["automation"],
    dependencies=[Depends(require_admin)],
)


def _incident_read(incident: Incident) -> IncidentRead:
    return IncidentRead(
        id=incident.id,
        correlation_key=incident.correlation_key,
        title=incident.title,
        summary=incident.summary,
        severity=incident.severity,
        status=incident.status,
        alert_ids=json.loads(incident.alert_ids_json),
        assigned_to=incident.assigned_to,
        operator_note=incident.operator_note,
        opened_at=incident.opened_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
    )


def _baseline_read(baseline: AssetBaseline) -> AssetBaselineRead:
    return AssetBaselineRead(
        id=baseline.id,
        device_id=baseline.device_id,
        signature=baseline.signature,
        snapshot=json.loads(baseline.snapshot_json),
        updated_at=baseline.updated_at,
    )


def _event_read(event: AutomationEvent) -> AutomationEventRead:
    return AutomationEventRead(
        id=event.id,
        device_id=event.device_id,
        event_type=event.event_type,
        severity=event.severity,
        message=event.message,
        details=json.loads(event.details_json),
        created_at=event.created_at,
    )


@router.get("/overview", response_model=AutomationOverview)
def get_overview(db: Session = Depends(get_db)) -> AutomationOverview:
    return automation_overview(db)


@router.put("/settings", response_model=AutomationSettingsRead)
def update_settings(
    payload: AutomationSettingsUpdate,
    db: Session = Depends(get_db),
) -> AutomationSettings:
    settings = get_automation_settings(db)
    for name, value in payload.model_dump().items():
        setattr(settings, name, value)
    db.commit()
    db.refresh(settings)
    return settings


@router.post("/run")
def run_now(db: Session = Depends(get_db)) -> dict[str, int]:
    return run_automation_cycle(db)


@router.get("/maintenance-windows", response_model=list[MaintenanceWindowRead])
def list_maintenance_windows(db: Session = Depends(get_db)) -> list[MaintenanceWindowRead]:
    windows = db.scalars(select(MaintenanceWindow).order_by(MaintenanceWindow.starts_at.desc()))
    return [
        MaintenanceWindowRead.model_validate(window).model_copy(update={"active_now": window_is_active(window)})
        for window in windows
    ]


@router.post("/maintenance-windows", response_model=MaintenanceWindowRead, status_code=201)
def create_maintenance_window(
    payload: MaintenanceWindowCreate,
    db: Session = Depends(get_db),
) -> MaintenanceWindowRead:
    if payload.ends_at <= payload.starts_at:
        raise HTTPException(status_code=422, detail="Maintenance must end after it starts")
    window = MaintenanceWindow(**payload.model_dump())
    db.add(window)
    db.commit()
    db.refresh(window)
    return MaintenanceWindowRead.model_validate(window).model_copy(update={"active_now": window_is_active(window)})


@router.patch("/maintenance-windows/{window_id}", response_model=MaintenanceWindowRead)
def update_maintenance_window(
    window_id: int,
    payload: MaintenanceWindowUpdate,
    db: Session = Depends(get_db),
) -> MaintenanceWindowRead:
    window = db.get(MaintenanceWindow, window_id)
    if window is None:
        raise HTTPException(status_code=404, detail="Maintenance window not found")
    window.enabled = payload.enabled
    db.commit()
    db.refresh(window)
    return MaintenanceWindowRead.model_validate(window).model_copy(
        update={"active_now": window_is_active(window)}
    )


@router.delete("/maintenance-windows/{window_id}", status_code=204)
def delete_maintenance_window(window_id: int, db: Session = Depends(get_db)) -> None:
    window = db.get(MaintenanceWindow, window_id)
    if window is None:
        raise HTTPException(status_code=404, detail="Maintenance window not found")
    db.delete(window)
    db.commit()


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(
    status: str | None = Query(default=None, pattern="^(OPEN|RESOLVED)$"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[IncidentRead]:
    statement = select(Incident)
    if status:
        statement = statement.where(Incident.status == status)
    incidents = db.scalars(statement.order_by(Incident.opened_at.desc()).limit(limit))
    return [_incident_read(incident) for incident in incidents]


@router.patch("/incidents/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
) -> IncidentRead:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
    incident.updated_at = utc_now()
    db.commit()
    db.refresh(incident)
    return _incident_read(incident)


@router.post("/incidents/{incident_id}/resolve", response_model=IncidentRead)
def resolve_incident(incident_id: int, db: Session = Depends(get_db)) -> IncidentRead:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = "RESOLVED"
    incident.resolved_at = utc_now()
    incident.updated_at = incident.resolved_at
    db.commit()
    db.refresh(incident)
    return _incident_read(incident)


@router.get("/reports", response_model=list[GeneratedReportRead])
def list_generated_reports(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[GeneratedReport]:
    return list(db.scalars(select(GeneratedReport).order_by(
        GeneratedReport.generated_at.desc()
    ).limit(limit)))


@router.post("/reports/generate", response_model=GeneratedReportRead, status_code=201)
def generate_report(db: Session = Depends(get_db)) -> GeneratedReport:
    report = generate_scheduled_report(db, force=True)
    if report is None:
        raise HTTPException(status_code=500, detail="Report generation failed")
    db.commit()
    db.refresh(report)
    return report


@router.get("/reports/{filename}/download")
def download_report(filename: str) -> FileResponse:
    try:
        path = report_path(filename)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Report not found") from exc
    return FileResponse(path, media_type="application/json", filename=path.name)


@router.get("/baselines", response_model=list[AssetBaselineRead])
def list_baselines(db: Session = Depends(get_db)) -> list[AssetBaselineRead]:
    return [_baseline_read(item) for item in db.scalars(select(AssetBaseline).order_by(AssetBaseline.device_id))]


@router.post("/baselines/refresh")
def refresh_baselines(db: Session = Depends(get_db)) -> dict[str, int]:
    changes = refresh_asset_baselines(db)
    db.commit()
    return {"changes": changes}


@router.get("/events", response_model=list[AutomationEventRead])
def list_events(
    limit: int = Query(default=100, ge=1, le=500),
    device_id: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
) -> list[AutomationEventRead]:
    statement = select(AutomationEvent)
    if device_id is not None:
        statement = statement.where(AutomationEvent.device_id == device_id)
    events = db.scalars(statement.order_by(AutomationEvent.created_at.desc()).limit(limit))
    return [_event_read(event) for event in events]


@router.post("/summary", response_model=AutomationSummary)
def summarize(db: Session = Depends(get_db)) -> AutomationSummary:
    return local_summary(db)
