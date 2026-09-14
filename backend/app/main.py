import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import get_settings
from app.database import Base, SessionLocal, engine, ensure_performance_indexes, get_db, migrate_agent_monitoring_columns, migrate_automation_columns, migrate_device_inventory_columns, migrate_diagnostic_job_types, migrate_notification_tables, migrate_security_playbook_columns, migrate_vulnerability_columns
from app.models import AuditEvent
from app.routers.alerts import router as alerts_router
from app.routers.dashboard import build_dashboard, router as dashboard_router
from app.routers.discovery import router as discovery_router
from app.routers.services import get_service_overview, router as services_router
from app.routers.metrics import router as metrics_router
from app.routers.agents import get_agent_overview, ingest_router as agent_ingest_router, router as agents_router
from app.routers.auth import router as auth_router
from app.routers.devices import router as devices_router
from app.routers.notifications import router as notifications_router
from app.routers.snmp import router as snmp_router
from app.routers.prometheus import router as prometheus_router
from app.routers.vulnerabilities import router as vulnerabilities_router
from app.routers.advanced_monitoring import router as advanced_monitoring_router
from app.routers.inventory import build_inventory_health, router as inventory_router
from app.routers.reliability import router as reliability_router
from app.routers.reports import router as reports_router
from app.routers.topology import build_topology, cached_connected_network, router as topology_router
from app.routers.diagnostics import ingest_router as diagnostic_ingest_router, router as diagnostics_router
from app.routers.automation import router as automation_router
from app.routers.system import router as system_router
from app.routers.security import router as security_router
from app.scheduler import PeriodicMonitor
from app.schemas import HealthResponse, SchedulerStatus
from app.services.auth_service import session_user
from app.security import InMemoryRateLimiter, RequestBodyLimitMiddleware, rate_limit_for, request_identity
from app.services.backup_service import BackupService, PeriodicBackup
from app.services.security_playbook_service import SecurityPlaybookRunner
from app.services.statistics_service import load_device_monitor_snapshot


@asynccontextmanager
async def lifespan(application: FastAPI):
    migrate_notification_tables(engine)
    migrate_device_inventory_columns(engine)
    Base.metadata.create_all(bind=engine)
    migrate_vulnerability_columns(engine)
    migrate_security_playbook_columns(engine)
    migrate_agent_monitoring_columns(engine)
    migrate_diagnostic_job_types(engine)
    migrate_automation_columns(engine)
    ensure_performance_indexes(engine)
    settings = get_settings()
    session_factory = getattr(application.state, "session_factory", SessionLocal)
    application.state.session_factory = session_factory
    application.state.auth_required = getattr(application.state, "auth_required", True)
    # A fresh limiter per application lifespan prevents stale counters after a
    # development reload and keeps test/application instances isolated.
    application.state.rate_limiter = InMemoryRateLimiter()
    playbook_runner = SecurityPlaybookRunner(session_factory)
    application.state.playbook_runner = playbook_runner
    playbook_runner.start()
    scheduler_enabled = getattr(application.state, "scheduler_enabled", settings.scheduler_enabled)
    scheduler = PeriodicMonitor(
        session_factory,
        interval_seconds=settings.monitor_interval_seconds,
        enabled=scheduler_enabled,
    )
    application.state.monitor_scheduler = scheduler
    scheduler.start()
    backup_service = getattr(
        application.state,
        "backup_service",
        BackupService(settings.database_url, settings.backup_directory, settings.backup_keep_count),
    )
    backup_enabled = getattr(application.state, "backup_enabled", settings.backup_enabled)
    backup_scheduler = PeriodicBackup(backup_service, settings.backup_interval_hours, enabled=backup_enabled)
    application.state.backup_service = backup_service
    application.state.backup_scheduler = backup_scheduler
    backup_scheduler.start()
    try:
        yield
    finally:
        await backup_scheduler.stop()
        await scheduler.stop()
        await asyncio.to_thread(playbook_runner.shutdown)


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_size=1_048_576,
    path_limits={r"/api/devices/\d+/attachments": 7_200_000},
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5174",
        "http://localhost:5174",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
_AUTH_PUBLIC_PATHS = {
    "/api/health", "/api/auth/status", "/api/auth/setup", "/api/auth/login", "/api/agent/metrics",
    "/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc", "/metrics",
}
_AUTH_PUBLIC_PREFIXES = ("/api/agent/",)


@app.middleware("http")
async def authenticate_request(request: Request, call_next):
    if request.url.path.startswith("/api/") or request.url.path == "/metrics":
        bucket, limit = rate_limit_for(request)
        retry_after = request.app.state.rate_limiter.check(bucket, request_identity(request), limit)
        if retry_after is not None:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests; try again later"},
                headers={"Retry-After": str(retry_after)},
            )
    if (
        not request.app.state.auth_required
        or request.method == "OPTIONS"
        or request.url.path in _AUTH_PUBLIC_PATHS
        or request.url.path.startswith(_AUTH_PUBLIC_PREFIXES)
    ):
        response = await call_next(request)
        return add_security_headers(request, response)
    authorization = request.headers.get("Authorization", "")
    token = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
    with request.app.state.session_factory() as db:
        user = session_user(token, db) if token else None
        if user is None:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        request.state.user = user
        if user.role == "VIEWER" and request.method not in {"GET", "HEAD"} and request.url.path != "/api/auth/logout":
            return JSONResponse(status_code=403, content={"detail": "Viewer role is read-only"})
        response = await call_next(request)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            db.add(AuditEvent(
                user_id=user.id,
                username=user.username,
                role=user.role,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                client_ip=request.client.host if request.client else None,
            ))
            db.commit()
    return add_security_headers(request, response)


def add_security_headers(request: Request, response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/") or request.url.path == "/metrics":
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(dashboard_router)
app.include_router(alerts_router)
app.include_router(discovery_router)
app.include_router(services_router)
app.include_router(metrics_router)
app.include_router(agents_router)
app.include_router(agent_ingest_router)
app.include_router(notifications_router)
app.include_router(snmp_router)
app.include_router(prometheus_router)
app.include_router(vulnerabilities_router)
app.include_router(advanced_monitoring_router)
app.include_router(inventory_router)
app.include_router(reliability_router)
app.include_router(reports_router)
app.include_router(topology_router)
app.include_router(diagnostics_router)
app.include_router(diagnostic_ingest_router)
app.include_router(automation_router)
app.include_router(system_router)
app.include_router(security_router)


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health_check() -> HealthResponse:
    return HealthResponse(status="healthy", application=settings.app_name)


def scheduler_response(scheduler: PeriodicMonitor) -> SchedulerStatus:
    return SchedulerStatus(
        enabled=scheduler.enabled,
        running=scheduler.is_running,
        interval_seconds=scheduler.interval_seconds,
    )


@app.get("/api/scheduler/status", response_model=SchedulerStatus, tags=["system"])
def scheduler_status(request: Request) -> SchedulerStatus:
    return scheduler_response(request.app.state.monitor_scheduler)


@app.get("/api/dashboard/refresh", tags=["dashboard"])
def dashboard_refresh(request: Request, db=Depends(get_db)):
    """Return the dashboard's periodic data as one authenticated response."""
    device_result_rows = load_device_monitor_snapshot(db)
    return {
        "dashboard": build_dashboard(db, device_result_rows),
        "scheduler": scheduler_response(request.app.state.monitor_scheduler),
        "inventory_health": build_inventory_health(24, db, device_result_rows),
        "topology": build_topology(db, cached_connected_network(), device_result_rows),
        "agent_overview": get_agent_overview(db),
        "service_overview": get_service_overview(db),
    }


@app.post("/api/scheduler/pause", response_model=SchedulerStatus, tags=["system"])
async def pause_scheduler(request: Request) -> SchedulerStatus:
    scheduler: PeriodicMonitor = request.app.state.monitor_scheduler
    await scheduler.stop()
    return scheduler_response(scheduler)


@app.post("/api/scheduler/resume", response_model=SchedulerStatus, tags=["system"])
async def resume_scheduler(request: Request) -> SchedulerStatus:
    scheduler: PeriodicMonitor = request.app.state.monitor_scheduler
    if not scheduler.enabled:
        raise HTTPException(status_code=409, detail="Automatic monitoring is disabled by server configuration")
    scheduler.start()
    return scheduler_response(scheduler)
