from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.database import Base, engine, migrate_agent_monitoring_columns, migrate_device_inventory_columns, migrate_notification_tables
from app.routers.agents import ingest_router
from app.routers.diagnostics import ingest_router as diagnostic_ingest_router
from app.security import InMemoryRateLimiter, RateLimit, RequestBodyLimitMiddleware, request_identity


@asynccontextmanager
async def lifespan(_application: FastAPI):
    migrate_notification_tables(engine)
    migrate_device_inventory_columns(engine)
    Base.metadata.create_all(bind=engine)
    migrate_agent_monitoring_columns(engine)
    yield


app = FastAPI(
    title="AEGIS Agent Ingress",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.state.rate_limiter = InMemoryRateLimiter()
app.add_middleware(RequestBodyLimitMiddleware, max_body_size=65_536)


@app.middleware("http")
async def protect_agent_ingress(request: Request, call_next):
    allowed = request.url.path in {"/api/agent/health", "/api/agent/metrics", "/api/agent/jobs/next"}
    allowed = allowed or (
        request.method == "POST"
        and request.url.path.startswith("/api/agent/jobs/")
        and request.url.path.endswith("/result")
    )
    if not allowed:
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    retry_after = request.app.state.rate_limiter.check(
        "agent-ingress", request_identity(request), RateLimit(120, 60)
    )
    if retry_after is not None:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many agent requests; try again later"},
            headers={"Retry-After": str(retry_after)},
        )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/agent/health", tags=["agent ingestion"])
def agent_health() -> dict[str, str]:
    return {"status": "healthy", "service": "AEGIS agent ingress"}


app.include_router(ingest_router)
app.include_router(diagnostic_ingest_router)
