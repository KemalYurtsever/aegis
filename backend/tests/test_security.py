from app.security import InMemoryRateLimiter, RateLimit
import pytest
from starlette.requests import Request
from app.security import rate_limit_for, request_identity


def test_idle_rate_limit_identities_are_reclaimed():
    now = [0.0]
    limiter = InMemoryRateLimiter(max_keys=2, cleanup_interval=1, clock=lambda: now[0])
    limit = RateLimit(1, 5)
    assert limiter.check("test", "old", limit) is None
    now[0] = 6.0
    assert limiter.check("test", "new", limit) is None
    assert len(limiter._events) == 1


def test_capacity_does_not_evict_active_limits_or_create_new_keys():
    now = [0.0]
    limiter = InMemoryRateLimiter(max_keys=2, clock=lambda: now[0])
    limit = RateLimit(1, 60)
    assert limiter.check("test", "first", limit) is None
    assert limiter.check("test", "second", limit) is None
    for index in range(100):
        assert limiter.check("test", f"extra-{index}", limit) >= 1
    assert len(limiter._events) == 2
    assert limiter.check("test", "first", limit) >= 1
    now[0] = 61.0
    assert limiter.check("test", "extra", limit) is None
    assert len(limiter._events) == 1


def test_concurrent_rate_limit_enforcement_is_atomic():
    from concurrent.futures import ThreadPoolExecutor
    limiter = InMemoryRateLimiter()
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _i: limiter.check("test", "shared", RateLimit(5, 60)), range(100)))
    assert outcomes.count(None) == 5
    assert len(limiter._events[("test", "shared")]) == 5


def test_capacity_allows_existing_non_exhausted_identities():
    limiter = InMemoryRateLimiter(max_keys=1)
    limit = RateLimit(2, 60)
    assert limiter.check("test", "known", limit) is None
    assert limiter.check("test", "new", limit) >= 1
    assert limiter.check("test", "known", limit) is None


def test_forwarded_header_does_not_control_rate_limit_identity():
    request = Request({"type": "http", "method": "GET", "path": "/api/health",
                       "headers": [(b"x-forwarded-for", b"198.18.0.1")], "client": ("127.0.0.1", 1)})
    assert request_identity(request) == "127.0.0.1"


@pytest.mark.parametrize("path,method", [("/api/system/mac/adapters", "GET"),
                                         ("/api/system/mac/plan", "POST"),
                                         ("/api/system/mac/apply", "POST")])
def test_host_mac_operations_have_bounded_request_budget(path, method):
    request = Request({"type": "http", "method": method, "path": path, "headers": [], "scheme": "http"})
    _bucket, limit = rate_limit_for(request)
    assert limit.requests <= 20


@pytest.mark.parametrize("status", [401, 403, 429])
def test_authentication_errors_have_security_and_cors_headers(client, admin_headers, status):
    origin = {"Origin": "http://127.0.0.1:5173"}
    if status == 401:
        response = client.get("/api/devices", headers=origin)
    elif status == 403:
        client.post("/api/auth/users", headers=admin_headers, json={
            "username": "header-viewer", "password": "synthetic-viewer-password", "role": "VIEWER",
        })
        token = client.post("/api/auth/login", json={
            "username": "header-viewer", "password": "synthetic-viewer-password",
        }).json()["token"]
        response = client.post("/api/scheduler/pause", headers={**origin, "Authorization": f"Bearer {token}"})
    else:
        client.app.state.rate_limiter.check = lambda *_args: 1
        response = client.get("/api/devices", headers=origin)
        assert response.headers["retry-after"] == "1"
    assert response.status_code == status
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["access-control-allow-origin"] == origin["Origin"]


def test_rate_limiter_rejects_requests_over_limit():
    limiter = InMemoryRateLimiter()
    limit = RateLimit(requests=2, window_seconds=60)
    assert limiter.check("login", "127.0.0.1", limit) is None
    assert limiter.check("login", "127.0.0.1", limit) is None
    assert limiter.check("login", "127.0.0.1", limit) >= 1
    assert limiter.check("login", "127.0.0.2", limit) is None


def test_api_responses_include_security_headers(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_oversized_request_is_rejected(client):
    response = client.post(
        "/api/auth/login",
        content=b"{}",
        headers={"Content-Length": "1048577", "Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_chunked_oversized_request_is_rejected(client):
    def body_chunks():
        for _ in range(17):
            yield b"x" * 65_536

    response = client.post(
        "/api/auth/login",
        content=body_chunks(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413


def test_oversized_request_keeps_cors_headers(client):
    response = client.post(
        "/api/auth/login",
        content=b"{}",
        headers={
            "Content-Length": "1048577",
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:5173",
        },
    )

    assert response.status_code == 413
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
