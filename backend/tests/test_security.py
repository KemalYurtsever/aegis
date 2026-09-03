from app.security import InMemoryRateLimiter, RateLimit


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
