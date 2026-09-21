from __future__ import annotations

import re
import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Awaitable, Callable

from fastapi import Request
from starlette.responses import JSONResponse


class RequestBodyLimitMiddleware:
    """Read and replay bounded ASGI request bodies, including chunked uploads."""

    def __init__(self, app, max_body_size: int, path_limits: dict[str, int] | None = None) -> None:
        self.app = app
        self.max_body_size = max_body_size
        self.path_limits = [(re.compile(pattern), limit) for pattern, limit in (path_limits or {}).items()]

    async def __call__(self, scope, receive: Callable[[], Awaitable[dict]], send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_limit = next(
            (limit for pattern, limit in self.path_limits if pattern.fullmatch(scope.get("path", ""))),
            self.max_body_size,
        )
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
                if declared_size < 0:
                    raise ValueError
            except ValueError:
                await self._reject(scope, receive, send, 400, "Invalid Content-Length header")
                return
            if declared_size > request_limit:
                await self._reject(scope, receive, send, 413, "Request body is too large")
                return

        body = bytearray()
        disconnected = False
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
                break
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > request_limit:
                await self._reject(scope, receive, send, 413, "Request body is too large")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_receive() -> dict:
            nonlocal replayed
            if disconnected:
                return {"type": "http.disconnect"}
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(scope, receive, send, status_code: int, detail: str) -> None:
        response = JSONResponse(status_code=status_code, content={"detail": detail})
        await response(scope, receive, send)


@dataclass(frozen=True)
class RateLimit:
    requests: int
    window_seconds: int


class InMemoryRateLimiter:
    """Small process-local sliding-window limiter for the single-instance AEGIS API."""

    def __init__(self, max_keys: int = 4096, cleanup_interval: float = 30.0,
                 clock: Callable[[], float] | None = None) -> None:
        if max_keys < 1 or not math.isfinite(cleanup_interval) or cleanup_interval <= 0:
            raise ValueError("Rate limiter capacity and cleanup interval must be positive")
        self._events: dict[tuple[str, str], deque[float]] = {}
        self._expires: dict[tuple[str, str], float] = {}
        self._max_keys = max_keys
        self._cleanup_interval = cleanup_interval
        self._next_cleanup = 0.0
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()

    def check(self, bucket: str, identity: str, limit: RateLimit) -> int | None:
        key = (bucket, identity)
        with self._lock:
            now = self._clock()
            cutoff = now - limit.window_seconds
            if now >= self._next_cleanup:
                for expired in [item for item, expiry in self._expires.items() if expiry <= now]:
                    del self._events[expired]
                    del self._expires[expired]
                self._next_cleanup = now + self._cleanup_interval
            events = self._events.get(key)
            if events is None:
                if len(self._events) >= self._max_keys:
                    # Fail closed for new identities: evicting a live counter
                    # would let identity churn reset another client's limit.
                    return max(1, math.ceil(self._next_cleanup - now))
                events = self._events[key] = deque()
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit.requests:
                return max(1, int(limit.window_seconds - (now - events[0])) + 1)
            events.append(now)
            # Rejected requests do not extend the lifetime of idle entries.
            self._expires[key] = now + limit.window_seconds
        return None


def request_identity(request: Request) -> str:
    # Do not trust X-Forwarded-For unless a trusted proxy middleware is configured.
    return request.client.host if request.client else "unknown"


def rate_limit_for(request: Request) -> tuple[str, RateLimit]:
    path = request.url.path
    method = request.method
    if path in {"/api/auth/login", "/api/auth/setup"} and method == "POST":
        return "authentication", RateLimit(10, 60)
    if path == "/api/system/mac/adapters" and method == "GET":
        return "host-inspection", RateLimit(20, 60)
    expensive = (
        path == "/api/discovery/import"
        or path in {"/api/system/mac/plan", "/api/system/mac/apply"}
        or path == "/api/devices/actions/clear-all"
        or path == "/api/devices/check-all"
        or path == "/api/devices/bulk/check"
        or path == "/api/packet-captures"
        or path.endswith("/scan-ports")
        or path.endswith("/vulnerability-scans")
        or path.endswith("/metrics/collect")
        or path.endswith("/snmp/poll")
        or path.endswith("/test")
        or path.endswith("/fingerprint")
        or path.endswith("/fingerprint-all")
        or path.endswith("/dhcp-leases/import")
        or path.endswith("/troubleshooting-runs")
        or (path.startswith("/api/segmentation-policies/") and path.endswith("/checks"))
        or path == "/api/backups"
        or (path.startswith("/api/backups/") and path.endswith("/verify"))
        or path == "/api/retention/apply"
        or path == "/api/automation/run"
        or path == "/api/automation/reports/generate"
        or path == "/api/automation/baselines/refresh"
        or path.startswith("/api/security/toolbox/")
        or path == "/api/security/playbooks/runs"
        or (path.endswith("/check") and method == "POST")
    )
    if expensive and method == "POST":
        return "expensive", RateLimit(20, 60)
    return "general", RateLimit(300, 60)
