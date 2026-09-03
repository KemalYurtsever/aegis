from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Request


@dataclass(frozen=True)
class RateLimit:
    requests: int
    window_seconds: int


class InMemoryRateLimiter:
    """Small process-local sliding-window limiter for the single-instance AEGIS API."""

    def __init__(self) -> None:
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, bucket: str, identity: str, limit: RateLimit) -> int | None:
        now = time.monotonic()
        cutoff = now - limit.window_seconds
        key = (bucket, identity)
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit.requests:
                return max(1, int(limit.window_seconds - (now - events[0])) + 1)
            events.append(now)
        return None


def request_identity(request: Request) -> str:
    # Do not trust X-Forwarded-For unless a trusted proxy middleware is configured.
    return request.client.host if request.client else "unknown"


def rate_limit_for(request: Request) -> tuple[str, RateLimit]:
    path = request.url.path
    method = request.method
    if path in {"/api/auth/login", "/api/auth/setup"} and method == "POST":
        return "authentication", RateLimit(10, 60)
    expensive = (
        path == "/api/discovery/import"
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
        or path == "/api/backups"
        or (path.startswith("/api/backups/") and path.endswith("/verify"))
        or path == "/api/retention/apply"
        or path == "/api/automation/run"
        or path == "/api/automation/reports/generate"
        or path == "/api/automation/baselines/refresh"
        or path == "/api/security/toolbox/traceroute"
        or (path.endswith("/check") and method == "POST")
    )
    if expensive and method == "POST":
        return "expensive", RateLimit(20, 60)
    return "general", RateLimit(300, 60)
