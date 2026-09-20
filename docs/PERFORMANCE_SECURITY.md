# API performance and security budgets

## Implemented

| Contract | Before | Current |
| --- | --- | --- |
| Valid bearer-session authentication SELECTs | 2 | 1 (session plus user in one joined query) |
| Authentication connections held while an endpoint runs | 1 | 0 |
| Authentication and mutation-audit database I/O | Async event-loop thread | Awaited worker with its own short-lived session |
| Process-local limiter identity/bucket keys | No global bound or idle-key removal | Maximum 4,096; periodic expired-key removal |
| Authentication middleware errors | Missing security/CORS headers on early returns | 401/403/429 retain security headers and permitted-origin CORS |

The query/connection figures are assertions measured with an isolated temporary SQLite database. They are not an overall API speedup or network-scan latency claim.

Permissions are not cached: every protected request still checks the session, expiry and current user role/active state. Authentication sessions close before endpoint work; mutation auditing is awaited and committed in a separate worker session before returning the response. Invalid and expired sessions are still rejected.

The limiter stores only accepted request timestamps. Rejected requests do not extend an entry's lifetime. At capacity, new identities receive HTTP 429 rather than evicting an active counter and allowing its rate limit to reset. Existing identities retain their own remaining budget. Idle cleanup runs at most once per 30 seconds by default; concurrent checks and cleanup share a lock. This is a bounded single-process limiter, not a distributed limiter or a replacement for an ingress traffic budget.

Read-only MAC adapter inspection has a separate 20-request/minute budget. MAC plan/apply POSTs share the existing 20-request/minute expensive-operation budget. Exact-address binding, elevation checks, single-use plans, fresh state and driver readback are unchanged.

CORS wraps authentication but still allows only the existing loopback frontend origins on ports 5173/5174; credentials and arbitrary origins are not enabled.

## Reproduce the regression checks

From `backend/` with its virtual environment installed:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_auth_performance.py tests/test_security.py tests/test_auth.py tests/test_mac_management.py -o addopts='' -q -s
```

This runs query-count, connection-lifetime, worker-thread, role-change, expiry, inactive-user, audit, limiter-capacity/concurrency, CORS/error-header and MAC guard checks. It uses temporary test databases and mocked MAC operations, not the operator database or physical adapter changes. The query-count/connection tests print `1` and `0`, respectively.

For the complete backend suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' -q
```

## Remaining boundaries

- Long endpoint work still occupies endpoint workers; this change does not add a durable queue or multi-instance support.
- Nmap/service detection time depends on actual target/network responses and scan budgets, not the authentication query count.
- Elevated Windows install/upgrade, custom-parent junction-race behavior and physical-adapter/target-observed MAC changes require separate controlled runtime verification.
- External Wireshark image enforcement and PCAP retention remain separately verified deployment concerns; this pass does not modify or publish Wireshark.
- Existing dependency deprecation notices and the lazily loaded spreadsheet-export bundle warning are not suppressed by these changes.
