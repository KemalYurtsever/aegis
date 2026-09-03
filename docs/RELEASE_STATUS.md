# AEGIS stabilization status

Validated on 31 August 2026 in the Windows hybrid deployment.

## Current state

- AEGIS frontend: `http://127.0.0.1:5173`
- Administrative API: `http://127.0.0.1:8001`
- Dedicated agent ingress: TCP `8002`
- Grafana: `http://127.0.0.1:3000`
- Prometheus: `http://127.0.0.1:9090`
- Active database: `backend/monitoring.db`
- Runtime logs: `logs/`

The active database passed SQLite integrity and foreign-key checks with 74 devices and one local user preserved. A verified backup was created before lifecycle testing.

## Validation completed

- 135 backend unit and API tests passed.
- The frontend production build completed successfully.
- Python compilation and all PowerShell syntax checks passed.
- `pip check` reported no broken Python requirements.
- `npm audit --omit=dev` reported zero vulnerabilities.
- Configured secret values were not present in the production browser bundle.
- Both Docker Compose definitions and the active Prometheus configuration validated.
- Prometheus successfully scraped the protected AEGIS metrics endpoint.
- All eight provisioned Grafana panel queries executed successfully.
- The administrative API remained bound to loopback and required authentication.
- The agent listener exposes only health, authenticated metric ingestion, and authenticated allowlisted diagnostic job polling/result routes; documentation and administrative routes return 404.
- Stop/start lifecycle testing released every AEGIS port, restored all services, and passed HTTP readiness checks.
- The authenticated system-readiness check reports database integrity, foreign-key health, monitoring and backup scheduler state, and available storage without exposing filesystem paths.
- The administrator-only attack-surface assessment uses a fixed service allowlist and records exposure, passive banners, HTTP headers/version disclosure, and TLS protocol/certificate posture without credential attempts or exploitation.
- Consecutive attack-surface assessments are compared using a capped risk score and new, persistent, and resolved actionable findings.
- The administrator-only attack-path view passively correlates stored assessment findings with device groups, subnets, and criticality; it does not generate traffic or attempt lateral movement.
- The administrator-only security workbench unifies local decoding, inventory, packet metadata, credential-hygiene guidance, registered-device traceroute, configuration completeness, local wireless-adapter status, and validated DNS queries.

## Browser workflow audit

The rendered application was tested against an isolated temporary database so the real inventory was not modified. The following workflows passed:

- first-run administrator creation, logout, and login;
- administrator and read-only viewer role separation;
- device creation, filtering, details, topology, and reachability checks;
- local CPU, memory, and disk collection;
- alert-rule editing;
- TCP service creation, execution, history, and statistics;
- SNMP missing-secret error handling;
- remote-agent enrollment and fleet filtering;
- user management, audit log, notifications, availability reports, DHCP import, and packet-capture panels;
- backup creation and integrity verification.
- a real one-second controlled packet capture using the recommended physical interface; five metadata-only packets were captured successfully without storing payloads.

## Stabilization changes

- Safe GET requests retry once after a transient browser network failure. Mutating requests are never automatically retried.
- `start-hybrid.ps1` validates prerequisites, records service logs, checks Docker exit codes, and waits for all five services to become ready.
- `stop-hybrid.ps1` performs a bounded shutdown wait and no longer reports a false occupied-port warning immediately after process termination.
- Local environment secrets, the Prometheus token, the active database, and backups use restricted Windows ACLs.
- The verified-empty database accidentally created at the project root was moved to `backend/backups/unused-empty-root-monitoring-20260815.db`; it is ignored by the normal backup catalog.

## Environment actions still required

Run the following once from an Administrator PowerShell if remote agents will connect from the LAN:

```powershell
cd "$HOME\Desktop\aegis"
.\configure-agent-access.ps1
```

SNMP, email, Teams, and SMS remain optional. Their server-side environment variables must be configured before those integrations can succeed. Empty optional secrets do not affect normal device, service, agent, Prometheus, or Grafana monitoring.

## Normal operation

Start:

```powershell
cd "$HOME\Desktop\aegis"
.\start-hybrid.ps1
```

Stop without deleting persistent data:

```powershell
.\stop-hybrid.ps1
```

If startup fails, inspect `logs/backend.err.log`, `logs/agent-ingress.err.log`, and `logs/frontend.err.log`.
