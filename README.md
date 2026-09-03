# LIIMS

Local IT Infrastructure Monitoring System (LIIMS) is an isolated-lab application for registering devices, checking their reachability, storing monitoring history, and presenting availability information.

## Week 1 status

The first backend milestone includes:

- FastAPI health endpoint
- SQLite database initialization
- Device create, list, retrieve, update, and delete endpoints
- IPv4/IPv6 normalization and validation
- Duplicate-IP and missing-device error handling
- Automated API tests
- Safe cross-platform ping command execution with bounded timeouts
- Manual monitoring checks persisted as online/offline results
- Reverse-chronological monitoring history with bounded result limits
- Availability, successful-latency, and current-status statistics
- Derived online/offline status-transition events
- Lifecycle-managed automatic monitoring of active devices every 60 seconds
- Scheduler status endpoint and duplicate-start prevention
- Dashboard aggregate API and initial responsive React dashboard

Email, Microsoft Teams, and SMS alert delivery, retry history, test actions, Prometheus metrics, and a provisioned Grafana dashboard are included.

## Docker deployment

### Recommended Windows hybrid mode

For full Windows adapter discovery, Npcap capture, Windows metrics, and future Active Directory support, run LIIMS natively and keep only Prometheus and Grafana in Docker:

```powershell
cd "$HOME\Desktop\liims"
.\start-hybrid.ps1
```

The launcher waits for the frontend, API, agent ingress, Grafana, and Prometheus to pass readiness checks. Native service output is stored under `logs/` for troubleshooting.

This starts the Windows backend from `backend/.venv`, the Vite frontend, and the observability-only Compose file. Prometheus reaches the native backend at `host.docker.internal:8000`. Your original `backend/monitoring.db` and Windows functionality remain available.

Stop the hybrid stack without deleting data:

```powershell
.\stop-hybrid.ps1
```

The current release validation results and remaining environment-only actions are recorded in [docs/RELEASE_STATUS.md](docs/RELEASE_STATUS.md).

If PowerShell script execution is restricted, run once in the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

### Fully containerized mode

Install Docker Desktop, then create the required local configuration from the project root:

```powershell
Copy-Item .env.docker.example .env
New-Item -ItemType Directory -Force secrets
$tokenBytes = New-Object byte[] 32
$rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
$rng.GetBytes($tokenBytes)
$rng.Dispose()
($tokenBytes | ForEach-Object { $_.ToString("x2") }) -join "" |
    Set-Content -NoNewline secrets/prometheus_token.txt
```

Edit `.env` and replace `GRAFANA_ADMIN_PASSWORD` with a unique long password. Then start the complete stack:

```powershell
docker compose up --build -d
docker compose ps
```

Services become available at:

- LIIMS dashboard: `http://127.0.0.1:5173`
- LIIMS API documentation: `http://127.0.0.1:8000/docs`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000`

LIIMS includes an **Observability** view that embeds the provisioned Grafana dashboard directly inside the application. The local read-only view does not require a separate login. Administrators can still open `http://127.0.0.1:3000` manually when they need Grafana configuration. The embedded dashboard defaults can be changed at frontend build time with `VITE_GRAFANA_URL` and `VITE_GRAFANA_DASHBOARD_URL`.

SQLite, Prometheus time-series data, and Grafana state use named Docker volumes. Stop the stack with `docker compose down`; this preserves data. Only use `docker compose down -v` when you intentionally want to delete all Docker-managed LIIMS data.

Device attachments accept only UTF-8 text, PDF, PNG, and JPEG files up to 5 MiB. Content signatures are validated by the API, files are stored under `backend/attachments` in native mode or `/data/attachments` in Docker using randomized `.blob` names, and downloads always use attachment disposition. Back up this directory together with the SQLite backup catalog when moving LIIMS to another machine.

## Prometheus and Grafana

The protected `/metrics` endpoint exposes device state and latency, unresolved-alert count, service state, latest host CPU/memory/disk utilization, and scheduler state in OpenMetrics format. Prometheus authenticates with the bearer token stored in `secrets/prometheus_token.txt`.

Grafana is automatically provisioned with the Prometheus data source and **LIIMS Infrastructure Overview** dashboard. The dashboard contains device totals, online count, active alerts, scheduler state, device latency, resource utilization, device status, and service status. Provisioned dashboard files remain the source of truth.

Grafana anonymous access is limited to the Viewer role and all published ports remain bound to `127.0.0.1`, so the embedded dashboard is available only on the LIIMS host by default. Administrative changes still require the Grafana administrator account.

## Kubernetes and cloud deployment

Cloud-ready Kustomize manifests are available under `deploy/kubernetes`. Build and push the backend and frontend images, replace `ghcr.io/replace-me/...` in the deployment files with your registry paths, then prepare the untracked secret:

```powershell
Copy-Item deploy/kubernetes/secret.example.yaml deploy/kubernetes/secret.yaml
```

Replace every placeholder in `secret.yaml`, change `liims.example.com` in `ingress.yaml`, and ensure the cluster has a default StorageClass and ingress controller. Deploy with:

```powershell
kubectl apply -k deploy/kubernetes
kubectl -n liims get pods,svc,pvc,ingress
```

The stack includes health probes, resource requests/limits, persistent claims, Prometheus, Grafana provisioning, and secret-backed credentials. The backend intentionally remains at one replica because SQLite uses a single persistent database file. A horizontally scaled backend requires the later PostgreSQL migration.

For production, enable Kubernetes secret encryption at rest, restrict secret RBAC, use a managed secret provider, configure TLS on the ingress, pin container images by digest, and configure backups for all persistent volumes.

## Attack-surface assessment

Administrators can run a bounded assessment against a registered device. It checks only the fixed common-port allowlist, flags exposed management, cleartext, database, and infrastructure services, reads short passive banners from greeting-based protocols, checks HTTP security headers and version disclosure, and records the negotiated TLS protocol, cipher, certificate fingerprint, and validation result. Findings include severity and remediation guidance; operators and viewers can review stored results but cannot start an assessment.

The device page compares the two latest completed assessments. It assigns a capped 0–100 score to actionable findings and separates newly exposed, persistent, and resolved items. Informational evidence does not increase the score, so a clean follow-up scan clearly shows remediated exposure without treating positive informational records as new risk.

The assessment does not exploit vulnerabilities, submit credentials, brute-force services, execute payloads, or enumerate arbitrary networks. In the hybrid lab launcher, `LIIMS_AUTHORIZED_LAB_MODE=true` removes address-range classification for explicit actions against devices already registered in LIIMS. Authentication, administrator checks, rate limits, bounded port sets, and input validation remain enabled. Results are exposure indicators—not proof that a CVE is present—and should be combined with authenticated patch and asset-management records.

### Passive attack-path analysis

Administrators can open **Attack paths** from the sidebar. LIIMS correlates the latest stored assessment for each active device with inventory groups, IP subnets, and target criticality. Exposed remote-access services such as SSH, SMB, RDP, VNC, FTP, and Telnet are shown as possible entry points toward related assets. The analysis sends no additional network traffic and clicking either endpoint opens that device's LIIMS record.

These paths are prioritization hypotheses, not confirmed routes. Sharing a group or subnet does not prove that firewalls, credentials, or network segmentation permit lateral access. Confirm important paths with the network design and authorized validation before treating them as exploitable.

### Security workbench

Administrators can open **Security workbench** from the sidebar for one consolidated defensive-investigation interface. It contains:

- Browser-local Base64, hexadecimal, and URL encoding/decoding. Input is never sent to the API.
- Searchable registered network inventory and existing packet-capture summaries.
- Browser-local credential-hygiene feedback using disposable password examples.
- A bounded traceroute to a selected registered device: at most 12 hops and 20 seconds.
- Inventory-completeness and stored attack-path review without configuration extraction.
- Local LIIMS-host wireless-adapter status without Wi-Fi keys or handshake collection.
- Validated forward and reverse DNS queries without constructing shell commands.

This is deliberately not a credential-cracking or interception suite. LIIMS does not provide password/hash cracking, credential harvesting, ARP poisoning, man-in-the-middle routing, wireless-key recovery, router-configuration theft, or arbitrary remote command execution. Packet inspection remains metadata-only and all workbench API routes require an administrator session.

## Controlled packet capture

Administrators can open **Packet capture** from the sidebar and select an interface, a duration of 1–30 seconds, and a maximum of 1–1000 packets. LIIMS stores only metadata: timestamp, source/destination address, protocol, ports, and packet length. Packet payloads and PCAP files are not retained.

Windows capture requires Npcap and may require launching the backend terminal as Administrator. Capture only networks and devices you own or are explicitly authorized to monitor. The feature disables promiscuous mode and does not inject or modify traffic.

The hybrid launcher sets `LIIMS_ALLOW_PUBLIC_LAN_DISCOVERY=true`, allowing discovery when the active physical Windows adapter receives a non-RFC-1918 address. This does not accept a browser-supplied target: discovery is restricted to the directly connected adapter, excludes VPN/virtual interfaces, and scans at most its local `/24`. Remove that environment assignment to restore private-network-only discovery.

ARP discovery is rate-limited by `LIIMS_DISCOVERY_ARP_PACKETS_PER_SECOND` (default `10`) and performs one retry-free pass. Lower values reduce broadcast traffic further but increase discovery duration.

All published Docker ports are explicitly bound to `127.0.0.1`. LIIMS, Grafana, and Prometheus are therefore accessible only from the local computer unless an operator deliberately changes the Compose bindings or places a separately secured reverse proxy in front of them.

## Local anomaly detection

After at least 21 samples, LIIMS builds a per-device robust local baseline using the median and median absolute deviation. It evaluates latency, CPU, memory, and disk measurements and records warning or critical anomalies when the latest value is significantly above that baseline. Detection runs after scheduled monitoring and can also be triggered from the device page.

This feature runs locally and does not send telemetry to an AI provider or require an API key. Its results are operational indicators rather than guaranteed diagnoses; review the underlying measurements before taking action.

## Requirements

- Python 3.12 or newer
- PowerShell (commands below) or an equivalent terminal

## Authentication and roles

On the first browser visit, LIIMS requires creation of a local administrator with a username and a password of at least 12 characters. Passwords are hashed with scrypt and a unique random salt. Successful sign-in creates a random 12-hour opaque session token; only its SHA-256 digest is stored in SQLite, and sign-out revokes it.

Roles are enforced by the API and reflected in the browser:

- **Admin**: full monitoring access plus local-user creation, role changes, enable/disable controls, and session revocation when an account is disabled.
- **Operator**: device, discovery, monitoring, alert, agent, and service-management access without user administration.
- **Viewer**: read-only dashboards, details, histories, statistics, and charts.

The health endpoint, first-run setup, login, API documentation, and authenticated remote-agent metric submission remain reachable without a browser session. All other application API endpoints require `Authorization: Bearer <session-token>`.

Authenticated POST, PUT, and DELETE operations create persistent audit events containing the acting username and role, HTTP method, route, response status, source address, and timestamp. Request bodies, passwords, and tokens are never written to the audit trail. Administrators can search and filter the latest events from **Audit log** in the sidebar; the API is available at `GET /api/auth/audit-events`.

LIIMS prevents the last active administrator from being disabled or demoted. Disabling an account or resetting its password revokes its existing sessions.

## Run the backend

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open:

- API documentation: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/api/health>

The local SQLite database is created as `backend/monitoring.db` and is intentionally ignored by Git.

## Run tests

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m pytest
```

Tests use a temporary SQLite database and do not modify the development database.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Confirm the API is healthy |
| POST | `/api/devices` | Create a device |
| GET | `/api/devices` | List devices |
| GET | `/api/devices/{id}` | Retrieve one device |
| PUT | `/api/devices/{id}` | Update one device |
| DELETE | `/api/devices/{id}` | Delete one device |
| POST | `/api/devices/{id}/check` | Ping one device and store the result |
| POST | `/api/devices/check-all` | Check every active device and return an online/offline summary |
| GET | `/api/devices/{id}/history` | List recent monitoring results |
| GET | `/api/devices/{id}/statistics` | Calculate availability and latency statistics |
| GET | `/api/devices/{id}/status-events` | List derived online/offline transitions |
| POST | `/api/devices/{id}/scan-ports` | Scan a bounded set of common TCP ports on a private registered device |
| GET | `/api/scheduler/status` | Show automatic-monitoring status and interval |
| POST | `/api/scheduler/pause` | Pause automatic monitoring without affecting manual checks |
| POST | `/api/scheduler/resume` | Resume automatic monitoring when enabled by server configuration |
| GET | `/api/dashboard` | Return dashboard counts, device summaries, and recent events |

## Run the frontend

Keep the backend running, then open a second PowerShell window:

```powershell
cd "$HOME\Desktop\liims\frontend"
npm.cmd install
npm.cmd run dev
```

Open <http://127.0.0.1:5173>. The dashboard refreshes automatically every 15 seconds and includes a **Check now** action for each device.

Use **Search** in the dashboard header (or `Ctrl+K` / `Cmd+K`) to quickly open devices and operational panels. The command palette supports typing to filter, arrow keys (or Home/End) to choose a result, `Enter` to open it, and `Esc` to close.

The dashboard-level **Check all** action runs an immediate reachability check for every active device, stores normal history and alert evaluations, disables conflicting dashboard actions while running, and reports the resulting online/offline totals.

The monitored-device table supports ascending/descending sorting by device name, status, latency, availability, and last-check time. Devices without a value remain at the end of either numeric/date ordering.

The inventory can also be searched by device name, IP address, or type and filtered by monitoring status and device type. Search and filters combine with the selected table sort, and the heading shows the number of matching devices.

Inventory results are paginated after filtering and sorting. The dashboard shows 10 rows by default, supports 10/25/50-row page sizes, and reports the visible result range and current page.

The **Export CSV** action downloads the complete currently filtered and sorted inventory, regardless of the current page. The UTF-8 CSV includes device identity, status, latency, availability, and last-check time for spreadsheet use and reporting.

The **Export Excel** action creates a native `.xlsx` workbook from the same filtered and sorted inventory. It contains a formatted, filterable **Device Inventory** table with frozen headers and typed latency, percentage, and date cells, plus a **Summary** sheet with formula-driven device-status counts. The Excel library is loaded only when export is requested so the normal dashboard bundle stays lightweight.

The frontend also supports adding and editing devices, confirmed deletion, and a detail view containing statistics, monitoring history, and status transitions.

Each device detail view has a shareable URL such as `/devices/1`, supports browser Back/Forward navigation, and plots the 30 most recent successful latency measurements without an external charting dependency.

Local alert rules can be configured per device. LIIMS raises persistent critical alerts after a chosen number of consecutive failures, warning alerts above a latency threshold, resolves them automatically after recovery, and supports acknowledgement from the dashboard.

Administrators can open **Notifications** from the sidebar to enable Email or Microsoft Teams, save non-secret settings, send test messages, inspect delivery history, and retry failures. Automatic alert deliveries are uniquely queued per alert/channel and retried at most three times by the scheduler.

Secrets are intentionally supplied as environment variables before starting the backend and are never returned by the API or stored in SQLite:

```powershell
$env:LIIMS_SMTP_PASSWORD = "your-smtp-app-password"
$env:LIIMS_TEAMS_WEBHOOK_URL = "https://your-teams-workflow-webhook"
$env:LIIMS_TWILIO_ACCOUNT_SID = "your-account-sid"
$env:LIIMS_TWILIO_AUTH_TOKEN = "your-auth-token"
```

Configure the SMTP host, port, username, sender, recipients, and TLS option in the administrator UI. The Teams card only needs the webhook environment variable. Restart the backend after changing environment variables.

The SMS channel uses Twilio's Messages API. Configure the sender and comma-separated recipients in **Notifications**; keep the account SID and authentication token in the environment variables above.

## SNMP monitoring

Each device detail page includes an opt-in SNMP v2c panel. LIIMS reads only the standard system description, system name, location, uptime, and interface-count OIDs and stores every result. Enable automatic polling or use **Poll now** for an immediate check.

The SNMP community is never stored in SQLite. Set it before launching the backend:

```powershell
$env:LIIMS_SNMP_COMMUNITY = "your-read-only-community"
```

For devices that use different communities, create another environment variable and enter its name—not its value—in that device's SNMP panel. Restrict UDP port 161 and read-only community access to the LIIMS host on your isolated lab network.

## Local network discovery

On Windows, **Discover devices** identifies the active private IPv4 adapter, shows the exact interface and `/24` network for confirmation, then probes at most 254 local addresses. Responsive addresses are imported automatically, existing IPs are skipped, and MAC addresses are included when Windows has them in its ARP table.

Discovery is deliberately user-triggered and restricted to private networks. Use it only on networks you own or have explicit permission to test. `ipconfig /all` itself lists adapter configuration; it does not enumerate all devices, so LIIMS combines adapter detection, bounded ping discovery, and the ARP table.

VPN, tunnel, Hyper-V, VirtualBox, VMware, loopback, and `/31`–`/32` interfaces are excluded from automatic LAN selection. If the physical adapter has a public IPv4 address, discovery stops instead of scanning a publicly routed range. Guest, campus, hotel, and mobile networks may also use client isolation, which prevents devices from discovering one another even when they share an apparent subnet.

## Service monitoring

Device detail pages support TCP, HTTP, and HTTPS service checks. TCP checks verify that a port accepts a connection; HTTP/HTTPS checks send a bounded `GET` request to a validated path and record response time plus status code. Checks use the registered device IP rather than arbitrary URLs, store history in SQLite, and run automatically with the normal scheduler when active.

Existing service checks can be edited from the device page, including their name, protocol, port, HTTP path, and automatic-check state. Individual checks can be paused without deleting their configuration or stored history.

Each service check also exposes its 20 most recent results inline, including timestamp, up/down status, response time, HTTP status code when applicable, and normalized failure diagnostics.

Expanded service history includes availability, average successful response time, successful/failed totals, and a dependency-free SVG response-time chart. Failed samples remain visible in the table but are omitted from the response-time line because they have no latency value. The statistics are also available from `GET /api/service-checks/{check_id}/statistics`.

The **Scan common ports** action performs a user-confirmed, concurrent scan of a fixed infrastructure allowlist: FTP, SSH, Telnet, SMTP, DNS, HTTP(S), POP3, IMAP, LDAP, SMB, MySQL, RDP, PostgreSQL, VNC, Redis, HTTP alternate, and Elasticsearch. It reports open ports plus connection time. It is limited to registered devices on private/loopback addresses or, when `LIIMS_ALLOW_PUBLIC_LAN_DISCOVERY=true`, the bounded `/24` of the active physical adapter. Unrelated public targets are rejected. The bounded scan is intended for devices you own or are explicitly authorized to test.

Each discovered open port includes a **Monitor** action. LIIMS maps port 443 to HTTPS, ports 80/8080 to HTTP, and the remaining common ports to TCP, then creates a persistent scheduled service check. Ports already represented by a service check are marked **Monitored** and cannot be duplicated from the scan result.

## Device groups and bulk operations

Devices can be assigned to an optional operational group such as `Finance Lab`, `Server Room`, or `Floor 2`. Groups are searchable, filterable, visible in device details, and included in Excel inventory exports.

Administrators and operators can select devices from the inventory table and assign or clear a group, enable or pause automatic monitoring, or run immediate checks. Bulk requests reject duplicate IDs and validate the complete selection before making changes; if any selected device no longer exists, no group or monitoring update is committed. Bulk deletion is deliberately not provided.

## Local host metrics

For loopback devices (`127.0.0.1` or `::1`), LIIMS collects CPU, memory, and system-disk usage through a built-in local collector. Samples are stored each scheduler cycle and can also be collected manually. Remote devices report through the separately enrolled authenticated agent described below.

## Remote host agent

Remote Windows/Linux devices can be enrolled from their device page. LIIMS displays a one-time token and stores only its SHA-256 hash. The agent submits metrics using the `X-Agent-Token` header; tokens can be rotated or revoked, and a token is bound to exactly one device.

Hybrid mode keeps the administrative API on loopback port `8001` and starts a separate agent-only ingress on TCP `8002`. Run the following once from PowerShell as Administrator to allow only the active physical subnet through Windows Firewall:

```powershell
.\configure-agent-access.ps1
```

For a remote Windows host, copy the `agent` folder, open PowerShell as Administrator, and run the one-command installer. The token is prompted securely when omitted:

```powershell
.\install-windows.ps1 -ServerUrl "http://LIIMS-LAN-IP:8002"
```

Remote diagnostics are disabled by default. To explicitly allow the administrator-only diagnostic job panel on that host, add `-EnableDiagnostics`:

```powershell
.\install-windows.ps1 -ServerUrl "http://LIIMS-LAN-IP:8002" -EnableDiagnostics
```

The agent accepts only fixed diagnostic types: local service/version scan, bounded packet metadata capture, operating-system warning/error summary, network connections, top processes, SUID audit, login history, local accounts, and firewall rules. It does not accept arbitrary command text. Every job is bound to one enrolled device, expires after 15 minutes, has bounded parameters and result size, and is recorded in the normal HTTP audit trail. Nmap must be installed on the agent host for service/version scanning. Packet metadata capture requires Scapy plus Npcap on Windows and never stores packet payloads.

The installer first verifies that the dedicated agent ingress is reachable, creates a private configuration under `%ProgramData%\LIIMS Agent`, submits one authenticated verification sample, and then registers the auto-restarting `LIIMS Host Agent` startup task. Operational logs rotate under `%ProgramData%\LIIMS Agent\logs\agent.log`. Remove the agent with `%ProgramData%\LIIMS Agent\uninstall-windows.ps1` from an administrator terminal.

Run a non-authenticated connectivity check on a remote host with:

```powershell
& "$env:ProgramData\LIIMS Agent\test-agent.ps1"
```

Test both connectivity and the enrolled token by submitting one real metric sample:

```powershell
& "$env:ProgramData\LIIMS Agent\test-agent.ps1" -SubmitSample
```

On the remote machine, copy the `agent/` folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:LIIMS_SERVER_URL = "http://192.168.10.74:8002"
$env:LIIMS_AGENT_TOKEN = "PASTE_ONE_TIME_TOKEN"
$env:LIIMS_AGENT_DIAGNOSTICS_ENABLED = "true" # Optional administrator diagnostics
.\.venv\Scripts\python.exe liims_agent.py
```

Agent state is derived from the interval each collector reports: `WAITING`, `REPORTING`, `DELAYED`, or `OFFLINE`. The dashboard-level **Remote agent fleet** panel summarizes those states and links each collector to its device page. Expand it to filter by health state and see the reported hostname, platform, last report time, and reporting interval. Attention states and the stalest reports are listed first.

When a previously reporting agent becomes `OFFLINE`, the scheduler creates one persistent `AGENT_OFFLINE` critical alert. The alert respects device maintenance windows, uses the normal acknowledgement and notification flow, and resolves automatically as soon as reporting resumes. Agents that have never connected remain `WAITING` and do not generate false offline alerts. CPU, memory, and disk warning thresholds are configured in the normal per-device alert rule. Do not expose the agent ingress to the public Internet; production deployment, especially remote diagnostics, requires HTTPS.

## Logical network topology

The dashboard topology groups inventory by imported VLAN and IPv4 `/24` or IPv6 `/64`. It identifies the active adapter and gateway when available, then arranges classified routers, switches, access points, and endpoints into an inferred logical flow. These relationships are inventory inferences; they do not claim physical switch-port, LLDP, or cable discovery.

Operators can also record confirmed `UPLINK`, `CONNECTS TO`, `ROUTES TO`, and `MANAGES` relationships between registered devices. Confirmed links remain separate from inferred subnet layout and both endpoints are clickable.

## Automatic monitoring

The backend starts one periodic monitoring task with the application. By default, it waits 60 seconds and then checks every active device. Inactive devices are skipped, and each result is stored exactly like a manual **Check Now** result.

The interval can be changed for local development before starting the server:

```powershell
$env:MONITOR_INTERVAL_SECONDS = "10"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Use a short interval only for testing. The recommended normal MVP value is 60 seconds.

## Operations automation

Administrators can open **Automation center** from the sidebar. It provides
recurring maintenance windows, correlated incidents, optional allowlisted
incident diagnostics, scheduled local availability reports, configuration
drift detection, desired-agent-version visibility, and an advisory health
summary. Network-changing automations—automatic discovery, service discovery,
and paced defensive assessment—are disabled until an administrator enables
them.

The automation scheduler reuses the normal monitoring cycle and database
records. It does not create a second worker or duplicate the monitoring logic.
See [docs/AUTOMATION.md](docs/AUTOMATION.md) for configuration and safety
boundaries.

## Backups and history retention

Administrators can open **Backups & retention** from the sidebar. LIIMS creates a consistent SQLite snapshot at startup and every 24 hours, verifies it with SQLite's integrity check, and retains the newest 14 backups. Manual backups can also be created, re-verified, and downloaded from the same screen. Backup files are stored under `backend/backups` in native Windows mode and `/data/backups` in Docker.

These environment variables customize the policy:

```powershell
$env:LIIMS_BACKUP_ENABLED = "true"
$env:LIIMS_BACKUP_INTERVAL_HOURS = "24"
$env:LIIMS_BACKUP_KEEP_COUNT = "14"
$env:LIIMS_BACKUP_DIRECTORY = ".\backups"
$env:LIIMS_HISTORY_RETENTION_DAYS = "90"
```

History cleanup always starts with a read-only preview. Applying it requires typing `DELETE HISTORY`, creates and verifies a safety backup first, and only removes old reachability results, service results, host metrics, SNMP results, and anomaly events. Devices, users, alert rules, service definitions, and other configuration are preserved.

To restore a downloaded or local backup, stop LIIMS and run the guarded Windows restore command:

```powershell
.\stop-hybrid.ps1
.\restore-backup.ps1 -BackupFile ".\backend\backups\liims-YYYYMMDD-HHMMSS-abcdef.db"
.\start-hybrid.ps1
```

The restore script refuses to continue while port 8001 is listening, verifies SQLite integrity and required LIIMS tables, and preserves the previous active database as `backend/backups/pre-restore-<timestamp>.db` before replacement.

The dashboard displays the scheduler as **Auto running**, **Auto paused**, or **Auto disabled**. Select the status control to pause or resume scheduled checks; manual device and batch checks remain available while paused. A server configured with `SCHEDULER_ENABLED=false` cannot be resumed from the browser.

Example request:

```json
{
  "name": "Ubuntu Server",
  "ip_address": "192.168.56.20",
  "device_type": "Server",
  "description": "Isolated Linux test VM",
  "is_active": true
}
```
