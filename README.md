# Aegis

Aegis is a self-hosted infrastructure monitoring and defensive operations console for authorized private networks and isolated labs. It combines asset inventory, availability monitoring, service checks, host telemetry, alerting, reporting, and bounded security diagnostics in one responsive web interface.

Aegis keeps operational data under the operator's control. The standard installation uses SQLite for application data, Prometheus for time-series scraping, and Grafana for long-range visualization. It does not require a cloud service.

> Aegis is intended for systems and networks you own or are explicitly authorized to assess. Its discovery, capture, diagnostic, and assessment tools are deliberately bounded and are not a substitute for authorization or change control.

## Product capabilities

### Operations dashboard

| Function | What it does |
|---|---|
| Infrastructure summary | Shows total, online, offline, and unchecked devices together with active alerts and scheduler state. |
| Device inventory | Presents current status, response time, availability, last check, type, group, and other identifying information in one table. |
| Search and filters | Filters devices by name, IP address, type, group, and monitoring status. Saved views preserve frequently used filter combinations in the browser. |
| Sorting and pagination | Sorts inventory by device name, status, latency, availability, or last-check time and supports 10, 25, or 50 rows per page. |
| Bulk actions | Checks selected devices, changes their operational group, or enables and pauses monitoring as one validated operation. |
| Operational insights | Highlights devices that need attention and links directly to the relevant device record. |
| Inventory health | Identifies incomplete asset records so operators can improve ownership, classification, and support information. |
| Service-health overview | Summarizes monitored TCP, HTTP, and HTTPS services and exposes unhealthy checks without opening each device. |
| Remote-agent fleet | Summarizes enrolled collectors as waiting, reporting, delayed, or offline and prioritizes stale agents. |
| Logical topology | Groups devices by VLAN and subnet, shows inferred network relationships, and displays operator-confirmed links separately. |
| Command palette | Opens devices and operational panels from a keyboard-searchable menu using `Ctrl+K` or `Cmd+K`. |
| Responsive navigation | Provides mobile navigation, fixed desktop navigation, collapsible sections, light and dark themes, readable typography, and keyboard focus states. |

The dashboard refreshes every 15 seconds. **Check all** runs an immediate reachability check for every active device and stores the results through the same alert and history pipeline used by scheduled monitoring.

### Asset inventory and device records

| Function | What it does |
|---|---|
| Device management | Creates, edits, views, and deletes monitored devices with normalized IPv4 or IPv6 addresses and duplicate-address protection. |
| Device groups | Assigns an operational group such as a site, floor, lab, or business unit for filtering and bulk administration. |
| Device profile | Combines availability statistics, latency history, status transitions, service checks, telemetry, SNMP, alerts, assessments, and agent state on one page. |
| Notes | Stores timestamped operational notes against a device. |
| Attachments | Stores validated UTF-8 text, PDF, PNG, and JPEG files up to 5 MiB. Files use randomized storage names and download as attachments. |
| Activity timeline | Merges important device events into a chronological operational history. |
| Change history | Records material changes to inventory data for later review. |
| DHCP import | Allows administrators to import lease information into inventory with validation and duplicate handling. |
| CSV export | Exports the complete filtered and sorted inventory as UTF-8 CSV, independent of the current page. |
| Excel export | Creates a formatted `.xlsx` workbook with typed values, filters, frozen headers, and a formula-driven summary sheet. The Excel library loads only when requested. |
| Shareable device URLs | Gives every device a direct URL such as `/devices/1` and supports normal browser Back and Forward navigation. |

### Availability, services, and alerts

| Function | What it does |
|---|---|
| Reachability checks | Performs bounded cross-platform ping checks and stores online/offline state, successful latency, timestamps, and normalized errors. |
| Automatic monitoring | Runs one lifecycle-managed scheduler that checks active devices at the configured interval. Operators can pause and resume scheduling without disabling manual checks. |
| Availability statistics | Calculates successful and failed checks, availability percentage, average successful latency, and current state from stored history. |
| Status transitions | Derives online-to-offline and offline-to-online events from monitoring history. |
| Service checks | Monitors TCP ports and HTTP or HTTPS endpoints on registered devices. HTTP checks use a validated path and record response time and status code. |
| Service history | Shows recent results, uptime, successful and failed totals, average response time, and a dependency-free response-time chart. |
| TCP port scan | Scans Nmap's 1,000 most common TCP ports on a registered device, using Nmap when available and a bounded host-side socket scanner otherwise, then can turn an open port into a scheduled service check. |
| Attack-surface CVE correlation | Runs a fast top-1,000 TCP pass, then performs Fast, Detailed, or Aggressive service detection only on open ports. It searches the full NVD CVE corpus for supported fingerprints, enriches matches with CISA KEV and FIRST EPSS priority data, caches external results for 24 hours, and marks matches for applicability review. |
| Device fingerprinting | Uses bounded network evidence such as open services, manufacturer information, and mDNS data to suggest a device classification. |
| Alert rules | Creates per-device rules for consecutive failures and high latency. Alerts persist, can be acknowledged, and resolve automatically after recovery. |
| Alert history | Provides a searchable operational record of active, acknowledged, and resolved alert events. |
| Maintenance windows | Suppresses expected monitoring noise during approved maintenance periods without deleting monitoring configuration. |

### Host telemetry and anomaly detection

| Function | What it does |
|---|---|
| Local host metrics | Collects CPU, memory, and system-disk utilization for loopback devices. |
| Remote host agent | Accepts authenticated CPU, memory, and disk samples from enrolled Windows or Linux collectors. Each enrollment has a one-time token; only its SHA-256 digest is stored. |
| Agent health | Derives waiting, reporting, delayed, and offline states from the collector's reporting interval. A previously reporting agent that becomes offline raises one persistent alert and resolves it when reporting resumes. |
| SNMP v2c polling | Reads the standard system description, name, location, uptime, and interface-count OIDs. Community values stay in environment variables and are not stored in SQLite. |
| Local anomaly detection | Builds a per-device baseline after at least 21 samples using the median and median absolute deviation, then flags unusual latency, CPU, memory, or disk values. |

Anomaly results are operational indicators, not diagnoses. Aegis performs this analysis locally and does not send telemetry to an external AI provider.

### Network visibility and defensive security

| Function | What it does |
|---|---|
| Local network discovery | Detects the active physical Windows adapter, presents its network for confirmation, and probes at most one local `/24`. Existing addresses are skipped and available MAC addresses are imported. |
| Network change reset | Remembers the last discovered subnet in the browser. When the connected subnet changes, the administrator is offered an exact-phrase reset before discovery so identical private IP ranges from different labs are not mixed. The same reset is available under **More actions**. |
| Network topology | Infers logical placement from VLAN and subnet data and supports confirmed `UPLINK`, `CONNECTS TO`, `ROUTES TO`, and `MANAGES` relationships. |
| Attack-surface assessment | Checks the ranked top 1,000 TCP ports, identifies exposed management, cleartext, database, and infrastructure services, runs time-bounded version detection, inspects HTTP security headers and TLS posture, correlates supported fingerprints with NVD CVEs, and prioritizes candidates with CISA KEV and FIRST EPSS evidence. |
| Assessment comparison | Compares the two latest assessments, calculates a capped 0–100 exposure score, and separates new, persistent, and resolved findings. Informational evidence does not increase the score. |
| Passive attack paths | Correlates stored assessment results with groups, subnets, criticality, and remote-access services to prioritize possible paths between registered assets. It sends no additional traffic. |
| Controlled packet capture | Captures packet metadata for 1–30 seconds and 1–1000 packets. It stores timestamps, addresses, protocol, ports, and length—never packet payloads or PCAP files. |
| Remote diagnostics | Dispatches only fixed, administrator-approved diagnostic job types to explicitly enabled agents. Jobs are device-bound, parameter-bounded, expire after 15 minutes, and cannot contain arbitrary commands. |
| Wireless status | Reports the local Aegis host's wireless-adapter state without collecting Wi-Fi keys or handshakes. |

Attack-surface findings and passive attack paths are prioritization evidence, not proof of exploitability. Confirm important results against firewall policy, network design, patch records, and approved validation procedures.

### Security workbench

The administrator-only **Security workbench** consolidates defensive investigation tools without turning Aegis into a credential or interception suite.

| Tool | What it does |
|---|---|
| Decoder and encoder | Converts Base64, hexadecimal, and URL components entirely in the browser. Input is not sent to the API. |
| Integer and bitwise converter | Converts practical-size integers between decimal, hexadecimal, binary, and octal and performs signed AND, OR, XOR, NOT, left-shift, and right-shift operations locally. |
| Secure password generator | Generates random 16-, 20-, 24-, or 32-character passwords with browser cryptographic randomness and supports masked display and copying. |
| Password-strength guide | Evaluates a disposable example locally, displays a four-stage strength meter, and explains how length, character variety, repetition, sequences, and predictable words affect the result. Real passwords should never be entered. |
| Registered inventory search | Searches known assets and their recorded details without scanning arbitrary targets. |
| Capture review | Summarizes stored controlled packet-capture metadata and links to the capture workflow. |
| Traceroute | Runs a validated trace of at most 12 hops and 20 seconds to a selected registered device. |
| Configuration review | Highlights incomplete inventory records and summarizes stored candidate attack paths without extracting device configurations. |
| DNS query | Performs validated forward and reverse DNS lookups without constructing shell commands from user input. |
| Network CLI | Runs administrator-only Nmap TCP scans against registered devices with Fast, Fast version, Detailed (`-sV --version-light`), and Aggressive (`-sV --version-all`) profiles. It also provides local ARP discovery, the host neighbor table, HTTP(S) `curl`, and DNS queries with optional literal line filtering. Commands use typed arguments, profile-specific timeouts, and capped output without invoking a shell. |
| PowerShell TCP test | Tests up to 128 TCP ports on one registered device with PowerShell 7 `Test-Connection -TcpPort`; Windows PowerShell falls back to `Test-NetConnection -Port`. Targets and ports are passed as validated data rather than command text. |
| Assessment playbooks | Queues a persistent four-step assessment for one registered target: PowerShell TCP reachability, traceroute, Nmap top-1,000 attack-surface and CVE correlation, then DNS identity. Fast, Detailed, and Aggressive profiles control probe depth. The workbench shows durable per-step progress and output, and cancellation takes effect after the active command finishes. |

Aegis does not provide password or hash cracking, credential harvesting, ARP poisoning, man-in-the-middle routing, Wi-Fi key recovery, router-configuration theft, payload capture, exploit execution, brute force, or arbitrary remote command execution.

### Reports and observability

| Function | What it does |
|---|---|
| Availability reports | Produces date-bounded availability, outage, and latency summaries from stored monitoring results. |
| Scheduled reports | Generates local availability-report files on an administrator-defined schedule and keeps a downloadable report history. |
| Prometheus metrics | Exposes authenticated OpenMetrics data for device state, latency, unresolved alerts, service health, host utilization, and scheduler state. |
| Embedded Grafana | Displays the provisioned **Aegis Infrastructure Overview** dashboard inside the application with device, alert, service, latency, and resource panels. |
| System status | Checks application readiness, database access, supporting tools, configured secrets, scheduler state, and integration availability from one administrator view. |

Prometheus authenticates with a bearer token stored in `secrets/prometheus_token.txt`. Grafana is provisioned automatically and its anonymous Viewer access is bound to the local host by default; administrative Grafana changes still require its administrator account.

### Notifications, administration, and resilience

| Function | What it does |
|---|---|
| Notification channels | Sends alert notifications through email, Microsoft Teams, or Twilio SMS. Administrators can configure non-secret settings, send tests, inspect delivery history, and retry failures. |
| Delivery control | Queues each alert/channel pair once and retries failed automatic deliveries at most three times. Integration secrets remain in environment variables. |
| User administration | Creates local users, assigns roles, enables or disables accounts, resets passwords, and revokes sessions when access changes. |
| Audit log | Records authenticated write operations with actor, role, method, route, response status, source address, and timestamp. Request bodies, passwords, and tokens are excluded. |
| Automation center | Manages maintenance windows, correlated incidents, allowlisted incident diagnostics, scheduled reports, configuration baselines, agent-version visibility, and advisory health summaries. |
| Configuration drift | Compares recorded device information with stored baselines and surfaces material changes for review. |
| Health summary | Produces a built-in operational summary. An optional local Foundry model can rewrite that summary when explicitly configured; the built-in result remains the fallback. |
| Backups | Creates verified SQLite snapshots at startup and on schedule, supports manual creation and verification, and keeps the configured number of recent backups. |
| History retention | Previews aged monitoring data before deletion, requires an explicit confirmation phrase, and creates a verified safety backup before cleanup. Configuration and identity records are preserved. |

Network-changing automations—automatic discovery, service discovery, and paced defensive assessment—remain disabled until an administrator explicitly enables them.

## Authentication and roles

The first browser visit creates the initial local administrator. Passwords must contain at least 12 characters and are hashed with scrypt using a unique random salt. Sign-in creates a random 12-hour opaque session token; only its SHA-256 digest is stored in SQLite, and sign-out revokes it.

| Role | Access |
|---|---|
| Administrator | Full monitoring and reporting access plus security tools, packet capture, automation, notification settings, backups, system status, audit events, and user management. |
| Operator | Device metadata, groups, basic monitoring, alerts, and topology management without active security testing or account controls. |
| Viewer | Read-only dashboards, device details, histories, statistics, charts, and stored findings. |

The API enforces permissions independently of the interface. Aegis prevents the last active administrator from being disabled or demoted. Disabling an account or resetting its password revokes existing sessions.

## Architecture

Aegis intentionally uses a small, inspectable architecture.

| Component | Technology | Responsibility |
|---|---|---|
| Web interface | React and Vite | Responsive dashboard, device workflows, reporting, administration, and browser-local utilities. |
| Application API | FastAPI and Pydantic | Authentication, validation, authorization, monitoring workflows, reporting, and administrative APIs. |
| Data store | SQLite and SQLAlchemy | Inventory, users, sessions, monitoring history, alerts, audit records, automation state, and configuration. |
| Scheduler and playbook runner | Bounded in-process workers | Periodic monitoring plus a single-worker queue for persistent administrator-requested security assessments. |
| Agent ingress | Separate FastAPI process in hybrid mode | Narrow endpoint surface for remote metrics and diagnostic job exchange. |
| Observability | Prometheus and Grafana | Metric retention, querying, and provisioned infrastructure dashboards. |

SQLite is appropriate for a single Aegis application instance. The Kubernetes manifests intentionally run one backend replica; horizontal backend scaling requires migration to a shared database such as PostgreSQL and coordination of scheduled work.

## Requirements

- Python 3.12 or newer
- Node.js 20.19 or newer and npm
- PowerShell on Windows, or an equivalent terminal for native development
- Docker Desktop for Prometheus, Grafana, or the complete container stack
- Npcap for Windows packet metadata capture
- Nmap is optional for top-port discovery, which has a host-side socket fallback. Nmap is required for Fast (`-sV --version-intensity 0`), Detailed (`-sV --version-light`), and Aggressive (`-sV --version-all`) fingerprints and high-confidence CPE-based CVE correlation.
- `arp-scan`, `curl`, `dig` (`dnsutils`), `iproute2`, and `traceroute` when running the backend directly on Linux; the backend container installs these packages

## Installation

### Prepare the application

From the repository root:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

cd ..\frontend
npm.cmd install
cd ..
```

Create the local Prometheus token used by hybrid and container deployments:

```powershell
New-Item -ItemType Directory -Force secrets
$tokenBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($tokenBytes)
$rng.Dispose()
($tokenBytes | ForEach-Object { $_.ToString("x2") }) -join "" |
  Set-Content -NoNewline secrets/prometheus_token.txt
```

### Recommended Windows hybrid deployment

Hybrid mode keeps the FastAPI application, Windows-aware discovery, host metrics, and agent ingress native while running a network-toolbox sidecar, Prometheus, and Grafana in Docker. When Nmap or another supported CLI is missing from Windows, the API executes it inside the toolbox container without invoking a shell:

```powershell
.\start-hybrid.ps1
```

The launcher verifies the frontend, API, agent ingress, network toolbox, Grafana, and Prometheus before returning. If Docker Desktop is unavailable, it starts the core Aegis services without the toolbox or observability containers. Runtime logs are written to `logs/`.

Stop the stack without deleting data:

```powershell
.\stop-hybrid.ps1
```

If script execution is restricted for the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

### Native development

Start the API from one PowerShell window:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload
```

Start the interface from another:

```powershell
cd frontend
npm.cmd run dev
```

Native development uses `http://127.0.0.1:8000` for the API and `http://127.0.0.1:5173` for the interface. The SQLite database is created as `backend/monitoring.db` and is ignored by Git.

### Fully containerized deployment

Create the Docker environment file:

```powershell
Copy-Item .env.docker.example .env
```

Set a unique `GRAFANA_ADMIN_PASSWORD` in `.env`, ensure `secrets/prometheus_token.txt` exists, and start the stack:

```powershell
docker compose up --build -d
docker compose ps
```

Stop containers while preserving named volumes:

```powershell
docker compose down
```

Do not add `-v` unless you intentionally want to remove Aegis, Prometheus, and Grafana volume data.

### Service addresses

| Service | Hybrid mode | Container or native development |
|---|---|---|
| Aegis interface | `http://127.0.0.1:5173` | `http://127.0.0.1:5173` |
| API documentation | `http://127.0.0.1:8001/docs` | `http://127.0.0.1:8000/docs` |
| Agent ingress | `http://<host-LAN-IP>:8002` | Not included in the standard single-process development command |
| Grafana | `http://127.0.0.1:3000` | `http://127.0.0.1:3000` with Docker |
| Prometheus | `http://127.0.0.1:9090` | `http://127.0.0.1:9090` with Docker |

On first sign-in, follow the setup screen to create the initial administrator.

## Remote agent deployment

Enroll a remote device from its Aegis device page and copy the one-time token. In hybrid mode, run the firewall helper once as Administrator on the Aegis host; it limits inbound agent access to the active physical subnet:

```powershell
.\configure-agent-access.ps1
```

On a remote Windows host, copy the `agent` directory and run:

```powershell
.\install-windows.ps1 -ServerUrl "http://AEGIS-LAN-IP:8002"
```

The installer prompts securely for the token when it is omitted, stores private configuration under `%ProgramData%\AEGIS Agent`, submits a verification sample, and registers an auto-restarting startup task. Enable the fixed diagnostic job set only when it is required:

```powershell
.\install-windows.ps1 -ServerUrl "http://AEGIS-LAN-IP:8002" -EnableDiagnostics
```

Test connectivity and enrollment from the remote host:

```powershell
& "$env:ProgramData\AEGIS Agent\test-agent.ps1"
& "$env:ProgramData\AEGIS Agent\test-agent.ps1" -SubmitSample
```

For manual Windows or Linux execution:

```powershell
cd agent
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:AEGIS_SERVER_URL = "http://AEGIS-LAN-IP:8002"
$env:AEGIS_AGENT_TOKEN = "PASTE_ONE_TIME_TOKEN"
$env:AEGIS_AGENT_DIAGNOSTICS_ENABLED = "false"
.\.venv\Scripts\python.exe aegis_agent.py
```

Do not expose agent ingress directly to the public Internet. Use authenticated HTTPS and network-layer access controls for production or routed deployments. See [Remote diagnostics](docs/REMOTE_DIAGNOSTICS.md) for job types and operating boundaries.

## Configuration

Backend settings can be supplied through the process environment or `backend/.env`. Secrets should remain in the process environment or dedicated secret files and must not be committed.

| Variable | Default | Purpose |
|---|---:|---|
| `DATABASE_URL` | `sqlite:///./monitoring.db` | SQLAlchemy database connection. |
| `PING_TIMEOUT_SECONDS` | `1` | Per-device reachability timeout. |
| `AEGIS_MONITOR_CHECK_WORKERS` | `32` | Maximum concurrent reachability probes for manual batch checks. Database writes remain sequential. |
| `MONITOR_INTERVAL_SECONDS` | `60` | Scheduler interval in seconds. |
| `SCHEDULER_ENABLED` | `true` | Enables scheduled monitoring at application startup. |
| `AEGIS_BACKUP_ENABLED` | `true` | Enables startup and scheduled database backups. |
| `AEGIS_BACKUP_INTERVAL_HOURS` | `24` | Time between automatic backups. |
| `AEGIS_BACKUP_KEEP_COUNT` | `14` | Number of newest backups retained. |
| `AEGIS_BACKUP_DIRECTORY` | `./backups` | Backup storage directory. |
| `AEGIS_HISTORY_RETENTION_DAYS` | `90` | Age threshold used by retention preview and cleanup. |
| `AEGIS_REPORT_DIRECTORY` | `./reports` | Generated report storage directory. |
| `AEGIS_ATTACHMENT_DIRECTORY` | `./attachments` | Device attachment storage directory. |
| `AEGIS_PROMETHEUS_TOKEN` | unset | Direct bearer token for `/metrics`. |
| `AEGIS_PROMETHEUS_TOKEN_FILE` | unset | File containing the Prometheus bearer token. |
| `AEGIS_SNMP_COMMUNITY` | unset | Read-only SNMP community used by every configured device. The value is never stored in SQLite. |
| `AEGIS_SMTP_PASSWORD` | unset | SMTP password for email delivery. |
| `AEGIS_TEAMS_WEBHOOK_URL` | unset | Microsoft Teams workflow webhook. |
| `AEGIS_TWILIO_ACCOUNT_SID` | unset | Twilio account identifier. |
| `AEGIS_TWILIO_AUTH_TOKEN` | unset | Twilio authentication secret. |
| `AEGIS_ALLOW_PUBLIC_LAN_DISCOVERY` | `false` | Allows discovery on the bounded `/24` of the active physical adapter when its address is not private. |
| `AEGIS_DISCOVERY_PING_WORKERS` | `64` | Maximum concurrent ICMP probes during bounded network discovery. |
| `AEGIS_DISCOVERY_PING_TIMEOUT_SECONDS` | `0.4` | Per-address ICMP timeout during discovery. |
| `AEGIS_DISCOVERY_MDNS_TIMEOUT_SECONDS` | `2` | Passive mDNS collection window during discovery. |
| `NVD_API_KEY` | unset | Optional NVD API key for a higher request rate during product/version CVE correlation. The key is sent only to `services.nvd.nist.gov`. |
| `AEGIS_FOUNDRY_LOCAL_URL` | unset | Optional loopback or private Foundry Local-compatible endpoint for health-summary wording. |
| `AEGIS_FOUNDRY_LOCAL_MODEL` | unset | Model identifier used with the optional local summary endpoint. |
| `VITE_GRAFANA_URL` | `http://127.0.0.1:3000` | Browser-visible Grafana base URL set at frontend build time. |
| `VITE_GRAFANA_DASHBOARD_URL` | provisioned dashboard | Optional complete embedded-dashboard URL set at frontend build time. |

Notification recipients, SMTP server details, ports, sender addresses, TLS choices, and channel enablement are non-secret settings managed in the administrator interface. Restart the backend after changing secret environment variables.

## Data, backup, and restoration

Native mode stores the database, reports, backups, and attachments under `backend/` by default. Docker stores them in the `aegis_data` named volume; Prometheus and Grafana use separate named volumes.

To restore a downloaded or local backup on Windows:

```powershell
.\stop-hybrid.ps1
.\restore-backup.ps1 -BackupFile ".\backend\backups\aegis-YYYYMMDD-HHMMSS-abcdef.db"
.\start-hybrid.ps1
```

The restore script refuses to proceed while the native API port is listening, verifies SQLite integrity and required Aegis tables, and preserves the previous database as `backend/backups/pre-restore-<timestamp>.db` before replacement.

Back up the attachment directory together with the database when moving an installation. Attachment metadata is stored in SQLite, while file contents are stored separately.

## API

Interactive OpenAPI documentation is available at `/docs`. The API is organized into authentication, devices, monitoring, alerts, discovery, services, host metrics, remote agents, SNMP, inventory health, reports, topology, notifications, reliability, automation, system status, and security operations.

The health endpoint, first-run setup, login, API documentation, and authenticated agent submission endpoints are available without a browser session. Other application endpoints require `Authorization: Bearer <session-token>`. The Prometheus endpoint uses its own bearer token.

## Testing and verification

Run the backend test suite:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest
```

Tests use temporary SQLite databases and do not modify the development database.

Create a production frontend build:

```powershell
cd frontend
npm.cmd run build
```

## Kubernetes deployment

Kustomize manifests are provided in `deploy/kubernetes`. Build and publish the backend and frontend images, replace the placeholder image references, and create the untracked secret manifest:

```powershell
Copy-Item deploy/kubernetes/secret.example.yaml deploy/kubernetes/secret.yaml
```

Replace every placeholder, configure the intended ingress hostname and TLS, then deploy:

```powershell
kubectl apply -k deploy/kubernetes
kubectl -n aegis get pods,svc,pvc,ingress
```

Before production use, configure secret encryption at rest, restrict secret RBAC, use a managed secret provider where possible, pin container images by digest, and back up all persistent volumes.

## Additional documentation

- [Automation behavior and safety controls](docs/AUTOMATION.md)
- [Remote diagnostics operating guide](docs/REMOTE_DIAGNOSTICS.md)
