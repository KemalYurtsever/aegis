# Aegis prototype improvement roadmap

The current build is suitable for an internal first prototype. The following work provides the highest return before a wider pilot or production deployment.

## Priority 0 — before a wider pilot

### 1. Authenticated browser end-to-end tests

**Why:** Component/source tests and API tests cover behavior, but they do not exercise sign-in, navigation, target selection, live progress, cancellation, and result rendering together in a real browser.

**Success criteria:** A repeatable test creates an isolated administrator, registers a fixture device, runs mocked assessment and CVE-refresh jobs, verifies progress and terminal states, and checks desktop plus mobile layouts.

### 2. Move the rebuildable CVE mirror into a separate SQLite database

**Why:** The NVD corpus dominates the operational database size. Separation would make operational integrity checks, migrations, restores, and support bundles faster while preserving local lookup performance.

**Success criteria:** Core backups and database checks never read CVE rows; mirror deletion or replacement cannot remove inventory; a restored core database clearly reports that the mirror needs rebuilding.

### 3. Add scheduled incremental CVE refresh

**Why:** The mirror currently supports safe manual `Modified` refreshes, but freshness depends on an administrator remembering to start them.

**Success criteria:** Administrators can choose a local schedule, see the last successful source timestamp, receive one actionable failure notification, and retry without invalidating the completed baseline.

### 4. Add a real integration-test target

**Why:** Tool availability tests prove binaries start, but repeatable expected network results need a deterministic, synthetic integration fixture.

**Success criteria:** A local container fixture exposes known TCP, HTTP, HTTPS, DNS, and SMB test states; CI and `verify-prototype.ps1` compare normalized Aegis results with expected evidence.

### 5. Finish contextual help and glossary coverage

**Why:** The workbench now explains its main workflow, but device findings, attack-path scoring, agent states, and observability panels still assume domain knowledge.

**Success criteria:** Every score and non-obvious state has a concise definition at its point of use, with links to the project guide for deeper explanation.

## Priority 1 — reliability and scale

### 6. Externalize durable background work

Move assessment, Nmap, CVE synchronization, report, and backup jobs from in-process workers to a recoverable queue before running multiple API instances. Preserve cancellation, audit ownership, and restart recovery.

### 7. PostgreSQL deployment profile

Keep SQLite as the simple single-node default, but add PostgreSQL migrations and deployment guidance for concurrent operators, multiple workers, or larger histories.

### 8. Performance budgets and retention telemetry

Track API latency, dashboard payload size, database growth, assessment duration, and frontend bundle sizes. Surface retention projections before monitoring history becomes operationally expensive.

### 9. Package and configuration correlation

Use authenticated agent package inventory or imported SBOMs to complement network fingerprints. Keep network-based and authenticated evidence visibly separate so confidence is not overstated.

### 10. Accessibility and localization pass

Run keyboard, screen-reader, contrast, reduced-motion, and responsive audits. Extract operator-facing strings so Turkish and English interfaces can be maintained without duplicating components.

## Priority 2 — optional integrations

- Dedicated Zeek or Suricata sensor ingestion for continuous passive monitoring.
- OpenVAS/Greenbone or Nessus result import without embedding those scanners in the application container.
- Signed release artifacts, SBOM publication, dependency scanning, and reproducible release notes.
- Exportable assessment reports with evidence provenance and remediation ownership.
- Multi-site inventory federation after shared-database and worker coordination are complete.

## Explicit non-goals for the prototype

- Arbitrary command execution on agents or targets.
- Credential collection, password cracking, or reusable exploit delivery.
- Treating CVE, Nuclei, or attack-path evidence as automatic proof of compromise.
- Horizontal backend scaling while using a single local SQLite file.
