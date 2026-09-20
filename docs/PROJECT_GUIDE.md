# Aegis project guide

This guide provides the shortest useful mental model for operating, demonstrating, and extending Aegis.

## What Aegis is

Aegis is a self-hosted infrastructure monitor with bounded defensive assessment tools. It answers three different questions:

1. **What do I own?** Device inventory, identity, grouping, ownership, and topology.
2. **Is it healthy?** Reachability, service checks, telemetry, alerts, and availability history.
3. **What deserves investigation?** Network evidence, service fingerprints, configuration observations, CVE candidates, and exposure paths.

Monitoring and assessment are deliberately separate. Monitoring runs repeatedly and should be low-noise. Assessment is an administrator-requested investigation that creates auditable evidence.

## The five-stage workflow

```text
1. Register → 2. Observe → 3. Assess → 4. Prioritize → 5. Verify
```

### 1. Register

Add an authorized device manually, import a DHCP lease, or discover the confirmed local `/24`. A registered device becomes the boundary for monitoring and assessment operations.

### 2. Observe

Run reachability and service checks. Aegis stores results, calculates availability, creates state transitions, and raises configured alerts. Host agents and SNMP add authenticated operating-system or network-device context.

### 3. Assess

Use **Security workbench → Assessment → Automated workflow** for a repeatable sequence:

1. Bounded TCP reachability checks.
2. A bounded traceroute.
3. Adaptive Nmap discovery, service detection, mDNS enrichment, web/TLS checks, Nuclei checks, and CVE correlation.
4. DNS identity checks.

Use **Manual checks** only when one focused question is enough—for example, whether TCP/443 is reachable or what certificate a TLS endpoint presents.

### 4. Prioritize

Aegis combines stored evidence with asset criticality and network context. CVE candidates can be enriched with:

- **CVSS:** technical severity.
- **CISA KEV:** whether exploitation is known and catalogued.
- **FIRST EPSS:** estimated probability of exploitation activity.

These signals help order work; they do not replace applicability validation.

### 5. Verify

Confirm the detected product and version, check vendor backports and compensating controls, remediate through approved change control, and rerun the same assessment. The comparison view separates new, persistent, and resolved evidence.

## Screen map

| Screen | Use it for | Do not confuse it with |
|---|---|---|
| Dashboard | Fleet health, alerts, services, agents, topology, and inventory quality | A vulnerability scanner |
| Device record | Everything known about one asset | Live device administration |
| Assessment | A complete saved investigation or one bounded manual check | Continuous monitoring |
| CVE mirror | Updating local NVD matching data | Scanning hosts or proving exploitation |
| Exposure review | Reviewing stored findings and candidate paths | Sending new traffic |
| Wireshark | Docker toolbox packet analysis, PCAP import/export, and legacy metadata history | Direct access to Windows Wi-Fi/Ethernet, all LAN conversations, automatic TLS decryption, or automatic PCAP-to-CVE matching |
| Observability | Long-range Prometheus and Grafana trends | The operational source of truth for inventory |
| System status | Aegis component readiness | Target-device health |

## Important terms

The [Wireshark guide](WIRESHARK.md) explains startup, capture filters, storage and Docker network visibility. Capture before running the assessment to see its network exchanges; Wireshark is a protocol analyzer, not the CVE mirror or a replacement for service identification.

| Term | Meaning in Aegis |
|---|---|
| Device | A registered, authorized target and its asset record. |
| Check | One monitoring observation, such as ping, TCP, HTTP, HTTPS, SNMP, or telemetry. |
| Alert | A persisted operational condition created by configured rules. |
| Assessment | An administrator-requested, bounded sequence that saves evidence. |
| Finding | Evidence that deserves review. It is not automatically a confirmed vulnerability. |
| CPE | A standardized product identifier used for higher-confidence CVE matching. |
| CVE candidate | An NVD record whose product and version applicability appears to match detected evidence. |
| Attack path | A passive prioritization hypothesis derived from stored evidence and network context. |

## How the CVE mirror fits

The mirror imports official NVD JSON 2.0 feeds into local CVE and CPE applicability tables.

```text
Nmap + WhatWeb/banner/NSE product/version/CPE
          ↓
Local vendor + product lookup
          ↓
NVD version-boundary evaluation
          ↓
CVSS-ranked CVE candidates
          ↓
CISA KEV and FIRST EPSS prioritization
```

An exact CPE match has higher confidence than a product/version keyword search. When Aegis lacks an exact CPE or a complete local baseline, it can fall back to the public NVD API. A match still requires operator validation because version fingerprints can be wrong and vendors may backport patches without changing the advertised version.

The assessment reports **CVE evidence coverage** separately from match count. `0 CVE matches` is useful only for services that were CVE-ready (both product and version were identified). Modern Windows SMB and RPC services commonly suppress version details from anonymous network probes; use `smb-os-discovery` evidence when available, then confirm the build through the Aegis agent, authenticated inventory, or an imported SBOM. Aegis intentionally skips correlation instead of matching a CVE from a port number alone.

### Comparing Nmap results with Kali

Aegis's managed toolbox includes Nmap 7.991 and the matching service-probe database. It uses SYN discovery (`-sS`) and TCP-connect application fingerprinting (`-sT`); a local host-side executable also uses TCP connect. Aggressive means `-sV --version-all` (all version probes), not `-A`. Detailed and Aggressive service detection have 90/180-second host budgets; a timeout is incomplete evidence, not a clean result.

CLI results show the engine, execution context and exact commands. Assessment step 3 stores the same scanner provenance under **Scanner version and execution context**. For a meaningful Kali comparison, use the same version/probe database, target, ports, scan technique and intensity. Also check the source IP: Docker-managed routing/NAT and the Kali VM network can trigger different firewall responses. A service name with `?` and no product/version is a tentative identification, not enough evidence for an exact CVE match.

See [Nmap parity troubleshooting](NMAP_PARITY.md) for equivalent Kali/Docker commands and probe-database checksum checks.

Use **Full** once to build the baseline. Use **Modified** for routine refreshes. A cancelled refresh does not erase the last complete baseline.

## Runtime map

| Component | Default location | Responsibility |
|---|---|---|
| React/Vite frontend | Native Windows process in hybrid mode | User interface and browser-local utilities. |
| FastAPI backend | Native Windows process in hybrid mode | Authentication, workflows, validation, storage, and native host integration. |
| Network toolbox | Docker | Nmap, Nuclei, Avahi, TLS, web, SMB, DNS, and related bounded tools. |
| SQLite | `backend/monitoring.db` | Operational data plus the rebuildable local CVE mirror. |
| Prometheus | Docker, loopback port 9090 | Metrics collection and time-series queries. |
| Grafana | Docker, loopback port 3000 | Provisioned read-only infrastructure dashboard. |
| Agent ingress | Native Windows process in hybrid mode | Narrow authenticated endpoint for remote collectors. |

## Result interpretation

- `ONLINE` means the latest configured reachability check succeeded; it does not mean every service is healthy.
- `filtered` means a probe did not receive a definitive response. It is not the same as `closed`.
- An open port identifies a listening network path, not necessarily a vulnerability.
- A CVE match is a candidate based on fingerprint and NVD applicability data.
- `CVE-ready` means product and version evidence exists; it does not mean a CVE was found.
- An unresolved service is outside the CVE result's coverage until version evidence is collected.
- A Nuclei match is stronger template evidence, but important results still require validation.
- A candidate attack path is a prioritization aid, not proof of lateral movement.

## Quick troubleshooting order

1. Open **Administration → System status**.
2. Confirm the API health endpoint and frontend are reachable.
3. Confirm `aegis-network-tools` is healthy when a Docker-backed tool is required.
4. Check whether the target is registered and active.
5. Use **Fast** assessment before increasing depth.
6. Treat an all-filtered result as a possible firewall, routing, rate-limit, or IDS signal—not automatically as no services.
7. Run `.\verify-prototype.ps1` from the repository root before demonstrations or releases.

## Data and safety boundaries

- Active tools accept registered targets and fixed typed options.
- Assessment actions are authenticated and audited.
- Packet observations store metadata, not payloads or PCAP files.
- Normal backups omit rebuildable CVE mirror rows to remain small.
- Secrets stay in ignored environment or secret files and must not be committed.
- Aegis does not perform credential harvesting, password cracking, arbitrary remote command execution, or uncontrolled exploitation.
