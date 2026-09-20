# Aegis learning-lab security assessment

Assessment date: 2026-09-09

Scope: repository-wide static review of the Aegis application and its local, hybrid, Docker, observability, and agent paths. The intended deployment is a single-user private learning lab. Active security-testing actions remain administrator-only, while target address classification is intentionally unrestricted for explicitly selected or registered lab work.

## Findings and disposition

| Severity | Finding | Disposition |
|---|---|---|
| High | SNMP device configuration could select any process environment-variable name, allowing an authorized non-admin user to make the backend use another secret as an SNMP community. | Fixed. SNMP accepts only `AEGIS_SNMP_COMMUNITY`, rejects incompatible persisted references, and the entire SNMP router requires an administrator. |
| Medium | Request limits trusted `Content-Length`, so a chunked request could bypass the main API and agent-ingress body caps. | Fixed. Both applications now enforce their limits while consuming and replaying ASGI request chunks. |
| Medium | SMTP STARTTLS relied on an implicit TLS context. | Fixed. STARTTLS now receives a default certificate-verifying SSL context explicitly. |
| Low | Common-port scanning and fingerprinting were writable operator actions. | Fixed. Discovery import, service-probe creation and execution, common-port scans, fingerprinting, SNMP, vulnerability assessment, packet capture, remote diagnostics, and the Security Workbench are administrator-only. |
| Medium | An operator could rotate an agent enrollment token and use the agent diagnostic channel to read returned diagnostic evidence. | Accepted for this single-user deployment. Do not create operator accounts. If roles are introduced later, split enrollment management from diagnostic-result access before adding users. |
| Medium | Hybrid agent ingress was reachable over the LAN and sent bearer credentials over plain HTTP. | Fixed for the single-user deployment. Agent ingress now binds to loopback, the launcher rejects non-loopback Aegis listeners, and the LAN firewall setup helper was removed. |
| Medium | A privileged scheduled-task update can inherit files from a pre-existing writable agent installation tree. | Hardened on 2026-09-17: trusted owner/ACL/ancestor and reparse verification precedes writes/execution; new roots use a protected creation descriptor. Writable legacy trees are rejected, safe upgrades preserved. Full elevated fresh-install/SYSTEM and upgrade validation remains required. |

The automated source scan had partial coverage, so this is evidence from the reviewed paths rather than a claim that every possible vulnerability is absent.

## Network testing changes

The administrator Security Workbench now exposes:

- Nmap TCP connect scans with optional light service detection and a validated list of up to 1024 ports.
- Existing bounded traceroute against a registered device.
- Local `arp-scan --localnet` with an optional validated interface name. Native Windows uses the existing bounded Npcap/Scapy ARP discovery when the binary is absent.
- The Windows neighbor table through `Get-NetNeighbor`, or `ip neigh show` on Linux.
- HTTP and HTTPS curl requests, including an opt-in switch for untrusted lab certificates.
- `dig` queries for a fixed set of DNS record types. Native Windows falls back to `nslookup` when `dig` is absent.
- Three bounded `fping` probes against one registered device.
- WhatWeb light-profile fingerprinting and a 45-second non-interactive Nikto assessment against a validated endpoint on one registered device.
- `sslscan` with Heartbleed probing disabled and an OpenSSL certificate/session inspection with closed stdin.
- Anonymous-only `smbclient` service listing and fixed Nmap scripts for SMB protocol and signing posture. No credential fields or arbitrary NSE scripts are accepted.
- `host` lookups and DNSRecon standard-record enumeration. DNSRecon brute force, reverse-range, cache-snooping, and wordlist modes are not exposed.
- Case-insensitive literal line filtering for every command result, providing grep-like output without invoking a shell.

Commands run as argument arrays with `shell=False`. Inputs are typed and validated, command durations are capped, curl redirects remain HTTP(S)-only, curl transfer rate and size are bounded, and returned output is capped at 100 KB. The expensive-operation rate-limit bucket applies to every Security Workbench command endpoint.

The backend container installs the core monitoring tools. Hybrid mode also starts a read-only network-toolbox sidecar with only the capabilities needed for raw network discovery; it contains Nmap, Nuclei, arp-scan, Avahi, curl, DNS utilities, DNSRecon, fping, Netdiscover, Nikto, OpenSSL, smbclient, SNMP CLI tools, sslscan, tcpdump, tshark, traceroute, and WhatWeb. The native API delegates an allowlisted missing binary through `docker exec` without invoking a shell. Windows continues to use Npcap/Scapy for physical-LAN ARP discovery because Docker Desktop bridge networking does not expose the physical layer-2 segment reliably.

Continuous Zeek or Suricata collection, OpenVAS or Nessus scanner orchestration, and Lynis or osquery host audits are explicit integration boundaries. They need dedicated sensor/scanner services, credentials and lifecycle management, or a host-agent result model. Aegis does not run them inside the toolbox and misrepresent container results as host findings. NetExec and credentialed SMB enumeration remain outside the product boundary.

## Infrastructure observations

- Docker publishes the API, UI, Prometheus, and Grafana only on loopback. Nginx proxies `/api/` to the backend, and production frontend builds use that same-origin route.
- Hybrid mode binds the interface, API, agent ingress, Grafana, and Prometheus to loopback. The launcher verifies each listener and fails if an Aegis service is reachable through a non-loopback address.
- SQLite and the in-process schedulers fit the single-instance learning-lab deployment. Multiple backend replicas would require shared storage and scheduler coordination.
- Nmap can assess any valid IP already registered in inventory. The scan policy no longer rejects public, documentation, loopback, or non-RFC1918 addresses solely by address class; the administrator remains responsible for selecting systems they control.
- Device inventory is keyed by IP address. To avoid mixing unrelated devices that reuse common private addresses, discovery remembers the last scanned subnet and offers an administrator-only full device reset when the subnet changes. The reset requires the exact phrase `CLEAR ALL DEVICES` and cascades through monitoring history, alerts, scans, notes, agent enrollments, topology links, and attachment records; stored attachment blobs are also removed.

## Repository hygiene

- No high-confidence private-key, cloud-provider token, API-key, or live credential patterns were found in the current tracked/untracked repository candidates or across all 39 Git commits.
- No database, environment, log, private-key, or generated build artifact is tracked. Local `.env` files, the Prometheus token, SQLite databases, logs, backups, reports, virtual environments, frontend dependencies, and build output are covered by `.gitignore`.
- `deploy/kubernetes/secret.example.yaml` contains explicit replacement placeholders only. Authentication tests contain a repeated fake password used solely for isolated temporary databases.
- The obsolete, unused `@vitejs/plugin-react` dependency was removed. Deprecated frontend transitive packages remain under the actively used ExcelJS export dependency; `npm audit` reports no known vulnerabilities.
- The curl workbench field no longer starts with an external URL, preventing an accidental outbound request from the default form state.

## Verification

- Python bytecode compilation completed successfully.
- The complete backend pytest suite passed.
- The Vite production build completed successfully. It retains the existing warning about the large ExcelJS chunk.
