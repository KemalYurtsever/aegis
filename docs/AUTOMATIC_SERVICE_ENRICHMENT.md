# Automatic service evidence

New assessments select tools from the discovered **protocol**, not only the port.
Conventional ports are a fallback when Nmap has not identified a protocol. Rerun
saved assessments to collect this evidence; existing results are not modified.

In hybrid mode, these tools run in the managed network toolbox. The full-stack
backend image installs WhatWeb, OpenSSL and sslscan locally so its automatic
HTTP/TLS enrichment does not require a Docker socket or a host-side toolbox.
Rebuild the backend image after upgrading. Scanner provenance identifies the
actual Nmap version used by each deployment.

```text
TCP discovery → Nmap versions + curated NSE + bounded Nuclei
      ↓
Fast profile: refine unresolved identities
      ↓
HTTP(S) → WhatWeb explicit technology versions
TLS     → OpenSSL certificate/session + sslscan protocols/ciphers
SMB     → reuse NSE protocol/signing/host identity
      ↓
Separate products → deduplicate aliases → withhold conflicting versions
      ↓
Local NVD applicability matching → online fallback → KEV/EPSS
```

## Tool selection

| Evidence | Automatic check | Saved result |
|---|---|---|
| HTTP(S) | WhatWeb aggression 1, no redirects | HTTP status, technologies, explicit versions |
| TLS tunnel/implicit TLS | OpenSSL `s_client` + local `x509` decoding | Session, certificate SHA-256, subject, issuer, dates, serial, chain count, IP verification result |
| Same TLS service | sslscan | Protocol support, returned accepted/preferred cipher suites, certificate clues; weak suites/legacy protocols become posture findings |
| Open TCP 139/445 | Existing Nmap NSE pass | `smb-os-discovery`, `smb-protocols`, `smb2-security-mode`; no duplicate SMB scan |

For example, `ssl/realserver` on TCP 7070 receives TLS tools, not an assumed HTTP
request. Identified SSH on TCP 443 does not receive web/TLS probes. This new stage
does not perform STARTTLS or RDP-specific TLS handshakes.

WhatWeb cannot follow a redirect to another host in this workflow. Supported
explicit-version CPE aliases include Apache HTTP Server, nginx, IIS, PHP,
WordPress, Tomcat, jQuery, Drupal, Joomla and lighttpd. Other technologies remain
visible without guessed CPEs. Ambiguous multi-version plugins are not correlated.

## Additional budgets

| Profile | Tool runs | Total additional time | Individual tool budget |
|---|---:|---:|---:|
| Fast | 6 | 45 seconds | 15 seconds |
| Detailed | 12 | 120 seconds | 35 seconds |
| Aggressive | 18 | 180 seconds | 50 seconds |

These are **additional** to Nmap/NSE/Nuclei, not total assessment deadlines. Tools
run sequentially. OpenSSL decoding shares its session budget. Docker commands
also have an in-container timeout, preventing an abandoned outer client from
leaving an indefinitely running scanner. sslscan pauses 10 ms between connection
requests; this is not a global traffic cap. Heartbleed, renegotiation, compression,
fallback and group-enumeration checks are disabled in this stage.

Results distinguish completed, incomplete, unavailable, no-evidence and skipped
checks. Missing SMB replies mean unknown posture. All-disabled TLS results without
a successful negotiation are inconclusive, not secure. At most 64 planned checks
are individually reported; further skipped checks are aggregated.

## CVE interpretation and storage

Each versioned software product is correlated separately: nginx and PHP on one
port are two identities. Equivalent CPE aliases are queried once. Contradictory
versions are retained as evidence but withheld from CVE matching.

Certificates (e.g. `AnyDesk Client`), TLS versions and cipher names are **not
remote software version evidence**. The scanner's own OpenSSL version never
becomes a remote identity. IP-based certificate verification can fail for a
hostname-only or private-PKI certificate; this does not establish a software CVE.
SNI-dependent virtual hosts may require a manual hostname-aware check. CVE
candidates still require review for fingerprint accuracy, backports and vendor
applicability.

Playbooks show compact tool reports and severity-prioritized findings. Full saved
reports are available under the device assessment's **Automatic tool reports**
and `GET /api/devices/{device_id}/vulnerability-scans`. Raw output is capped at
4,000 characters per tool; returned cipher lists are capped at 500 entries.
Large playbook previews remain valid JSON and disclose omitted findings/checks.

Backend restart creates the additive `vulnerability_tool_runs` table; no existing
assessment columns, results, or secrets are overwritten.

## Verification

Run backend tests with `.\.venv\Scripts\python.exe -m pytest` from `backend`.
The opt-in real WhatWeb fixture advertises **synthetic test versions**, contacts
no NVD service and shuts down afterward. Use an IP assigned to the Aegis host:

```powershell
$env:AEGIS_NETWORK_TOOLBOX_CONTAINER = 'aegis-network-tools'
$env:AEGIS_LIVE_ENRICHMENT_TEST_IP = Read-Host 'IP assigned to the owned Aegis test host'
.\.venv\Scripts\python.exe -m pytest tests/test_service_enrichment_live.py -s
```

If it times out, check the host firewall and Docker route to that local IP. The
test does not change firewall policy.
