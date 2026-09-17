# Compare Aegis and Kali fingerprints

## Observations

Aegis's previous toolbox used Nmap 7.93 and short host timeouts. The current toolbox pins Nmap 7.991; Detailed/Aggressive TCP version detection uses 90/180-second host budgets. Full-probe scans can exceed shorter budgets, so discovery evidence must be preserved when identification is incomplete.

A repeated source-port bind can fail with `Cannot assign requested address (99)` during application probing. Aegis keeps SYN for ports-only Docker discovery but uses `-sT` for application fingerprints so the kernel selects connection source ports. A transport error alone is not evidence that a target banned the scanner. Workstation-specific traces and observed device results are not published.

Plain `-sV` defaults to intensity 7. Aegis Aggressive uses `--version-all` (intensity 9), which tests more probes and can take longer. It is not `-A`. See [official version-detection documentation](https://nmap.org/book/man-version-detection).

## Test

First compare the engines and probe datasets. `--version` prints the release and compiled features; `sha256sum` identifies the exact service-probe file. Different hashes mean the two scans are not using the same fingerprint rules.

On Kali:

```bash
nmap --version
sha256sum /usr/share/nmap/nmap-service-probes
```

On the Aegis host:

```powershell
docker exec aegis-network-tools nmap --version
docker exec aegis-network-tools sha256sum /opt/nmap/share/nmap/nmap-service-probes
```

Run the same controlled port set and profile on Kali. The address below is reserved for documentation; ports 22/443 are illustrative, not an observed inventory. Replace both with the owned registered target and its discovered port set:

```bash
nmap -Pn -sT -n -T4 --max-retries 2 --max-rate 100 --scan-delay 10ms --host-timeout 180s -p 22,443 -sV --version-all --reason 198.51.100.20
```

Run its equivalent from the Aegis host:

```powershell
docker exec aegis-network-tools nmap -Pn -sT -n -T4 --max-retries 2 --max-rate 100 --scan-delay 10ms --host-timeout 180s -p 22,443 -sV --version-all --reason 198.51.100.20
```

- `-Pn`: skip host-discovery gating; `-n`: skip reverse DNS.
- `-sT`: TCP connect; version-probe connections let the kernel select their source ports. The separate Aegis Docker ports-only pass uses `-sS` with `NET_RAW`.
- `-T4`, `--max-retries 2`: match the timing template and port-discovery retransmission budget.
- `--max-rate 100`, `--scan-delay 10ms`: match Aegis's default discovery pacing; these do not provide an IDS allowlist or a universal application-probe rate limit.
- `--host-timeout 180s`: the same bounded host budget.
- `-p`: identical TCP ports; `-sV --version-all`: all version probes; `--reason`: show port-state evidence.

## Conclusions and troubleshooting

Compare scans close together against a stable service. Aegis records the actual commands and engine in CLI output and stores assessment provenance. The background job can reuse recently confirmed closed ports; its output states which ports were cached, so use the commands above when testing engine parity without cache reuse.

Even identical flags and probe hashes can produce different observations when source interfaces/IPs differ. Docker-managed routing/NAT and a Kali VM can reach different firewall policies or service behavior. [Nmap documents port states as observations from the scanner's vantage point](https://nmap.org/book/port-scanning.html).

`Skipping host ... due to host timeout` is incomplete evidence even when Nmap exits with code 0. A `?` service name or a missing product/version is tentative identity, not proof of CVE applicability. If results still differ, preserve both complete commands, versions, probe hashes, outputs, timestamps and source interfaces before attributing the difference to Aegis.
