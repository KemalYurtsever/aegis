# AEGIS local agent diagnostics

Agent diagnostics provide administrator-requested, allowlisted checks on an enrolled local host. They are not a general remote shell. The hybrid launcher binds agent ingress to `127.0.0.1`, so other devices on the Wi-Fi or LAN cannot submit data or claim jobs.

## Security properties

- Only an authenticated AEGIS administrator can create, list, or cancel jobs.
- An agent can claim and submit results only with the token bound to its device.
- The agent must explicitly report `diagnostics_enabled=true` before the server accepts a job.
- Job types and numeric parameters are validated by the API.
- External tools are invoked with argument arrays and `shell=False`.
- Jobs expire after 15 minutes and only pending jobs can be cancelled.
- Agent transfer and server storage limits prevent unbounded output.
- Browser output is rendered as text/JSON; it is never inserted as executable HTML.
- Packet capture is non-promiscuous metadata only. Payloads and PCAP files are not retained.

## Available jobs

| Job | Windows | Linux/Unix |
| --- | --- | --- |
| Network and routing state | `psutil` plus `Get-NetRoute` | `psutil` plus `ip route` or `netstat -rn` |
| Top processes | `psutil` | `psutil` |
| Security log summary | Windows System log | systemd journal |
| Login history | Security events 4624/4625 | `last` |
| Local accounts | `Get-LocalUser` | local account database |
| Firewall rules | Windows Defender Firewall | nftables, UFW, firewalld, or iptables |
| Local service scan | Nmap against `127.0.0.1` | Nmap against `127.0.0.1` |
| Packet metadata | Scapy/Npcap | Scapy |
| SUID audit | Not applicable | bounded root-filesystem `find` |

Completed network-state results are hashed into the device drift baseline. AEGIS records a change event when either socket ownership or routing-table state changes; raw results remain available only through the authenticated diagnostic panel.

## Windows rollout on the Aegis host

1. Enroll or rotate the device agent token in AEGIS.
2. Use the current `agent` directory on the same Windows host.
3. Open PowerShell as Administrator.
4. Install or update the agent:

```powershell
.\install-windows.ps1 -ServerUrl "http://127.0.0.1:8002" -EnableDiagnostics
```

5. Wait for the first metric report. The device page will change from **Agent opt-in required** to **Agent enabled**.

The Windows installer runs the agent as `SYSTEM`; therefore diagnostics should be enabled only on the local learning host. Remote rollout is intentionally disabled by the loopback-only listener.
