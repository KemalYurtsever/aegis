# Docker Wireshark in Aegis

Aegis now opens the actual Wireshark desktop through a browser, replacing the primary metadata-only capture form. The optional image uses LinuxServer's Selkies desktop streaming platform and separate Basic authentication over HTTPS. [Image documentation](https://docs.linuxserver.io/images/docker-wireshark/).

## Start and open

From the repository root, with `aegis-network-tools` running:

```powershell
.\start-wireshark.ps1
.\verify-wireshark.ps1
```

The launcher discovers the toolbox bridge network, starts two optional containers, creates `/config/captures`, and waits for authenticated HTTPS. It generates a random local password only if none exists. It does not recreate the toolbox or restart the API. Verification checks the current namespace, health, loopback port, anonymous denial, authenticated success, proxy syntax and non-root interface listing; it sends no scan traffic and starts no capture.

The password file is ignored by Git. If an operator explicitly chooses a password shorter than 20 characters, an ignored `secrets/wireshark_allow_short_password.txt` file opts that local installation out of the launcher's length check; otherwise the launcher continues to require at least 20 characters. After editing the password file, recreate the Wireshark and proxy containers so the GUI reads the new secret, then run `verify-wireshark.ps1`.

Open **Wireshark → Open Wireshark** in Aegis, or `https://127.0.0.1:8444/`. Sign in as `aegis` using `secrets/wireshark_password.txt`. Authentication is separate from the Aegis account. The image supplies a self-signed certificate by default; the first browser connection may require your manual approval. No browser or Windows trust settings are modified by the scripts. [HTTPS and authentication behavior](https://docs.linuxserver.io/images/docker-wireshark/#security).

`start-hybrid.ps1 -WithWireshark` enables it on a first hybrid launch. Once its password file exists, subsequent hybrid launches automatically restart/reattach it. The GUI is optional: core Aegis can still start without Docker.

## What traffic it sees

The topology is:

```text
Browser → 127.0.0.1:8444 → TLS TCP proxy → Wireshark HTTPS:3001
                                              │
                              same network namespace as toolbox
                                              │
                                  eth0 → owned network target
```

The GUI shares the running toolbox's network namespace rather than merely joining the same bridge. Select `eth0` to capture Nmap, WhatWeb, TLS and SMB requests executed in that toolbox and their responses. No duplicate scanner MAC is created by this sidecar, and existing Docker Desktop routing/NAT is unchanged.

This does not expose physical Windows Wi-Fi/Ethernet adapters, the Kali VM's traffic, native Windows discovery/monitoring traffic, or every LAN device-to-device conversation. To inspect those, capture at the actual observation point with Windows Wireshark/Npcap or another authorized sensor, then import the PCAP/PCAPNG through the GUI's file transfer and **File → Open**. Sharing a Docker namespace is not a switch mirror or Windows adapter passthrough.

## Capture a check

1. Select `eth0`, enter a **capture filter**, and start recording before the Aegis check. Example: `host 198.51.100.20 and tcp port 445`. This is a reserved documentation address, not an observed device. Substitute your registered device address; this example collects only its SMB-port exchanges.
2. Run the corresponding Aegis scan or tool, then stop capture.
3. Apply a **display filter** such as `ip.addr == 198.51.100.20 && tcp.port == 445`, `tls.handshake`, `dns`, or `smb2`. These change the view, not the bytes already collected. A port-only Nmap scan normally shows TCP connection packets, not a full SMB session; run the SMB posture check for protocol exchanges.
4. Inspect packet fields, timing, retransmissions and **Follow TCP Stream**. Save under `/config/captures` for persistence.

Use target/protocol filters. Unfiltered `eth0` captures can include the GUI's own HTTPS desktop stream on port 3001. Stop after the investigation; for longer captures, configure a file-size limit and a small multi-file ring buffer in **Capture Options → Output**. Unlike legacy capture, this application does not inherit Aegis's old 30-second/1,000-packet limits. Its container is capped at 2 CPUs and 2 GB RAM; saved captures can still consume disk space.

Wireshark can retain full payloads, including cleartext application data when present. TLS application data remains encrypted without separately supplied session secrets; none are collected automatically. Imported captures and GUI analysis are not automatically fed to CVE matching. The automated assessment still correlates identified product/version/CPE evidence separately.

## Storage and lifecycle

- `/config` is the named volume `aegis-wireshark_wireshark_data`; save captures in `/config/captures`, not a temporary directory.
- PCAP files/settings survive container recreation. Unsaved GUI sessions and in-progress captures may not.
- Password and local capture extensions are ignored by Git and excluded from Docker build contexts. There is no host directory or Docker socket mount.
- Normal Aegis database backups do **not** include this volume. Export required PCAPs separately using the GUI file-transfer download feature.
- Rerun `start-wireshark.ps1` after the toolbox is recreated. The launcher compares the exact toolbox container ID and reattaches only the optional containers when necessary.
- `stop-hybrid.ps1` stops the optional GUI/proxy before its toolbox while preserving volumes.

To stop just Wireshark, leaving scans and other Aegis services running:

```powershell
docker stop aegis-wireshark-proxy aegis-wireshark
```

This stops both optional containers without deleting saved files. Rerun the launcher to start them again.

## Troubleshooting

| Observation | Check / action |
|---|---|
| Connection refused | Run `start-wireshark.ps1`; Docker and the toolbox must be running. |
| Browser certificate warning | Manually inspect/approve this local self-signed endpoint. Scripts do not bypass browser interstitials. |
| Authentication prompt | Use the separate `aegis` GUI account and the local password file, not your Aegis account password. |
| No `eth0` or traffic after a toolbox rebuild | Rerun the launcher to reattach to the current toolbox namespace. |
| No packets from a Windows-native check | Expected: that check does not execute in the toolbox. Capture on Windows and import the file instead. |
| Capture contains only TCP SYN/ACK | A port scan is not a full application session. Run the matching service tool while capture is active. |
| TLS data is unreadable | Expected encryption, not a broken capture. TLS handshake/certificate fields remain useful. |
| Capture permission or GUI health failure | Run `verify-wireshark.ps1`; inspect the relevant container logs locally. Do not publish logs or PCAPs without reviewing their contents. |

For a different standalone GUI port, use `start-wireshark.ps1 -Port 9444` and `verify-wireshark.ps1 -Port 9444`; set `VITE_WIRESHARK_URL=https://127.0.0.1:9444/` before starting/rebuilding the frontend. Hybrid's automatic GUI startup uses the standard 8444 port.

## Verification and publication

Use `verify-wireshark.ps1` for repeatable local readiness checks. Capture outputs, observed device states and workstation-specific verification records stay local; no real-network sample is distributed with this guide. Images are pinned by digest in Compose, not floating `latest` tags. The first authenticated desktop interaction requires your browser certificate approval/sign-in.
