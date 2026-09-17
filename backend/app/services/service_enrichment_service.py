"""Bounded, service-directed evidence collection before CVE correlation.

Only explicit software versions become identities. Certificates, cipher names,
OS guesses and port-number labels never become CVE lookup keys.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.services.nse_verification_service import NseVerificationResult
from app.services.port_scan_service import DetectedService, OpenPort
from app.services.scan_policy import scan_target_rejection_reason
from app.services.security_toolbox_service import _run_lab_tool

WEB_PORTS = {80: "http", 443: "https", 8000: "http", 8008: "http", 8080: "http",
             8081: "http", 8443: "https", 8888: "http", 9443: "https"}
TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 995, 3269, 8443, 9443}
# (maximum additional tool runs, total seconds, per-tool seconds)
PROFILE_LIMITS = {"FAST": (6, 45, 15), "DETAILED": (12, 120, 35), "AGGRESSIVE": (18, 180, 50)}
PRODUCT_ALIASES = {
    "apache": ("Apache HTTP Server", "apache", "http_server"),
    "nginx": ("nginx", "nginx", "nginx"),
    "microsoft-iis": ("Microsoft IIS", "microsoft", "internet_information_services"),
    "php": ("PHP", "php", "php"),
    "wordpress": ("WordPress", "wordpress", "wordpress"),
    "apache-tomcat": ("Apache Tomcat", "apache", "tomcat"),
    "jquery": ("jQuery", "jquery", "jquery"),
    "drupal": ("Drupal", "drupal", "drupal"),
    "joomla": ("Joomla!", "joomla", "joomla"),
    "lighttpd": ("lighttpd", "lighttpd", "lighttpd"),
}
VERSION = re.compile(r"\d[A-Za-z0-9._+~-]{0,79}\Z")
LEGACY_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHER = re.compile(r"(?:NULL|EXPORT|RC4|3DES|DES-CBC|DES_)", re.I)


@dataclass(frozen=True)
class EnrichmentIssue:
    port: int
    severity: str
    category: str
    title: str
    description: str
    recommendation: str


@dataclass(frozen=True)
class ToolEvidence:
    tool: str
    port: int
    status: str
    duration_ms: float
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ServiceEnrichmentResult:
    services: tuple[DetectedService, ...] = ()
    tool_runs: tuple[ToolEvidence, ...] = ()
    issues: tuple[EnrichmentIssue, ...] = ()


def service_route(item: OpenPort, detected: DetectedService | None = None) -> tuple[str | None, bool]:
    """Prefer probed protocol over a conventional port-number fallback."""
    name = (detected.name if detected else item.service).casefold().strip().rstrip("?")
    tls = bool(detected and detected.tunnel == "ssl") or name.startswith("ssl/") or name in {"https", "ssl", "tls", "imaps", "pop3s", "smtps", "ldaps", "ftps", "mqtts"}
    plain_name = name.removeprefix("ssl/")
    web = "http" in plain_name
    if web:
        tls = tls or "https" in name
        return ("https" if tls else "http"), tls
    # A positively identified non-web service (including TLS mail/LDAP) is not
    # sent HTTP requests merely because it happens to use a familiar web port.
    if detected and name not in {"unknown", "ssl", "tls", "tcpwrapped", ""}:
        return None, tls
    scheme = WEB_PORTS.get(item.port)
    return scheme, tls or item.port in TLS_PORTS or scheme == "https"


def parse_whatweb(output: str, port: int, target: str) -> tuple[list[DetectedService], dict]:
    try:
        records = json.loads(output)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("WhatWeb did not return a complete JSON report") from exc
    if not isinstance(records, list):
        raise RuntimeError("WhatWeb returned an unexpected JSON report")
    identities: list[DetectedService] = []
    technologies: list[dict] = []
    statuses: list[int] = []
    for record in records[:10]:
        if not isinstance(record, dict) or record.get("target") != target:
            continue
        if isinstance(record.get("http_status"), int):
            statuses.append(record["http_status"])
        plugins = record.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for name, evidence in list(plugins.items())[:100]:
            if not isinstance(evidence, dict):
                continue
            versions = evidence.get("version") or []
            if not isinstance(versions, list):
                versions = [versions]
            versions = sorted({str(value) for value in versions if VERSION.fullmatch(str(value))})
            strings = evidence.get("string") or []
            if not isinstance(strings, list):
                strings = [strings]
            technologies.append({"technology": str(name)[:80], "versions": versions[:8],
                                 "observed_values": [str(value)[:200] for value in strings[:4]]})
            alias = PRODUCT_ALIASES.get(name.casefold())
            # Unknown plugins remain visible but cannot supply invented CPEs.
            # Multiple versions in one plugin are ambiguous, not eight matches.
            if alias and len(versions) == 1:
                product, vendor, cpe_product = alias
                version = versions[0]
                identities.append(DetectedService(port, "http", product, version, "WhatWeb plugin",
                                                  (f"cpe:/a:{vendor}:{cpe_product}:{version}",)))
    if not statuses:
        raise RuntimeError("WhatWeb received no HTTP response from the selected endpoint")
    return identities, {"http_status": statuses[0], "technologies": technologies}


def parse_sslscan(output: str, port: int) -> tuple[dict, list[EnrichmentIssue]]:
    # sslscan's human-readable report can precede its --xml=- stream.
    start = output.find("<?xml")
    if start < 0:
        start = output.find("<document")
    try:
        root = ET.fromstring(output[start:]) if start >= 0 else None
    except ET.ParseError as exc:
        raise RuntimeError("sslscan returned incomplete or unreadable XML") from exc
    test = root.find(".//ssltest") if root is not None else None
    if test is None or not test.findall("protocol"):
        raise RuntimeError("sslscan returned no protocol evidence")
    protocols = []
    enabled = []
    for node in test.findall("protocol"):
        kind = node.get("type", "").upper()
        version = node.get("version", "")
        name = f"{kind}v{version}"
        supported = node.get("enabled") == "1"
        protocols.append({"protocol": name, "enabled": supported})
        if supported:
            enabled.append(name)
    if not enabled:
        raise RuntimeError("No TLS protocol was negotiated; negative results may reflect filtering or handshake failure")
    ciphers = [{"protocol": node.get("sslversion"), "cipher": node.get("cipher"),
                "bits": node.get("bits"), "status": node.get("status")}
               for node in test.findall("cipher") if node.get("status") in {"accepted", "preferred"}]
    issues = []
    legacy = sorted(set(enabled) & LEGACY_PROTOCOLS)
    if legacy:
        issues.append(EnrichmentIssue(port, "HIGH", "TLS_PROTOCOL", "Legacy TLS protocols supported",
                                     ", ".join(legacy), "Disable SSLv2/3 and TLS 1.0/1.1; require TLS 1.2 or newer."))
    weak = sorted({row["cipher"] for row in ciphers if row["cipher"] and WEAK_CIPHER.search(row["cipher"])})
    if weak:
        issues.append(EnrichmentIssue(port, "MEDIUM", "TLS_CIPHER", "Weak TLS cipher suites supported",
                                     ", ".join(weak), "Disable NULL, export, RC4, DES and 3DES suites; prefer modern AEAD suites."))
    certificates = [{child.tag: (child.text or "").strip()[:500] for child in node if child.text}
                    for node in test.findall(".//certificate")]
    for certificate, node in zip(certificates, test.findall(".//certificate")):
        public_key = node.find("pk")
        if public_key is not None:
            certificate["public_key"] = dict(public_key.attrib)
    return {"engine_version": root.get("version"), "protocols": protocols, "ciphers": ciphers[:500], "certificates": certificates[:8]}, issues


def parse_openssl(output: str) -> dict:
    protocol = re.search(r"(?:Protocol\s*(?::|version:)\s*|New,\s*)(TLSv?[\d.]+|SSLv[\d.]+)", output)
    cipher = re.search(r"(?:Cipher\s*:\s*|Cipher is\s+|Ciphersuite:\s*)([\w-]+)", output)
    pem = re.search(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----", output)
    if not protocol or not cipher or cipher.group(1) in {"0000", "NONE"} or not pem:
        raise RuntimeError("OpenSSL did not return a complete TLS session and peer certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert(pem.group())
    except (ValueError, ssl.SSLError) as exc:
        raise RuntimeError("OpenSSL returned an unreadable certificate") from exc
    verification = re.search(r"Verify return code:\s*(\d+)\s*\(([^\n]*)\)", output)
    return {"protocol": protocol.group(1), "cipher": cipher.group(1),
            "certificate_sha256": hashlib.sha256(der).hexdigest(),
            "chain_certificates": output.count("-----BEGIN CERTIFICATE-----"),
            "verification": verification.group(2) if verification else "not reported"}


def _execute(tool: str, port: int, command: list[str], target: str, timeout: int) -> tuple[ToolEvidence, list[DetectedService], list[EnrichmentIssue]]:
    started = time.monotonic()
    raw = ""
    context = None
    try:
        result = _run_lab_tool(tool, command, target=target, timeout=timeout, contain_timeout=True)
        raw = result.output
        command = getattr(result, "command", None) or command
        context = getattr(result, "execution_context", None)
        if result.exit_code != 0 or result.truncated:
            raise RuntimeError(f"{tool} {'output was truncated' if result.truncated else f'exited with status {result.exit_code}'}")
        identities, issues = [], []
        if tool == "whatweb":
            identities, evidence = parse_whatweb(raw, port, target)
        elif tool == "sslscan":
            evidence, issues = parse_sslscan(raw, port)
        else:
            evidence = parse_openssl(raw)
            pem = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S).group()
            certificate_command = ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"]
            remaining = max(0, int(timeout - (time.monotonic() - started)))
            if remaining < 4:
                raise RuntimeError("OpenSSL certificate decoding exceeded the tool budget")
            certificate = _run_lab_tool("openssl", certificate_command, input_text=pem, timeout=min(8, remaining), contain_timeout=True)
            if certificate.exit_code != 0 or certificate.truncated:
                raise RuntimeError("OpenSSL could not decode the peer certificate")
            evidence["certificate"] = dict(line.split("=", 1) for line in certificate.output.splitlines() if "=" in line)
            evidence["certificate_command"] = getattr(certificate, "command", None) or certificate_command
        return ToolEvidence(tool, port, "COMPLETED", round((time.monotonic() - started) * 1000, 2),
                            {"target": target, "command": command, "execution_context": context, "evidence": evidence, "raw_output": raw[:4000]}), identities, issues
    except (RuntimeError, ValueError, OSError) as exc:
        status = "UNAVAILABLE" if "not installed" in str(exc) else "INCOMPLETE"
        return ToolEvidence(tool, port, status, round((time.monotonic() - started) * 1000, 2),
                            {"target": target, "command": command, "execution_context": context, "error": str(exc)[:500], "raw_output": raw[:4000]}), [], []


def enrich_open_services(address: str, open_ports: list[OpenPort], detected_services: list[DetectedService],
                         nse_result: NseVerificationResult, profile: str = "FAST") -> ServiceEnrichmentResult:
    rejection = scan_target_rejection_reason(address)
    if rejection:
        raise ValueError(rejection)
    address = str(ipaddress.ip_address(address))
    authority = f"[{address}]" if ":" in address else address
    max_runs, total_seconds, per_tool = PROFILE_LIMITS[profile.upper()]
    deadline = time.monotonic() + total_seconds
    services = {item.port: item for item in detected_services}
    runs, identities, issues = [], [], []
    smb_ports = sorted({item.port for item in open_ports if item.port in {139, 445}})
    if smb_ports:
        smb_scripts = {"smb-os-discovery", "smb-protocols", "smb2-security-mode", "smb2-time"}
        observed = [row for row in nse_result.observations if row.script_id in smb_scripts]
        requested = sorted(smb_scripts & set(nse_result.requested_scripts))
        runs.append(ToolEvidence("Nmap SMB", 445 if 445 in smb_ports else 139,
                                 "COMPLETED" if observed else "NO_EVIDENCE", nse_result.duration_ms,
                                 {"reused_nse_result": True, "requested_scripts": requested,
                                  "observations": [{"script": row.script_id, "port": row.port, "output": row.output} for row in observed],
                                  "note": "Reuses the curated NSE pass; displayed duration is shared with its other checks. No duplicate SMB probes. Missing signing/protocol replies mean unknown posture, not secure."}))
    commands = []
    for item in sorted(open_ports, key=lambda row: row.port):
        scheme, tls = service_route(item, services.get(item.port))
        host_port = f"{authority}:{item.port}"
        if scheme:
            target = f"{scheme}://{host_port}/"
            commands.append(("whatweb", item.port, target,
                             ["whatweb", "--aggression=1", "--max-threads=1", "--open-timeout=3", "--read-timeout=5",
                              "--follow-redirect=never", "--colour=never", "--quiet", "--log-json=-", target]))
        if tls:
            commands.append(("openssl", item.port, host_port,
                             ["openssl", "s_client", "-connect", host_port, "-showcerts", "-no_ign_eof", "-verify_ip", address]))
            commands.append(("sslscan", item.port, host_port,
                             ["sslscan", "--no-colour", "--no-heartbleed", "--no-renegotiation", "--no-compression",
                              "--no-fallback", "--no-groups", "--timeout=2", "--sleep=10", "--xml=-", host_port]))
    overflow = commands[64:]
    for index, (tool, port, target, command) in enumerate(commands[:64]):
        remaining = int(deadline - time.monotonic())
        if index >= max_runs or remaining < 5:
            runs.append(ToolEvidence(tool, port, "SKIPPED", 0.0, {"target": target, "note": "Per-host enrichment run/time limit reached. Use a deeper profile or run this check manually."}))
            continue
        run, found, warnings = _execute(tool, port, command, target, min(per_tool, remaining))
        runs.append(run)
        identities.extend(found)
        issues.extend(warnings)
    if overflow:
        runs.append(ToolEvidence("Service enrichment", overflow[0][1], "SKIPPED", 0.0,
                                 {"skipped_run_count": len(overflow), "note": "Additional planned checks exceeded the 64-row reporting limit and were not run."}))
    return ServiceEnrichmentResult(tuple(identities), tuple(runs), tuple(issues))
