from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.services.port_scan_service import OpenPort


WEB_PORT_SCHEMES = {
    80: "http",
    443: "https",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8443: "https",
    8888: "http",
    9443: "https",
}
PROFILE_OPTIONS = {
    "FAST": {
        "severities": "medium,high,critical",
        "rate_limit": "15",
        "concurrency": "4",
        "request_timeout": "3",
        "process_timeout": 25,
    },
    "DETAILED": {
        "severities": "low,medium,high,critical",
        "rate_limit": "25",
        "concurrency": "8",
        "request_timeout": "5",
        "process_timeout": 60,
    },
    "AGGRESSIVE": {
        "severities": "low,medium,high,critical",
        "rate_limit": "40",
        "concurrency": "12",
        "request_timeout": "6",
        "process_timeout": 120,
    },
}
TEMPLATE_DIRECTORIES = ("http/exposures", "http/misconfiguration", "ssl")
EXCLUDED_TAGS = "dos,fuzz,intrusive,bruteforce,default-login,credential-stuffing"
MAX_WEB_TARGETS = 16
MAX_FINDINGS = 100
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_TEXT_LENGTH = 1_000
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class NucleiObservation:
    template_id: str
    name: str
    severity: str
    description: str | None
    remediation: str | None
    matched_at: str
    matcher_name: str | None
    reference: str | None
    cve_id: str | None
    port: int


@dataclass(frozen=True)
class NucleiValidationResult:
    targets: tuple[str, ...]
    observations: tuple[NucleiObservation, ...]
    duration_ms: float
    completed: bool
    error: str | None = None
    skipped_target_count: int = 0


def _clean_text(value: object, limit: int = MAX_TEXT_LENGTH) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _target_authority(address: str, port: int) -> str:
    parsed = ipaddress.ip_address(address)
    host = f"[{parsed}]" if parsed.version == 6 else str(parsed)
    return f"{host}:{port}"


def web_targets(address: str, open_ports: list[OpenPort]) -> tuple[tuple[str, ...], int]:
    target_ip = str(ipaddress.ip_address(address))
    targets: set[str] = set()
    for item in open_ports:
        service = item.service.casefold()
        scheme = None
        if "https" in service or "ssl" in service:
            scheme = "https"
        elif "http" in service:
            scheme = "http"
        elif item.port in WEB_PORT_SCHEMES:
            scheme = WEB_PORT_SCHEMES[item.port]
        if scheme:
            targets.add(f"{scheme}://{_target_authority(target_ip, item.port)}")
    ordered = sorted(targets, key=lambda value: (urlsplit(value).port or 0, value))
    return tuple(ordered[:MAX_WEB_TARGETS]), max(0, len(ordered) - MAX_WEB_TARGETS)


def _safe_reference(value: object) -> str | None:
    values = value if isinstance(value, list) else [value]
    for candidate in values:
        reference = _clean_text(candidate, 500)
        try:
            parsed = urlsplit(reference)
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return reference
    return None


def _safe_matched_target(
    record: dict,
    expected_ip: str,
    targets_by_port: dict[int, str],
) -> tuple[str, int] | None:
    raw = _clean_text(record.get("matched-at") or record.get("url") or record.get("host"), 700)
    if not raw:
        return None
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = str(ipaddress.ip_address(parsed.hostname or ""))
        port = parsed.port
    except (ValueError, TypeError):
        return None
    if hostname != expected_ip:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    base = targets_by_port.get(port)
    if base is None:
        return None
    path = parsed.path[:300] if parsed.path.startswith("/") else ""
    return f"{base}{path}", port


def _first_cve(info: dict) -> str | None:
    classification = info.get("classification")
    candidates: list[object] = []
    if isinstance(classification, dict):
        candidates.extend((classification.get("cve-id"), classification.get("cve_id")))
    candidates.append(info.get("tags"))
    for candidate in candidates:
        values = candidate if isinstance(candidate, list) else [candidate]
        for value in values:
            match = CVE_PATTERN.search(str(value or ""))
            if match:
                return match.group(0).upper()
    return None


def parse_nuclei_jsonl(
    output: str,
    *,
    expected_ip: str,
    targets: tuple[str, ...],
) -> tuple[NucleiObservation, ...]:
    normalized_ip = str(ipaddress.ip_address(expected_ip))
    targets_by_port = {urlsplit(target).port or 0: target for target in targets}
    observations: dict[tuple[str, str], NucleiObservation] = {}
    for raw_line in output.splitlines():
        if len(observations) >= MAX_FINDINGS:
            break
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        matched = _safe_matched_target(record, normalized_ip, targets_by_port)
        if matched is None:
            continue
        matched_at, port = matched
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        template_id = _clean_text(record.get("template-id"), 200)
        name = _clean_text(info.get("name"), 200)
        severity = _clean_text(info.get("severity"), 10).casefold()
        if not template_id or not name or severity not in SEVERITIES:
            continue
        observation = NucleiObservation(
            template_id=template_id,
            name=name,
            severity=severity.upper(),
            description=_clean_text(info.get("description")) or None,
            remediation=_clean_text(info.get("remediation")) or None,
            matched_at=matched_at,
            matcher_name=_clean_text(record.get("matcher-name"), 100) or None,
            reference=_safe_reference(info.get("reference")),
            cve_id=_first_cve(info),
            port=port,
        )
        observations[(observation.template_id, observation.matched_at)] = observation
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return tuple(sorted(
        observations.values(),
        key=lambda item: (severity_order[item.severity], item.port, item.template_id),
    ))


def _nuclei_runtime() -> tuple[list[str], str] | None:
    executable = shutil.which("nuclei")
    if executable:
        return [executable], os.getenv("AEGIS_NUCLEI_TEMPLATE_ROOT", "").strip()
    container = os.getenv("AEGIS_NETWORK_TOOLBOX_CONTAINER", "").strip()
    docker = shutil.which("docker")
    if container and docker:
        return [docker, "exec", container, "nuclei"], "/nuclei-templates"
    return None


def run_nuclei_validation(
    address: str,
    open_ports: list[OpenPort],
    profile: str = "FAST",
) -> NucleiValidationResult:
    normalized_profile = profile.upper()
    options = PROFILE_OPTIONS.get(normalized_profile)
    if options is None:
        raise ValueError("Unknown Nuclei validation profile")
    targets, skipped = web_targets(address, open_ports)
    if not targets:
        return NucleiValidationResult((), (), 0.0, True)
    runtime = _nuclei_runtime()
    if runtime is None:
        raise RuntimeError("Nuclei validation requires Nuclei or the Docker network toolbox")
    prefix, template_root = runtime
    command = [
        *prefix,
        "-disable-update-check",
        "-disable-unsigned-templates",
        "-no-interactsh",
        "-no-stdin",
        "-disable-redirects",
        "-type",
        "http,ssl",
        "-exclude-type",
        "headless,code,javascript,file,websocket",
        "-exclude-tags",
        EXCLUDED_TAGS,
        "-severity",
        options["severities"],
        "-rate-limit",
        options["rate_limit"],
        "-concurrency",
        options["concurrency"],
        "-bulk-size",
        "1",
        "-timeout",
        options["request_timeout"],
        "-retries",
        "0",
        "-max-host-error",
        "5",
        "-jsonl",
        "-silent",
        "-no-color",
        "-omit-raw",
        "-omit-template",
    ]
    for directory in TEMPLATE_DIRECTORIES:
        path = f"{template_root}/{directory}" if template_root else directory
        command.extend(["-templates", path])
    for target in targets:
        command.extend(["-target", target])

    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile() as output_file, tempfile.TemporaryFile() as error_file:
        try:
            completed = subprocess.run(
                command,
                stdout=output_file,
                stderr=error_file,
                timeout=options["process_timeout"],
                shell=False,
                check=False,
            )
            return_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            return_code = 124
        output_file.seek(0)
        encoded_output = output_file.read(MAX_OUTPUT_BYTES + 1)
        error_file.seek(0)
        encoded_error = error_file.read(4_001)
    if len(encoded_output) > MAX_OUTPUT_BYTES:
        raise RuntimeError("Nuclei validation output exceeded the 4 MiB safety limit")
    output = encoded_output.decode("utf-8", errors="replace")
    observations = parse_nuclei_jsonl(output, expected_ip=address, targets=targets)
    error = None
    if timed_out:
        error = f"{normalized_profile.title()} Nuclei validation reached its {options['process_timeout']}-second budget"
    elif return_code != 0:
        detail = _clean_text(encoded_error.decode("utf-8", errors="replace"), 500)
        error = detail or "Nuclei validation failed"
    return NucleiValidationResult(
        targets=targets,
        observations=observations,
        duration_ms=round((time.monotonic() - started) * 1000, 2),
        completed=error is None,
        error=error,
        skipped_target_count=skipped,
    )
