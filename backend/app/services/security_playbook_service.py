from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from app.models import (
    Device,
    SecurityPlaybookRun,
    SecurityPlaybookStep,
    VulnerabilityScan,
    utc_now,
)
from app.schemas import DnsQueryRead, LabCommandRead, TraceRouteRead
from app.services.nmap_top_ports import NMAP_TOP_1000_TCP_PORTS
from app.services.security_toolbox_service import (
    avahi_browse,
    query_dns,
    test_connection_ports,
    trace_registered_device,
)
from app.services.scan_policy import scan_target_rejection_reason
from app.services.vulnerability_service import run_vulnerability_scan


PLAYBOOK_STEPS = (
    ("powershell_tcp", "PowerShell TCP reachability"),
    ("traceroute", "Network path trace"),
    ("attack_surface", "Service discovery, automatic web/TLS/SMB evidence and CVE correlation"),
    ("dns_identity", "DNS identity lookup"),
)
ACTIVE_RUN_STATUSES = ("QUEUED", "RUNNING")
TERMINAL_RUN_STATUSES = ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED")
_OUTPUT_LIMIT_BYTES = 100_000
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PlaybookTarget:
    run_id: int
    device_id: int
    target_name: str
    target_ip: str
    profile: str


def build_playbook_run(
    device: Device,
    profile: str,
    requested_by: str,
) -> SecurityPlaybookRun:
    normalized_profile = profile.upper()
    if normalized_profile not in {"FAST", "DETAILED", "AGGRESSIVE"}:
        raise ValueError("Unknown security playbook profile")
    rejection = scan_target_rejection_reason(device.ip_address, mac_address=device.mac_address)
    if rejection:
        raise ValueError(rejection)
    return SecurityPlaybookRun(
        device_id=device.id,
        target_name=device.name,
        target_ip=device.ip_address,
        requested_by=requested_by[:80],
        profile=normalized_profile,
        active_slot=1,
        steps=[
            SecurityPlaybookStep(position=position, step_key=key, name=name)
            for position, (key, name) in enumerate(PLAYBOOK_STEPS, start=1)
        ],
    )


def load_playbook_run(run_id: int, db: Session) -> SecurityPlaybookRun | None:
    return db.scalar(
        select(SecurityPlaybookRun)
        .options(selectinload(SecurityPlaybookRun.steps))
        .where(SecurityPlaybookRun.id == run_id)
    )


def _bounded_text(value: object, limit: int = _OUTPUT_LIMIT_BYTES) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if isinstance(value, str):
        rendered = value
    else:
        rendered = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    encoded = rendered.encode("utf-8")
    if len(encoded) <= limit:
        return rendered
    suffix = b"\n[stored output truncated]"
    return encoded[: limit - len(suffix)].decode("utf-8", errors="ignore") + suffix.decode()


def _render_step_output(value: object) -> str:
    if isinstance(value, LabCommandRead):
        lines = [
            f"Tool: {value.tool}",
            f"Target: {value.target or 'local host'}",
            f"Exit code: {value.exit_code}",
            f"Duration: {value.duration_ms:.2f} ms",
        ]
        if value.scanned_port_count is not None:
            lines.append(f"Scanned ports: {value.scanned_port_count}")
        if value.truncated:
            lines.append("Output was truncated by the command runner.")
        if value.output:
            lines.extend(("", value.output))
        return _bounded_text("\n".join(lines))
    if isinstance(value, TraceRouteRead):
        lines = [
            f"Target: {value.target}",
            f"Completed: {'yes' if value.completed else 'no'}",
            "",
            "HOPS",
        ]
        if not value.hops:
            lines.append("No hops returned.")
        for hop in value.hops:
            address = hop.address or "*"
            latency = "timed out" if hop.timed_out else (
                f"{hop.latency_ms:.2f} ms" if hop.latency_ms is not None else "latency unavailable"
            )
            lines.append(f"{hop.hop:>2}  {address:<39}  {latency}")
        return _bounded_text("\n".join(lines))
    if isinstance(value, DnsQueryRead):
        return _bounded_text("\n".join((
            f"Query: {value.query}",
            f"Canonical name: {value.canonical_name or 'not returned'}",
            f"Addresses: {', '.join(value.addresses) or 'not returned'}",
            f"Reverse name: {value.reverse_name or 'not returned'}",
        )))
    return _bounded_text(value)


def _compact_finding(finding) -> dict[str, object]:
    """Render useful playbook evidence without pages of misleading nulls."""
    rendered: dict[str, object] = {
        "severity": finding.severity,
        "category": finding.category,
        "title": finding.title,
        "description": finding.description,
        "recommendation": finding.recommendation,
    }
    optional_fields = (
        "port",
        "cve_id",
        "cvss_score",
        "match_confidence",
        "epss_score",
        "validation_tool",
        "validation_check_id",
        "validation_target",
        "service_product",
        "service_version",
        "service_cpe",
    )
    for field in optional_fields:
        value = getattr(finding, field)
        if value is not None:
            rendered[field] = value
    if finding.known_exploited:
        rendered["known_exploited"] = True
    return rendered


def _compact_tool_run(run) -> dict:
    details = dict(run.details)
    details.pop("raw_output", None)
    evidence = dict(details.get("evidence") or {})
    for key, limit in (("ciphers", 20), ("technologies", 20)):
        if isinstance(evidence.get(key), list):
            evidence[f"{key}_total"] = len(evidence[key])
            evidence[key] = evidence[key][:limit]
    if evidence:
        details["evidence"] = evidence
    if isinstance(details.get("observations"), list):
        details["observations"] = [{**item, "output": item.get("output", "")[:1000]} for item in details["observations"][:8]]
    return {"tool": run.tool, "port": run.port, "status": run.status, "duration_ms": run.duration_ms, "details": details}


def _fit_attack_surface_output(result: dict) -> dict:
    """Keep the stored report valid JSON; full evidence stays on the scan API."""
    while len(json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")) > _OUTPUT_LIMIT_BYTES:
        if result["findings"]:
            result["findings"].pop()
            result["omitted_finding_count"] = result.get("omitted_finding_count", 0) + 1
        elif result.get("tool_runs"):
            result["tool_runs"].pop()
            result["omitted_tool_run_count"] = result.get("omitted_tool_run_count", 0) + 1
        else:
            break
    return result


def _error_text(exc: Exception) -> str:
    message = " ".join(str(exc).split()) or exc.__class__.__name__
    return message[:1000]


def _result_error(value: object) -> str | None:
    if isinstance(value, LabCommandRead) and value.exit_code == 124:
        return "Command exceeded its time limit"
    if isinstance(value, LabCommandRead) and value.exit_code != 0:
        return f"Command exited with status {value.exit_code}"
    if isinstance(value, TraceRouteRead) and not value.completed:
        return "Traceroute did not complete within its bounded probe limits"
    return None


def _mdns_enrichment(target_ip: str) -> dict[str, object]:
    """Collect target-scoped DNS-SD evidence without making it step-fatal."""
    try:
        result = avahi_browse(grep=target_ip)
    except Exception as exc:
        return {
            "status": "UNAVAILABLE",
            "tool": "avahi-browse",
            "target": target_ip,
            "records": [],
            "error": _error_text(exc),
        }

    output = result.output.strip()
    no_record_markers = (
        "no host-interface mdns records matched",
        "no dns-sd services were observed",
        "no avahi output matched",
        "no dns-sd services were visible",
    )
    has_records = bool(output) and not any(
        marker in output.casefold() for marker in no_record_markers
    )
    records: list[dict[str, object]] = []
    if has_records:
        for line in output.splitlines()[:20]:
            columns = line.split("\t")
            if len(columns) >= 5 and columns[0] == target_ip:
                records.append({
                    "address": columns[0],
                    "display_name": None if columns[1] == "-" else columns[1],
                    "model": None if columns[2] == "-" else columns[2],
                    "hostname": None if columns[3] == "-" else columns[3],
                    "services": [] if columns[4] == "-" else columns[4].split(","),
                })
            elif target_ip in line:
                records.append({"raw": line[:1000]})
    return {
        "status": "MATCHED" if records else "NO_RECORDS",
        "tool": result.tool,
        "target": target_ip,
        "duration_ms": result.duration_ms,
        "records": records,
        "raw_output": output[:4000] if output else None,
    }


class SecurityPlaybookRunner:
    """Run durable, administrator-requested assessments with one bounded worker."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        max_workers: int = 1,
        max_pending: int = 16,
    ) -> None:
        self._session_factory = session_factory
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="security-playbook")
        self._max_pending = max_pending
        self._futures: dict[int, Future] = {}
        self._lock = threading.RLock()
        self._stop_requested = threading.Event()
        self._accepting = False

    def start(self) -> None:
        self._recover_interrupted_runs()
        self._stop_requested.clear()
        with self._lock:
            self._accepting = True
        self._pump()

    def submit(self, run_id: int) -> bool:
        with self._lock:
            self._discard_finished_locked()
            if not self._accepting:
                return False
            if run_id in self._futures:
                return True
        with self._session_factory() as db:
            status = db.scalar(
                select(SecurityPlaybookRun.status).where(SecurityPlaybookRun.id == run_id)
            )
        if status != "QUEUED":
            return False
        self._pump()
        # A full in-memory queue is not an error: the persisted QUEUED row is
        # picked up as soon as an earlier future completes.
        return True

    def cancel(self, run_id: int) -> bool:
        now = utc_now()
        with self._session_factory() as db:
            status = db.scalar(
                select(SecurityPlaybookRun.status).where(SecurityPlaybookRun.id == run_id)
            )
            if status not in ACTIVE_RUN_STATUSES:
                return False
            if status == "QUEUED":
                result = db.execute(
                    update(SecurityPlaybookRun)
                    .where(SecurityPlaybookRun.id == run_id, SecurityPlaybookRun.status == "QUEUED")
                    .values(
                        status="CANCELLED",
                        active_slot=None,
                        cancel_requested=True,
                        completed_at=now,
                        current_step=None,
                    )
                )
                if result.rowcount != 1:
                    db.rollback()
                    return False
                run = load_playbook_run(run_id, db)
                if run is None:
                    db.rollback()
                    return False
                for step in run.steps:
                    if step.status == "PENDING":
                        step.status = "CANCELLED"
                        step.completed_at = now
                run.summary_json = json.dumps(self._summary(run.steps))
            else:
                result = db.execute(
                    update(SecurityPlaybookRun)
                    .where(SecurityPlaybookRun.id == run_id, SecurityPlaybookRun.status == "RUNNING")
                    .values(cancel_requested=True)
                )
                if result.rowcount != 1:
                    db.rollback()
                    return False
            db.commit()
        with self._lock:
            future = self._futures.get(run_id)
            if future is not None:
                future.cancel()
        return True

    def shutdown(self) -> None:
        with self._lock:
            self._accepting = False
            self._stop_requested.set()
            futures = list(self._futures.values())
        with self._session_factory() as db:
            db.execute(
                update(SecurityPlaybookRun)
                .where(SecurityPlaybookRun.status == "RUNNING")
                .values(cancel_requested=True)
            )
            db.commit()
        for future in futures:
            future.cancel()
        # Running commands are individually time bounded. Waiting here keeps an
        # old application process from writing after a replacement starts.
        self._executor.shutdown(wait=True, cancel_futures=True)

    def _discard_finished_locked(self) -> None:
        for run_id, future in list(self._futures.items()):
            if future.done():
                self._futures.pop(run_id, None)

    def _forget(self, run_id: int) -> None:
        with self._lock:
            future = self._futures.pop(run_id, None)
        if future is not None:
            try:
                exception = future.exception()
            except Exception:
                exception = None
            if exception is not None:
                logger.error(
                    "Security playbook worker failed: %s",
                    exception,
                    exc_info=(type(exception), exception, exception.__traceback__),
                )
        self._pump()

    def _pump(self) -> None:
        with self._lock:
            self._discard_finished_locked()
            if not self._accepting:
                return
            capacity = self._max_pending - len(self._futures)
            if capacity <= 0:
                return
            excluded_ids = tuple(self._futures)
            with self._session_factory() as db:
                statement = (
                    select(SecurityPlaybookRun.id)
                    .where(SecurityPlaybookRun.status == "QUEUED")
                    .order_by(SecurityPlaybookRun.created_at, SecurityPlaybookRun.id)
                    .limit(capacity)
                )
                if excluded_ids:
                    statement = statement.where(SecurityPlaybookRun.id.not_in(excluded_ids))
                queued_ids = list(db.scalars(statement))
            for queued_id in queued_ids:
                future = self._executor.submit(self._execute_run, queued_id)
                self._futures[queued_id] = future
                future.add_done_callback(lambda _future, item_id=queued_id: self._forget(item_id))

    def _recover_interrupted_runs(self) -> None:
        now = utc_now()
        with self._session_factory() as db:
            runs = list(db.scalars(
                select(SecurityPlaybookRun)
                .options(selectinload(SecurityPlaybookRun.steps))
                .where(SecurityPlaybookRun.status == "RUNNING")
            ))
            for run in runs:
                run.status = "CANCELLED" if run.cancel_requested else "FAILED"
                run.active_slot = None
                run.completed_at = now
                run.current_step = None
                run.error = (
                    "The assessment was cancelled while the application stopped."
                    if run.cancel_requested
                    else "The application stopped before this assessment completed. Start a new run."
                )
                for step in run.steps:
                    if step.status == "RUNNING":
                        step.status = "FAILED"
                        step.completed_at = now
                        step.error = "Interrupted by application restart"
                    elif step.status == "PENDING":
                        step.status = "CANCELLED"
                        step.completed_at = now
                run.summary_json = json.dumps(self._summary(run.steps))
            db.commit()

    def _claim(self, run_id: int) -> PlaybookTarget | None:
        now = utc_now()
        with self._session_factory() as db:
            result = db.execute(
                update(SecurityPlaybookRun)
                .where(SecurityPlaybookRun.id == run_id, SecurityPlaybookRun.status == "QUEUED")
                .values(status="RUNNING", started_at=now, current_step=None, active_slot=1)
            )
            if result.rowcount != 1:
                db.rollback()
                return None
            db.commit()
            run = db.get(SecurityPlaybookRun, run_id)
            if run is None:
                return None
            return PlaybookTarget(
                run_id=run.id,
                device_id=run.device_id,
                target_name=run.target_name,
                target_ip=run.target_ip,
                profile=run.profile,
            )

    def _execute_run(self, run_id: int) -> None:
        target: PlaybookTarget | None = None
        try:
            target = self._claim(run_id)
            if target is None:
                return
            for step_key, _name in PLAYBOOK_STEPS:
                if self._cancellation_requested(run_id):
                    self._finish_cancelled(run_id)
                    return
                self._ensure_target_unchanged(target)
                self._execute_step(target, step_key)
            self._finalize(run_id)
        except Exception as exc:
            if target is None:
                self._fail_queued_run(run_id, exc)
            else:
                self._fail_run(run_id, exc)

    def _ensure_target_unchanged(self, target: PlaybookTarget) -> None:
        with self._session_factory() as db:
            device = db.get(Device, target.device_id)
            if device is None:
                raise RuntimeError("The registered target was deleted before the assessment started")
            if device.ip_address != target.target_ip:
                raise RuntimeError(
                    "The registered target IP changed after this assessment was queued; start a new run"
                )
            rejection = scan_target_rejection_reason(
                device.ip_address,
                mac_address=device.mac_address,
            )
            if rejection:
                raise RuntimeError(rejection)

    def _cancellation_requested(self, run_id: int) -> bool:
        if self._stop_requested.is_set():
            return True
        with self._session_factory() as db:
            state = db.execute(
                select(SecurityPlaybookRun.status, SecurityPlaybookRun.cancel_requested)
                .where(SecurityPlaybookRun.id == run_id)
            ).one_or_none()
            return state is None or state.status != "RUNNING" or bool(state.cancel_requested)

    def _execute_step(self, target: PlaybookTarget, step_key: str) -> None:
        with self._session_factory() as db:
            step = db.scalar(select(SecurityPlaybookStep).where(
                SecurityPlaybookStep.run_id == target.run_id,
                SecurityPlaybookStep.step_key == step_key,
            ))
            run = db.get(SecurityPlaybookRun, target.run_id)
            if (
                step is None
                or run is None
                or run.status != "RUNNING"
                or run.cancel_requested
                or self._stop_requested.is_set()
                or step.status != "PENDING"
            ):
                return
            step.status = "RUNNING"
            step.started_at = utc_now()
            run.current_step = step.step_key
            db.commit()

        started = time.monotonic()
        try:
            output = self._run_step(target, step_key)
        except Exception as exc:
            self._complete_step(target.run_id, step_key, "FAILED", started, error=_error_text(exc))
        else:
            failure = _result_error(output)
            self._complete_step(
                target.run_id,
                step_key,
                "FAILED" if failure else "COMPLETED",
                started,
                output=_render_step_output(output),
                error=failure,
            )

    def _run_step(self, target: PlaybookTarget, step_key: str) -> object:
        rejection = scan_target_rejection_reason(target.target_ip)
        if rejection:
            raise RuntimeError(rejection)
        if step_key == "powershell_tcp":
            port_counts = {"FAST": 8, "DETAILED": 24, "AGGRESSIVE": 64}
            timeouts = {"FAST": 1, "DETAILED": 2, "AGGRESSIVE": 3}
            ports = list(NMAP_TOP_1000_TCP_PORTS[:port_counts[target.profile]])
            return test_connection_ports(target.target_ip, ports, timeouts[target.profile])
        if step_key == "traceroute":
            device = Device(id=target.device_id, name=target.target_name, ip_address=target.target_ip)
            return trace_registered_device(device)
        if step_key == "attack_surface":
            return self._run_attack_surface(target)
        if step_key == "dns_identity":
            return query_dns(target.target_ip)
        raise RuntimeError(f"Unknown playbook step: {step_key}")

    def _run_attack_surface(self, target: PlaybookTarget) -> dict:
        mdns = _mdns_enrichment(target.target_ip)
        # Vulnerability scans own their commit lifecycle, so they receive an
        # isolated session rather than the runner's progress session.
        with self._session_factory() as db:
            device = db.get(Device, target.device_id)
            if device is None or device.ip_address != target.target_ip:
                raise RuntimeError("The registered target changed before attack-surface analysis")
            scan = run_vulnerability_scan(device, db, target.profile)
            scan_id = scan.id
        with self._session_factory() as db:
            scan = db.scalar(
                select(VulnerabilityScan)
                .options(selectinload(VulnerabilityScan.findings), selectinload(VulnerabilityScan.tool_runs))
                .where(VulnerabilityScan.id == scan_id)
            )
            if scan is None:
                raise RuntimeError("The completed vulnerability scan could not be loaded")
            severity_counts: dict[str, int] = {}
            for finding in scan.findings:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            identified_ports = {
                item.port
                for item in scan.findings
                if item.port is not None and item.category == "SERVICE_IDENTIFICATION"
            }
            unresolved_ports = {
                item.port
                for item in scan.findings
                if item.port is not None and item.category == "CVE_CORRELATION"
            }
            cve_ready_ports = {
                item.port
                for item in scan.findings
                if item.port is not None and item.service_product and item.service_version
            }
            exact_cpe_ports = {
                item.port
                for item in scan.findings
                if item.port is not None and item.service_cpe
            }
            cve_ready_ports -= unresolved_ports
            exact_cpe_ports -= unresolved_ports
            open_ports = identified_ports | unresolved_ports
            evidence_coverage = {
                "open_services": len(open_ports),
                "cve_ready_services": len(cve_ready_ports),
                "exact_cpe_services": len(exact_cpe_ports),
                "unresolved_ports": sorted(unresolved_ports),
                "coverage_percent": (
                    round(len(cve_ready_ports) * 100 / len(open_ports))
                    if open_ports
                    else 0
                ),
            }
            scan_provenance = None
            for finding in scan.findings:
                if finding.category == "SCAN_PROVENANCE":
                    try:
                        saved = json.loads(finding.description)
                        if isinstance(saved, dict):
                            scan_provenance = saved
                    except (TypeError, ValueError):
                        pass
                    break
            ordered_findings = sorted(scan.findings, key=lambda item: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(item.severity, 5),
                0 if item.cve_id else 1, item.port or 0, item.title,
            ))
            return _fit_attack_surface_output({
                "output_schema_version": 2,
                "scan_id": scan.id,
                "status": scan.status,
                "profile": scan.profile,
                "finding_count": len(scan.findings),
                "cve_candidates": sum(1 for item in scan.findings if item.cve_id),
                "cve_matches": sum(1 for item in scan.findings if item.cve_id),
                "cve_evidence": evidence_coverage,
                "severity_counts": severity_counts,
                "mdns_enrichment": mdns,
                "tool_runs": [_compact_tool_run(run) for run in scan.tool_runs],
                **({"scan_provenance": scan_provenance} if scan_provenance else {}),
                "findings": [_compact_finding(item) for item in ordered_findings[:50]],
                "omitted_finding_count": max(0, len(ordered_findings) - 50),
            })

    def _complete_step(
        self,
        run_id: int,
        step_key: str,
        status: str,
        started: float,
        *,
        output: str | None = None,
        error: str | None = None,
    ) -> None:
        with self._session_factory() as db:
            run = db.get(SecurityPlaybookRun, run_id)
            step = db.scalar(select(SecurityPlaybookStep).where(
                SecurityPlaybookStep.run_id == run_id,
                SecurityPlaybookStep.step_key == step_key,
            ))
            if run is None or run.status != "RUNNING" or step is None or step.status != "RUNNING":
                return
            step.status = status
            step.completed_at = utc_now()
            step.duration_ms = round((time.monotonic() - started) * 1000, 2)
            step.output = output
            step.error = error
            if run.current_step == step.step_key:
                run.current_step = None
            db.commit()

    def _finish_cancelled(self, run_id: int) -> None:
        now = utc_now()
        with self._session_factory() as db:
            run = db.scalar(
                select(SecurityPlaybookRun)
                .options(selectinload(SecurityPlaybookRun.steps))
                .where(SecurityPlaybookRun.id == run_id)
            )
            if run is None or run.status not in ACTIVE_RUN_STATUSES:
                return
            for step in run.steps:
                if step.status == "PENDING":
                    step.status = "CANCELLED"
                    step.completed_at = now
            run.status = "CANCELLED"
            run.active_slot = None
            run.cancel_requested = True
            run.current_step = None
            run.completed_at = now
            run.summary_json = json.dumps(self._summary(run.steps))
            db.commit()

    def _finalize(self, run_id: int) -> None:
        with self._session_factory() as db:
            run = db.scalar(
                select(SecurityPlaybookRun)
                .options(selectinload(SecurityPlaybookRun.steps))
                .where(SecurityPlaybookRun.id == run_id)
            )
            if run is None:
                return
            completed = sum(step.status == "COMPLETED" for step in run.steps)
            final_status = (
                "COMPLETED"
                if completed == len(run.steps)
                else ("PARTIAL" if completed else "FAILED")
            )
            result = db.execute(
                update(SecurityPlaybookRun)
                .where(
                    SecurityPlaybookRun.id == run_id,
                    SecurityPlaybookRun.status == "RUNNING",
                    SecurityPlaybookRun.cancel_requested.is_(False),
                )
                .values(
                    status=final_status,
                    active_slot=None,
                    error="Every assessment step failed" if final_status == "FAILED" else None,
                    current_step=None,
                    completed_at=utc_now(),
                    summary_json=json.dumps(self._summary(run.steps)),
                )
            )
            if result.rowcount == 1:
                db.commit()
                return
            db.rollback()
        self._finish_cancelled(run_id)

    def _fail_run(self, run_id: int, exc: Exception) -> None:
        now = utc_now()
        with self._session_factory() as db:
            run = db.scalar(
                select(SecurityPlaybookRun)
                .options(selectinload(SecurityPlaybookRun.steps))
                .where(SecurityPlaybookRun.id == run_id)
            )
            if run is None or run.status != "RUNNING":
                return
            run.status = "FAILED"
            run.active_slot = None
            run.current_step = None
            run.completed_at = now
            run.error = _error_text(exc)
            for step in run.steps:
                if step.status == "RUNNING":
                    step.status = "FAILED"
                    step.completed_at = now
                    step.error = run.error
                elif step.status == "PENDING":
                    step.status = "CANCELLED"
                    step.completed_at = now
            run.summary_json = json.dumps(self._summary(run.steps))
            db.commit()

    def _fail_queued_run(self, run_id: int, exc: Exception) -> None:
        now = utc_now()
        try:
            with self._session_factory() as db:
                run = db.scalar(
                    select(SecurityPlaybookRun)
                    .options(selectinload(SecurityPlaybookRun.steps))
                    .where(SecurityPlaybookRun.id == run_id)
                )
                if run is None or run.status != "QUEUED":
                    return
                run.status = "FAILED"
                run.active_slot = None
                run.completed_at = now
                run.error = _error_text(exc)
                for step in run.steps:
                    if step.status == "PENDING":
                        step.status = "CANCELLED"
                        step.completed_at = now
                run.summary_json = json.dumps(self._summary(run.steps))
                db.commit()
        except Exception:
            logger.exception("Could not persist a failed security playbook claim for run %s", run_id)

    @staticmethod
    def _summary(steps: list[SecurityPlaybookStep]) -> dict:
        summary: dict[str, object] = {
            "total_steps": len(steps),
            "completed_steps": sum(step.status == "COMPLETED" for step in steps),
            "failed_steps": sum(step.status == "FAILED" for step in steps),
            "cancelled_steps": sum(step.status == "CANCELLED" for step in steps),
        }
        attack_step = next((step for step in steps if step.step_key == "attack_surface"), None)
        if attack_step and attack_step.output:
            try:
                attack_summary = json.loads(attack_step.output)
            except json.JSONDecodeError:
                attack_summary = None
            if isinstance(attack_summary, dict):
                summary["vulnerability_scan_id"] = attack_summary.get("scan_id")
                summary["findings"] = attack_summary.get("finding_count", 0)
                summary["cve_candidates"] = attack_summary.get("cve_candidates", 0)
                evidence = attack_summary.get("cve_evidence")
                if isinstance(evidence, dict):
                    summary["cve_ready_services"] = evidence.get("cve_ready_services", 0)
                    summary["open_services"] = evidence.get("open_services", 0)
                    summary["cve_coverage_percent"] = evidence.get("coverage_percent", 0)
                mdns = attack_summary.get("mdns_enrichment")
                if isinstance(mdns, dict):
                    summary["mdns_status"] = mdns.get("status")
        return summary
