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
    query_dns,
    test_connection_ports,
    trace_registered_device,
)
from app.services.vulnerability_service import run_vulnerability_scan


PLAYBOOK_STEPS = (
    ("powershell_tcp", "PowerShell TCP reachability"),
    ("traceroute", "Network path trace"),
    ("attack_surface", "Nmap exposure, NSE verification and CVE correlation"),
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
                .options(selectinload(VulnerabilityScan.findings))
                .where(VulnerabilityScan.id == scan_id)
            )
            if scan is None:
                raise RuntimeError("The completed vulnerability scan could not be loaded")
            severity_counts: dict[str, int] = {}
            for finding in scan.findings:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            return {
                "scan_id": scan.id,
                "status": scan.status,
                "profile": scan.profile,
                "finding_count": len(scan.findings),
                "cve_candidates": sum(1 for item in scan.findings if item.cve_id),
                "severity_counts": severity_counts,
                "findings": [
                    {
                        "severity": item.severity,
                        "category": item.category,
                        "title": item.title,
                        "port": item.port,
                        "cve_id": item.cve_id,
                        "cvss_score": item.cvss_score,
                        "match_confidence": item.match_confidence,
                        "known_exploited": item.known_exploited,
                        "epss_score": item.epss_score,
                        "validation_tool": item.validation_tool,
                        "validation_check_id": item.validation_check_id,
                        "validation_target": item.validation_target,
                    }
                    for item in scan.findings[:50]
                ],
            }

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
        return summary
