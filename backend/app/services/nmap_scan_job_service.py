import json
import logging
import re
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import Device, NmapPortCache, NmapScanJob, utc_now
from app.services.nmap_top_ports import NMAP_TOP_1000_TCP_PORTS
from app.services.scan_policy import scan_target_rejection_reason
from app.services.security_toolbox_service import _filter_output, nmap_tcp_scan


ACTIVE_STATUSES = ("QUEUED", "RUNNING")
TERMINAL_STATUSES = ("COMPLETED", "PARTIAL", "FAILED", "CANCELLED")
CLOSED_CACHE_TTL = timedelta(minutes=10)
OPEN_HISTORY_TTL = timedelta(hours=24)
_PORT_STATE = re.compile(r"(?m)^(\d+)/tcp\s+(open|closed)\b")
_FILTERING_SIGNAL = re.compile(
    r"(?im)(filtered|no-response|host timeout|command timed out|retransmission cap)"
)
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanTarget:
    job_id: int
    device_id: int
    target_ip: str
    scan_mode: str
    profile: str
    traffic_policy: str
    show_reason: bool
    ports: list[int]
    grep: str | None


def build_nmap_scan_job(
    device: Device,
    *,
    ports: list[int],
    scan_mode: str,
    profile: str,
    traffic_policy: str,
    service_detection: bool,
    show_reason: bool,
    grep: str | None,
    requested_by: str,
    client_ip: str | None,
) -> NmapScanJob:
    rejection = scan_target_rejection_reason(device.ip_address, mac_address=device.mac_address)
    if rejection:
        raise ValueError(rejection)
    requested_ports = (
        list(NMAP_TOP_1000_TCP_PORTS) if scan_mode == "TOP_1000" else list(dict.fromkeys(ports))
    )
    effective_profile = "FAST_VERSION" if service_detection and profile == "FAST" else profile
    return NmapScanJob(
        device_id=device.id,
        target_name=device.name,
        target_ip=device.ip_address,
        requested_by=requested_by[:80],
        client_ip=client_ip,
        scan_mode=scan_mode,
        profile=effective_profile,
        traffic_policy=traffic_policy,
        show_reason=show_reason,
        grep=grep,
        ports_json=json.dumps(requested_ports),
        active_slot=1,
    )


def load_nmap_scan_job(job_id: int, db: Session) -> NmapScanJob | None:
    return db.get(NmapScanJob, job_id)


def _bounded_error(exc: Exception) -> str:
    return (" ".join(str(exc).split()) or exc.__class__.__name__)[:1000]


def _port_states(output: str, requested_ports: list[int]) -> tuple[set[int], set[int]]:
    open_ports: set[int] = set()
    closed_ports: set[int] = set()
    for port_text, state in _PORT_STATE.findall(output):
        port = int(port_text)
        (open_ports if state == "open" else closed_ports).add(port)
    # When Nmap collapses a fully closed range into "Not shown", every
    # non-open requested port is safe to cache only if no filtered state exists.
    hidden_closed = re.search(r"(?im)Not shown:\s+(\d+)\s+closed tcp ports?", output)
    if hidden_closed and not re.search(r"(?im)\bfiltered\b", output):
        inferred = set(requested_ports) - open_ports
        if len(inferred) == int(hidden_closed.group(1)):
            closed_ports.update(inferred)
    return open_ports, closed_ports


class NmapScanJobRunner:
    """Durable single-worker Nmap queue with adaptive stages and state cache."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="nmap-scan")
        self._futures: dict[int, Future] = {}
        self._lock = threading.RLock()
        self._accepting = False
        self._stopping = threading.Event()

    def start(self) -> None:
        self._recover_interrupted_jobs()
        self._stopping.clear()
        self._accepting = True
        self._pump()

    def submit(self, job_id: int) -> bool:
        with self._lock:
            if not self._accepting:
                return False
        self._pump()
        return True

    def cancel(self, job_id: int) -> bool:
        now = utc_now()
        with self._session_factory() as db:
            job = db.get(NmapScanJob, job_id)
            if job is None or job.status not in ACTIVE_STATUSES:
                return False
            job.cancel_requested = True
            if job.status == "QUEUED":
                job.status = "CANCELLED"
                job.phase = "CANCELLED"
                job.active_slot = None
                job.completed_at = now
            db.commit()
        with self._lock:
            future = self._futures.get(job_id)
            if future is not None:
                future.cancel()
        return True

    def shutdown(self) -> None:
        self._accepting = False
        self._stopping.set()
        with self._session_factory() as db:
            db.execute(
                update(NmapScanJob)
                .where(NmapScanJob.status == "RUNNING")
                .values(cancel_requested=True)
            )
            db.commit()
        self._executor.shutdown(wait=True, cancel_futures=True)

    def _pump(self) -> None:
        with self._lock:
            for job_id, future in list(self._futures.items()):
                if future.done():
                    self._futures.pop(job_id, None)
            if not self._accepting or self._futures:
                return
            with self._session_factory() as db:
                job_id = db.scalar(
                    select(NmapScanJob.id)
                    .where(NmapScanJob.status == "QUEUED")
                    .order_by(NmapScanJob.created_at, NmapScanJob.id)
                    .limit(1)
                )
            if job_id is None:
                return
            future = self._executor.submit(self._execute, job_id)
            self._futures[job_id] = future
            future.add_done_callback(lambda _future, item_id=job_id: self._finished(item_id))

    def _finished(self, job_id: int) -> None:
        with self._lock:
            self._futures.pop(job_id, None)
        self._pump()

    def _recover_interrupted_jobs(self) -> None:
        with self._session_factory() as db:
            jobs = list(db.scalars(select(NmapScanJob).where(NmapScanJob.status == "RUNNING")))
            for job in jobs:
                job.status = "CANCELLED" if job.cancel_requested else "FAILED"
                job.phase = job.status
                job.active_slot = None
                job.completed_at = utc_now()
                job.error = "Nmap job was interrupted by application restart"
            db.commit()

    def _claim(self, job_id: int) -> ScanTarget | None:
        with self._session_factory() as db:
            result = db.execute(
                update(NmapScanJob)
                .where(NmapScanJob.id == job_id, NmapScanJob.status == "QUEUED")
                .values(
                    status="RUNNING", phase="DISCOVERY", progress_percent=5,
                    started_at=utc_now(), active_slot=1,
                )
            )
            if result.rowcount != 1:
                db.rollback()
                return None
            db.commit()
            job = db.get(NmapScanJob, job_id)
            if job is None:
                return None
            return ScanTarget(
                job_id=job.id, device_id=job.device_id, target_ip=job.target_ip,
                scan_mode=job.scan_mode, profile=job.profile,
                traffic_policy=job.traffic_policy, show_reason=job.show_reason,
                ports=job.ports, grep=job.grep,
            )

    def _execute(self, job_id: int) -> None:
        started = time.monotonic()
        try:
            target = self._claim(job_id)
            if target is None:
                return
            self._ensure_target(target)
            self._run_adaptive_scan(target, started)
        except Exception as exc:
            logger.exception("Nmap scan job %s failed", job_id)
            self._fail(job_id, exc, started)

    def _ensure_target(self, target: ScanTarget) -> None:
        with self._session_factory() as db:
            device = db.get(Device, target.device_id)
            if device is None or device.ip_address != target.target_ip:
                raise RuntimeError("Registered target changed after this Nmap job was queued")
            rejection = scan_target_rejection_reason(device.ip_address, mac_address=device.mac_address)
            if rejection:
                raise RuntimeError(rejection)

    def _cancel_requested(self, job_id: int) -> bool:
        if self._stopping.is_set():
            return True
        with self._session_factory() as db:
            row = db.execute(
                select(NmapScanJob.status, NmapScanJob.cancel_requested)
                .where(NmapScanJob.id == job_id)
            ).one_or_none()
            return row is None or row.status != "RUNNING" or bool(row.cancel_requested)

    def _recent_cache(self, target: ScanTarget) -> tuple[set[int], set[int]]:
        now = utc_now()
        with self._session_factory() as db:
            recent_closed = set(db.scalars(
                select(NmapPortCache.port).where(
                    NmapPortCache.device_id == target.device_id,
                    NmapPortCache.target_ip == target.target_ip,
                    NmapPortCache.state == "CLOSED",
                    NmapPortCache.observed_at >= now - CLOSED_CACHE_TTL,
                )
            ))
            previous_open = set(db.scalars(
                select(NmapPortCache.port).where(
                    NmapPortCache.device_id == target.device_id,
                    NmapPortCache.target_ip == target.target_ip,
                    NmapPortCache.state == "OPEN",
                    NmapPortCache.observed_at >= now - OPEN_HISTORY_TTL,
                )
            ))
        return recent_closed, previous_open

    def _update_cache(
        self, target: ScanTarget, open_ports: set[int], closed_ports: set[int]
    ) -> None:
        observed_at = utc_now()
        with self._session_factory() as db:
            for port, state in [
                *((port, "OPEN") for port in open_ports),
                *((port, "CLOSED") for port in closed_ports),
            ]:
                row = db.scalar(select(NmapPortCache).where(
                    NmapPortCache.device_id == target.device_id,
                    NmapPortCache.target_ip == target.target_ip,
                    NmapPortCache.port == port,
                ))
                if row is None:
                    db.add(NmapPortCache(
                        device_id=target.device_id, target_ip=target.target_ip,
                        port=port, state=state, observed_at=observed_at,
                    ))
                else:
                    row.state = state
                    row.observed_at = observed_at
            db.commit()

    def _run_adaptive_scan(self, target: ScanTarget, started: float) -> None:
        recent_closed, previous_open = self._recent_cache(target)
        requested = set(target.ports)
        cached_closed = requested & recent_closed
        candidates = sorted(requested - cached_closed)
        cache_note = (
            f"Cache: skipped {len(cached_closed)} port(s) confirmed closed in the last 10 minutes."
            if cached_closed else "Cache: no recent closed-port entries were reused."
        )
        if not candidates:
            self._complete(
                target.job_id, status="COMPLETED", phase="CACHE_COMPLETE",
                output=f"{cache_note}\nNo network probes were required.",
                open_ports=[], scanned_count=0, cached_closed=len(cached_closed),
                cache_hit=True, ban_signal=False, ban_reason=None, started=started,
            )
            return

        use_ranked_mode = target.scan_mode == "TOP_1000" and not cached_closed
        discovery = nmap_tcp_scan(
            target.target_ip,
            candidates,
            False,
            scan_mode="TOP_1000" if use_ranked_mode else "CUSTOM",
            profile="FAST",
            discovery_profile=target.profile,
            show_reason=target.show_reason,
            traffic_policy=target.traffic_policy,
        )
        open_ports, closed_ports = _port_states(discovery.output, candidates)
        self._update_cache(target, open_ports, closed_ports)
        filtering_signal = bool(_FILTERING_SIGNAL.search(discovery.output))
        missing_previous = previous_open & set(candidates)
        ban_signal = bool(missing_previous and not open_ports and filtering_signal)
        ban_reason = (
            "Previously open ports disappeared while Nmap reported filtering, loss or timeout; "
            "an IDS/firewall block is possible."
            if ban_signal else None
        )
        discovery_output = (
            f"Phase 1 - adaptive discovery ({len(candidates)} network-tested, "
            f"{len(cached_closed)} cached closed)\n{discovery.output}\n\n{cache_note}"
        )
        with self._session_factory() as db:
            job = db.get(NmapScanJob, target.job_id)
            if job is None or job.status != "RUNNING":
                return
            job.progress_percent = 55
            job.output = discovery_output
            job.open_ports_json = json.dumps(sorted(open_ports))
            job.scanned_port_count = len(candidates)
            job.cached_closed_count = len(cached_closed)
            job.cache_hit = bool(cached_closed)
            job.ban_signal = ban_signal
            job.ban_reason = ban_reason
            db.commit()

        if self._cancel_requested(target.job_id):
            self._finish_cancelled(target.job_id, started)
            return

        final_output = discovery_output
        partial = discovery.exit_code != 0 or "open-port status is incomplete" in discovery.output
        if target.profile != "FAST" and open_ports:
            with self._session_factory() as db:
                job = db.get(NmapScanJob, target.job_id)
                if job is None or job.status != "RUNNING":
                    return
                job.phase = "FINGERPRINT"
                job.progress_percent = 65
                db.commit()
            fingerprint = nmap_tcp_scan(
                target.target_ip,
                sorted(open_ports),
                False,
                scan_mode="CUSTOM",
                profile=target.profile,
                show_reason=target.show_reason,
                traffic_policy=target.traffic_policy,
            )
            final_output += (
                f"\n\nPhase 2 - {target.profile.replace('_', ' ').title()} fingerprinting "
                f"on {len(open_ports)} open port(s)\n{fingerprint.output}"
            )
            partial = partial or fingerprint.exit_code != 0 or bool(
                re.search(r"(?im)(host timeout|command timed out)", fingerprint.output)
            )
            if self._cancel_requested(target.job_id):
                with self._session_factory() as db:
                    job = db.get(NmapScanJob, target.job_id)
                    if job is not None:
                        job.output = final_output
                        db.commit()
                self._finish_cancelled(target.job_id, started)
                return

        if ban_reason:
            final_output += f"\n\nPossible block signal: {ban_reason}"
        filtered_output = _filter_output(final_output, target.grep)
        if target.grep and not filtered_output:
            filtered_output = f"No Nmap output matched {target.grep!r}."
        self._complete(
            target.job_id,
            status="PARTIAL" if partial or ban_signal else "COMPLETED",
            phase="COMPLETED",
            output=filtered_output,
            open_ports=sorted(open_ports),
            scanned_count=len(candidates),
            cached_closed=len(cached_closed),
            cache_hit=bool(cached_closed),
            ban_signal=ban_signal,
            ban_reason=ban_reason,
            started=started,
        )

    def _complete(
        self,
        job_id: int,
        *,
        status: str,
        phase: str,
        output: str,
        open_ports: list[int],
        scanned_count: int,
        cached_closed: int,
        cache_hit: bool,
        ban_signal: bool,
        ban_reason: str | None,
        started: float,
    ) -> None:
        with self._session_factory() as db:
            job = db.get(NmapScanJob, job_id)
            if job is None or job.status != "RUNNING":
                return
            job.status = status
            job.phase = phase
            job.progress_percent = 100
            job.active_slot = None
            job.output = output[:100_000]
            job.open_ports_json = json.dumps(open_ports)
            job.scanned_port_count = scanned_count
            job.cached_closed_count = cached_closed
            job.cache_hit = cache_hit
            job.ban_signal = ban_signal
            job.ban_reason = ban_reason
            job.duration_ms = round((time.monotonic() - started) * 1000, 2)
            job.completed_at = utc_now()
            db.commit()

    def _finish_cancelled(self, job_id: int, started: float) -> None:
        with self._session_factory() as db:
            job = db.get(NmapScanJob, job_id)
            if job is None or job.status not in ACTIVE_STATUSES:
                return
            job.status = "CANCELLED"
            job.phase = "CANCELLED"
            job.active_slot = None
            job.cancel_requested = True
            job.completed_at = utc_now()
            job.duration_ms = round((time.monotonic() - started) * 1000, 2)
            db.commit()

    def _fail(self, job_id: int, exc: Exception, started: float) -> None:
        with self._session_factory() as db:
            job = db.get(NmapScanJob, job_id)
            if job is None or job.status not in ACTIVE_STATUSES:
                return
            job.status = "FAILED"
            job.phase = "FAILED"
            job.active_slot = None
            job.progress_percent = 100
            job.error = _bounded_error(exc)
            job.duration_ms = round((time.monotonic() - started) * 1000, 2)
            job.completed_at = utc_now()
            db.commit()
