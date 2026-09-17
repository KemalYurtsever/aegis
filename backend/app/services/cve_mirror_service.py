import gzip
import hashlib
import io
import json
import logging
import re
import tempfile
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version
from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.models import CveMirrorState, LocalCveCpeMatch, LocalCveRecord, utc_now


NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
FIRST_NVD_YEAR = 2002
MAX_META_BYTES = 16 * 1024
MAX_COMPRESSED_BYTES = 160 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
IMPORT_BATCH_SIZE = 500
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MirrorCveMatch:
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    published: str | None


@dataclass(frozen=True)
class LocalCveLookup:
    matches: tuple[MirrorCveMatch, ...]
    total_results: int
    authoritative: bool


def _feed_names(mode: str, year: int | None = None) -> list[str]:
    current_year = datetime.now(timezone.utc).year
    normalized = mode.upper()
    if normalized == "MODIFIED":
        return ["modified"]
    if normalized == "RECENT":
        return ["recent"]
    if normalized == "YEAR":
        if year is None or year < FIRST_NVD_YEAR or year > current_year:
            raise ValueError(f"NVD year must be between {FIRST_NVD_YEAR} and {current_year}")
        return [str(year)]
    if normalized == "FULL":
        return [*(str(item) for item in range(FIRST_NVD_YEAR, current_year + 1)), "modified"]
    raise ValueError("Unknown CVE mirror synchronization mode")


def _fetch_small_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": "Aegis/0.1 local CVE mirror"})
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read(MAX_META_BYTES + 1)
    except HTTPError as exc:
        raise RuntimeError(f"NVD feed metadata request failed with HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("NVD feed metadata could not be reached") from exc
    if len(raw) > MAX_META_BYTES:
        raise RuntimeError("NVD feed metadata exceeded the safety limit")
    return raw.decode("utf-8", errors="strict")


def _parse_meta(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key.strip()] = value.strip()
    required = {"lastModifiedDate", "gzSize", "size", "sha256"}
    if not required.issubset(values):
        raise RuntimeError("NVD feed metadata is missing required fields")
    return values


def _download_feed(
    feed: str,
    *,
    cancelled: Callable[[], bool],
) -> tuple[dict, dict[str, str]]:
    prefix = f"{NVD_FEED_BASE}/nvdcve-2.0-{feed}"
    metadata = _parse_meta(_fetch_small_text(f"{prefix}.meta"))
    expected_compressed = int(metadata["gzSize"])
    expected_size = int(metadata["size"])
    if expected_compressed <= 0 or expected_compressed > MAX_COMPRESSED_BYTES:
        raise RuntimeError("NVD compressed feed size is outside the safety limit")
    if expected_size <= 0 or expected_size > MAX_UNCOMPRESSED_BYTES:
        raise RuntimeError("NVD expanded feed size is outside the safety limit")
    request = Request(f"{prefix}.json.gz", headers={"User-Agent": "Aegis/0.1 local CVE mirror"})
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-nvd-") as temporary_directory:
            compressed_path = Path(temporary_directory) / "feed.json.gz"
            json_path = Path(temporary_directory) / "feed.json"
            downloaded = 0
            with urlopen(request, timeout=90) as response, compressed_path.open("wb") as destination:
                while True:
                    if cancelled():
                        raise InterruptedError("CVE mirror synchronization cancelled")
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > MAX_COMPRESSED_BYTES:
                        raise RuntimeError("NVD compressed feed exceeded the safety limit")
                    destination.write(chunk)
            if downloaded != expected_compressed:
                raise RuntimeError("NVD compressed feed size did not match its metadata")
            digest = hashlib.sha256()
            expanded = 0
            with gzip.open(compressed_path, "rb") as source, json_path.open("wb") as destination:
                while True:
                    if cancelled():
                        raise InterruptedError("CVE mirror synchronization cancelled")
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    expanded += len(chunk)
                    if expanded > MAX_UNCOMPRESSED_BYTES:
                        raise RuntimeError("NVD expanded feed exceeded the safety limit")
                    digest.update(chunk)
                    destination.write(chunk)
            if expanded != expected_size or digest.hexdigest().upper() != metadata["sha256"].upper():
                raise RuntimeError("NVD feed integrity verification failed")
            with json_path.open("r", encoding="utf-8") as source:
                payload = json.load(source)
    except HTTPError as exc:
        raise RuntimeError(f"NVD feed download failed with HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        raise RuntimeError("NVD feed could not be downloaded or decoded") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise RuntimeError("NVD feed returned an unexpected JSON structure")
    return payload, metadata


def _english_description(cve: dict) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en" and item.get("value"):
            return " ".join(str(item["value"]).split())[:4000]
    return "No English description was supplied by NVD."


def _cvss(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key) or []
        if not candidates:
            continue
        data = candidates[0].get("cvssData") or {}
        try:
            score = float(data["baseScore"]) if data.get("baseScore") is not None else None
        except (TypeError, ValueError):
            score = None
        severity = str(data.get("baseSeverity") or candidates[0].get("baseSeverity") or "INFO").upper()
        return score, severity if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "INFO"
    return None, "INFO"


def _split_cpe23(value: str) -> list[str]:
    if not value.startswith("cpe:2.3:"):
        return []
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value[8:]:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    current.append("\\" if escaped else "")
    parts.append("".join(current))
    return parts


def _cpe_rows(cve_id: str, configurations: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, dict):
            return
        for match in value.get("cpeMatch") or []:
            if not isinstance(match, dict):
                continue
            criteria = str(match.get("criteria") or "")
            components = _split_cpe23(criteria)
            if len(components) < 4:
                continue
            rows.append({
                "cve_id": cve_id,
                "criteria": criteria[:1000],
                "match_criteria_id": str(match.get("matchCriteriaId") or "")[:50] or None,
                "vulnerable": bool(match.get("vulnerable", False)),
                "part": components[0][:1],
                "vendor": components[1][:255],
                "product": components[2][:255],
                "criteria_version": components[3][:255] or None,
                "version_start_including": str(match.get("versionStartIncluding") or "")[:255] or None,
                "version_start_excluding": str(match.get("versionStartExcluding") or "")[:255] or None,
                "version_end_including": str(match.get("versionEndIncluding") or "")[:255] or None,
                "version_end_excluding": str(match.get("versionEndExcluding") or "")[:255] or None,
            })
        visit(value.get("nodes"))

    visit(configurations)
    return rows


def _normalized_record(
    wrapper: object,
    imported_at: datetime,
) -> tuple[dict[str, object], list[dict[str, object]]] | None:
    if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
        return None
    cve = wrapper["cve"]
    cve_id = str(cve.get("id") or "").upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        return None
    score, severity = _cvss(cve)
    configurations = cve.get("configurations") or []
    record = {
        "cve_id": cve_id,
        "source_identifier": str(cve.get("sourceIdentifier") or "")[:255] or None,
        "vuln_status": str(cve.get("vulnStatus") or "")[:40] or None,
        "description": _english_description(cve),
        "cvss_score": score,
        "severity": severity,
        "published": str(cve.get("published") or "")[:40] or None,
        "last_modified": str(cve.get("lastModified") or "")[:40] or None,
        "configurations_json": json.dumps(configurations, separators=(",", ":")),
        "imported_at": imported_at,
    }
    return record, _cpe_rows(cve_id, configurations)


def _upsert_batch(db: Session, batch: list[tuple[dict[str, object], list[dict[str, object]]]]) -> None:
    records = [item[0] for item in batch]
    cve_ids = [str(item["cve_id"]) for item in records]
    statement = sqlite_insert(LocalCveRecord).values(records)
    statement = statement.on_conflict_do_update(
        index_elements=[LocalCveRecord.cve_id],
        set_={
            column: getattr(statement.excluded, column)
            for column in (
                "source_identifier", "vuln_status", "description", "cvss_score",
                "severity", "published", "last_modified", "configurations_json", "imported_at",
            )
        },
    )
    db.execute(statement)
    db.execute(delete(LocalCveCpeMatch).where(LocalCveCpeMatch.cve_id.in_(cve_ids)))
    cpe_rows = [row for _record, rows in batch for row in rows]
    if cpe_rows:
        db.execute(sqlite_insert(LocalCveCpeMatch), cpe_rows)
    db.commit()


def import_nvd_feed(
    db: Session,
    payload: dict,
    *,
    progress: Callable[[int], None] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> int:
    vulnerabilities = payload.get("vulnerabilities") or []
    total = len(vulnerabilities)
    imported = 0
    imported_at = utc_now()
    for offset in range(0, total, IMPORT_BATCH_SIZE):
        if cancelled():
            raise InterruptedError("CVE mirror synchronization cancelled")
        batch = [
            normalized
            for wrapper in vulnerabilities[offset: offset + IMPORT_BATCH_SIZE]
            if (normalized := _normalized_record(wrapper, imported_at)) is not None
        ]
        if batch:
            _upsert_batch(db, batch)
            imported += len(batch)
        if progress:
            progress(min(total, offset + IMPORT_BATCH_SIZE))
    return imported


@lru_cache(maxsize=262_144)
def _natural_key(value: str) -> tuple[tuple[int, object], ...]:
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token.casefold())
        for token in re.findall(r"\d+|[A-Za-z]+", value)
    )


@lru_cache(maxsize=262_144)
def _parsed_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _compare_versions(left: str, right: str) -> int:
    left_value, right_value = _parsed_version(left), _parsed_version(right)
    if left_value is not None and right_value is not None:
        return (left_value > right_value) - (left_value < right_value)
    left_key, right_key = _natural_key(left), _natural_key(right)
    return (left_key > right_key) - (left_key < right_key)


def _version_matches(row: LocalCveCpeMatch, version: str) -> bool:
    criteria_version = row.criteria_version
    if criteria_version == "-" and version != "-":
        return False
    if criteria_version not in {None, "", "*", "-"} and criteria_version != version:
        return False
    if row.version_start_including and _compare_versions(version, row.version_start_including) < 0:
        return False
    if row.version_start_excluding and _compare_versions(version, row.version_start_excluding) <= 0:
        return False
    if row.version_end_including and _compare_versions(version, row.version_end_including) > 0:
        return False
    if row.version_end_excluding and _compare_versions(version, row.version_end_excluding) >= 0:
        return False
    return True


def lookup_local_cves(db: Session, cpe23: str, *, limit: int = 50) -> LocalCveLookup | None:
    components = _split_cpe23(cpe23)
    if len(components) < 4:
        return None
    part, vendor, product, version = components[:4]
    state = db.get(CveMirrorState, 1)
    eligible_versions = ["", "*", version]
    if version == "-":
        eligible_versions.append("-")
    candidate_rows = db.execute(
        select(
            LocalCveCpeMatch.cve_id,
            LocalCveCpeMatch.criteria_version,
            LocalCveCpeMatch.version_start_including,
            LocalCveCpeMatch.version_start_excluding,
            LocalCveCpeMatch.version_end_including,
            LocalCveCpeMatch.version_end_excluding,
        )
        .where(
            LocalCveCpeMatch.part == part,
            LocalCveCpeMatch.vendor == vendor,
            LocalCveCpeMatch.product == product,
            LocalCveCpeMatch.vulnerable.is_(True),
            or_(
                LocalCveCpeMatch.criteria_version.is_(None),
                LocalCveCpeMatch.criteria_version.in_(eligible_versions),
            ),
        )
    ).all()
    matched_ids = {
        row.cve_id
        for row in candidate_rows
        if _version_matches(row, version)
    }
    # An interrupted incremental refresh does not invalidate the last complete
    # baseline; imports commit bounded batches and preserve the existing corpus.
    authoritative = bool(state and state.baseline_complete)
    if not matched_ids:
        return LocalCveLookup(matches=(), total_results=0, authoritative=True) if authoritative else None

    applicable = (
        LocalCveRecord.cve_id.in_(matched_ids),
        or_(
            LocalCveRecord.vuln_status.is_(None),
            LocalCveRecord.vuln_status.not_in(("Rejected", "REJECTED")),
        ),
    )
    total_results = db.scalar(
        select(func.count(LocalCveRecord.cve_id)).where(*applicable)
    ) or 0
    ordered = db.execute(
        select(
            LocalCveRecord.cve_id,
            LocalCveRecord.description,
            LocalCveRecord.cvss_score,
            LocalCveRecord.severity,
            LocalCveRecord.published,
        )
        .where(*applicable)
        .order_by(
            LocalCveRecord.cvss_score.is_not(None).desc(),
            LocalCveRecord.cvss_score.desc(),
            LocalCveRecord.published.desc(),
        )
        .limit(limit)
    ).all()
    if not ordered and not authoritative:
        return None
    return LocalCveLookup(
        matches=tuple(MirrorCveMatch(
            cve_id=item.cve_id,
            description=item.description,
            cvss_score=item.cvss_score,
            severity=item.severity,
            published=item.published,
        ) for item in ordered),
        total_results=int(total_results),
        authoritative=authoritative,
    )


class CveMirrorRunner:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cve-mirror")
        self._future: Future | None = None
        self._cancel = threading.Event()
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._session_factory() as db:
            state = db.get(CveMirrorState, 1)
            if state is None:
                db.add(CveMirrorState(id=1))
            elif state.status == "SYNCING":
                state.status = "FAILED"
                state.error = "CVE mirror synchronization was interrupted by application restart"
                state.completed_at = utc_now()
            db.commit()

    def sync(self, mode: str, year: int | None = None) -> bool:
        feeds = _feed_names(mode, year)
        with self._lock:
            if self._future and not self._future.done():
                return False
            self._cancel.clear()
            with self._session_factory() as db:
                state = db.get(CveMirrorState, 1) or CveMirrorState(id=1)
                db.add(state)
                state.status = "SYNCING"
                state.mode = mode.upper()
                state.current_feed = feeds[0]
                state.feeds_completed = 0
                state.feeds_total = len(feeds)
                state.progress_percent = 0
                state.cancel_requested = False
                state.started_at = utc_now()
                state.completed_at = None
                state.error = None
                db.commit()
            self._future = self._executor.submit(self._run, mode.upper(), feeds)
            return True

    def cancel(self) -> bool:
        with self._lock:
            if self._future is None or self._future.done():
                return False
            self._cancel.set()
        with self._session_factory() as db:
            state = db.get(CveMirrorState, 1)
            if state:
                state.cancel_requested = True
                db.commit()
        return True

    def shutdown(self) -> None:
        self._cancel.set()
        self._executor.shutdown(wait=True, cancel_futures=True)

    def _set_progress(self, feed: str, completed: int, total_feeds: int, fraction: float) -> None:
        with self._session_factory() as db:
            state = db.get(CveMirrorState, 1)
            if state is None:
                return
            state.current_feed = feed
            state.feeds_completed = completed
            state.progress_percent = min(99, round(((completed + fraction) / total_feeds) * 100))
            db.commit()

    def _run(self, mode: str, feeds: list[str]) -> None:
        try:
            latest_modified = None
            for index, feed in enumerate(feeds):
                if self._cancel.is_set():
                    raise InterruptedError("CVE mirror synchronization cancelled")
                self._set_progress(feed, index, len(feeds), 0.05)
                payload, metadata = _download_feed(feed, cancelled=self._cancel.is_set)
                latest_modified = metadata["lastModifiedDate"]
                total_records = len(payload.get("vulnerabilities") or [])
                with self._session_factory() as db:
                    import_nvd_feed(
                        db,
                        payload,
                        progress=lambda count, item=index, total=max(1, total_records): self._set_progress(
                            feed, item, len(feeds), 0.15 + (count / total) * 0.8
                        ),
                        cancelled=self._cancel.is_set,
                    )
                self._set_progress(feed, index + 1, len(feeds), 0)
            with self._session_factory() as db:
                state = db.get(CveMirrorState, 1)
                if state is None:
                    return
                state.status = "READY"
                state.current_feed = None
                state.feeds_completed = len(feeds)
                state.progress_percent = 100
                state.record_count = db.scalar(select(func.count()).select_from(LocalCveRecord)) or 0
                state.cpe_match_count = db.scalar(select(func.count()).select_from(LocalCveCpeMatch)) or 0
                if mode == "FULL":
                    state.baseline_complete = True
                state.cancel_requested = False
                state.source_last_modified = latest_modified
                state.completed_at = utc_now()
                state.error = None
                db.commit()
        except InterruptedError as exc:
            self._finish_failure("CANCELLED", str(exc))
        except Exception as exc:
            logger.exception("CVE mirror synchronization failed")
            self._finish_failure("FAILED", str(exc))

    def _finish_failure(self, status: str, error: str) -> None:
        with self._session_factory() as db:
            state = db.get(CveMirrorState, 1)
            if state is None:
                return
            state.status = status
            state.current_feed = None
            state.cancel_requested = status == "CANCELLED"
            state.completed_at = utc_now()
            state.error = " ".join(error.split())[:1000]
            state.record_count = db.scalar(select(func.count()).select_from(LocalCveRecord)) or 0
            state.cpe_match_count = db.scalar(select(func.count()).select_from(LocalCveCpeMatch)) or 0
            db.commit()
