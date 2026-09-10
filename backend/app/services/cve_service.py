import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import CveLookupCache, utc_now


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = timedelta(hours=24)
MAX_DISPLAY_MATCHES = 50
MAX_NVD_RESPONSE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    published: str | None
    url: str


@dataclass(frozen=True)
class CveLookupResult:
    matches: tuple[CveMatch, ...]
    total_results: int
    query: str
    confidence: str
    cached: bool


def cpe22_to_cpe23(value: str) -> str:
    """Convert Nmap's CPE 2.2 URI binding to the CPE 2.3 formatted binding."""
    value = value.strip()
    if value.startswith("cpe:2.3:"):
        return value
    if not value.startswith("cpe:/"):
        raise ValueError("Unsupported CPE format")
    legacy = value[5:].split(":")
    if not legacy or legacy[0] not in {"a", "o", "h"}:
        raise ValueError("Unsupported CPE part")
    components = [component or "*" for component in legacy[:7]]
    components.extend("*" for _ in range(7 - len(components)))
    components.extend(["*", "*", "*", "*"])
    return "cpe:2.3:" + ":".join(components)


def _normalized_fetched_at(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _metric(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key) or []
        if not candidates:
            continue
        data = candidates[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or candidates[0].get("baseSeverity")
        try:
            normalized_score = float(score) if score is not None else None
        except (TypeError, ValueError):
            normalized_score = None
        if severity:
            return normalized_score, str(severity).upper()
        if normalized_score is not None:
            if normalized_score >= 9:
                return normalized_score, "CRITICAL"
            if normalized_score >= 7:
                return normalized_score, "HIGH"
            if normalized_score >= 4:
                return normalized_score, "MEDIUM"
            return normalized_score, "LOW"
    return None, "INFO"


def _english_description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    for description in descriptions:
        if description.get("lang") == "en" and description.get("value"):
            return " ".join(str(description["value"]).split())[:1000]
    return "No English description was supplied by NVD."


def parse_nvd_response(payload: dict) -> tuple[tuple[CveMatch, ...], int]:
    matches = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        score, severity = _metric(cve)
        matches.append(CveMatch(
            cve_id=cve_id,
            description=_english_description(cve),
            cvss_score=score,
            severity=severity if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "INFO",
            published=cve.get("published"),
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ))
    matches.sort(key=lambda item: (item.cvss_score is not None, item.cvss_score or -1, item.published or ""), reverse=True)
    total = int(payload.get("totalResults") or len(matches))
    return tuple(matches[:MAX_DISPLAY_MATCHES]), total


def _fetch_nvd(params: dict[str, str], timeout_seconds: float = 15.0) -> dict:
    request = Request(
        f"{NVD_CVE_API}?{urlencode(params)}",
        headers={"Accept": "application/json", "User-Agent": "Aegis/0.1 local defensive assessment"},
    )
    configured_key = get_settings().nvd_api_key
    api_key = configured_key.get_secret_value().strip() if configured_key else ""
    if api_key:
        request.add_header("apiKey", api_key)
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(MAX_NVD_RESPONSE_BYTES + 1)
            if len(raw) > MAX_NVD_RESPONSE_BYTES:
                raise RuntimeError("NVD response exceeded the 32 MiB safety limit")
            return json.loads(raw)
    except HTTPError as exc:
        if exc.code == 403:
            raise RuntimeError("NVD rejected the request; check the configured API key") from exc
        if exc.code == 429:
            raise RuntimeError("NVD rate limit reached; retry later or configure NVD_API_KEY") from exc
        raise RuntimeError(f"NVD request failed with HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("NVD could not be reached or returned an unreadable response") from exc


def lookup_cves(
    db: Session,
    *,
    product: str,
    version: str,
    cpe: str | None = None,
) -> CveLookupResult:
    product = " ".join(product.split())[:200]
    version = " ".join(version.split())[:100]
    if not product or not version:
        raise ValueError("CVE correlation requires both product and version evidence")

    if cpe:
        cpe23 = cpe22_to_cpe23(cpe)
        query = cpe23
        confidence = "HIGH"
        params = {"cpeName": cpe23, "resultsPerPage": "2000"}
        cache_identity = f"cpe:{cpe23}"
    else:
        query = f"{product} {version}"
        confidence = "MEDIUM"
        params = {"keywordSearch": query, "resultsPerPage": "2000"}
        cache_identity = f"keyword:{query.casefold()}"

    query_key = hashlib.sha256(cache_identity.encode("utf-8")).hexdigest()

    cache = db.get(CveLookupCache, query_key)
    now = utc_now()
    cached = bool(cache and now - _normalized_fetched_at(cache.fetched_at) <= CACHE_TTL)
    if cached:
        try:
            payload = json.loads(cache.response_json)
        except json.JSONDecodeError:
            cached = False
    if not cached:
        payload = _fetch_nvd(params)
        serialized = json.dumps(payload, separators=(",", ":"))
        if cache:
            cache.response_json = serialized
            cache.fetched_at = now
        else:
            db.add(CveLookupCache(query_key=query_key, response_json=serialized, fetched_at=now))
        db.flush()

    matches, total = parse_nvd_response(payload)
    return CveLookupResult(
        matches=matches,
        total_results=total,
        query=query,
        confidence=confidence,
        cached=cached,
    )
