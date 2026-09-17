import time

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

import app.services.cve_mirror_service as mirror_service
from app.database import Base, create_database_engine
from app.models import CveMirrorState, LocalCveCpeMatch, LocalCveRecord
from app.services.cve_mirror_service import (
    CveMirrorRunner,
    import_nvd_feed,
    lookup_local_cves,
)
from app.services.cve_service import lookup_cves


NVD_FEED = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-1234",
            "sourceIdentifier": "security@example.test",
            "vulnStatus": "Analyzed",
            "published": "2024-01-02T03:04:05.000",
            "lastModified": "2024-02-02T03:04:05.000",
            "descriptions": [{"lang": "en", "value": "Representative Apache vulnerability."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}
                }]
            },
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                        "matchCriteriaId": "00000000-0000-0000-0000-000000000001",
                        "versionStartIncluding": "2.4.0",
                        "versionEndExcluding": "2.4.60",
                    }],
                }],
            }],
        }
    }],
}


def _database(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'mirror.db'}")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_imported_nvd_feed_matches_exact_cpe_version_range(tmp_path):
    engine, sessions = _database(tmp_path)
    with sessions() as db:
        assert import_nvd_feed(db, NVD_FEED) == 1
        db.add(CveMirrorState(id=1, status="READY", baseline_complete=True))
        db.commit()
        matching = lookup_local_cves(
            db, "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
        )
        outside = lookup_local_cves(
            db, "cpe:2.3:a:apache:http_server:2.4.61:*:*:*:*:*:*:*"
        )
        assert db.scalar(select(func.count()).select_from(LocalCveRecord)) == 1
        assert db.scalar(select(func.count()).select_from(LocalCveCpeMatch)) == 1

    assert matching is not None
    assert matching.authoritative is True
    assert matching.matches[0].cve_id == "CVE-2024-1234"
    assert matching.matches[0].cvss_score == 8.8
    assert outside is not None
    assert outside.matches == ()
    engine.dispose()


def test_not_applicable_cpe_version_is_not_a_wildcard(tmp_path):
    engine, sessions = _database(tmp_path)
    payload = {
        "vulnerabilities": [{"cve": {
            "id": "CVE-1999-1237",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Unrelated module issue."}],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*",
            }]}]}],
        }}],
    }
    with sessions() as db:
        import_nvd_feed(db, payload)
        db.add(CveMirrorState(id=1, status="READY", baseline_complete=True))
        db.commit()
        result = lookup_local_cves(
            db, "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
        )

    assert result is not None
    assert result.matches == ()
    engine.dispose()


def test_lookup_filters_unrelated_exact_versions_before_python_matching(tmp_path, monkeypatch):
    engine, sessions = _database(tmp_path)
    with sessions() as db:
        db.add(LocalCveRecord(
            cve_id="CVE-2024-9000",
            description="Version filtering fixture.",
            severity="MEDIUM",
            configurations_json="[]",
        ))
        db.flush()
        for index in range(500):
            version = "1.2.3" if index == 0 else f"9.9.{index}"
            db.add(LocalCveCpeMatch(
                cve_id="CVE-2024-9000",
                criteria=f"cpe:2.3:a:example:server:{version}:*:*:*:*:*:*:*",
                vulnerable=True,
                part="a",
                vendor="example",
                product="server",
                criteria_version=version,
            ))
        db.add(CveMirrorState(id=1, status="READY", baseline_complete=True))
        db.commit()

        original_match = mirror_service._version_matches
        evaluated = []

        def counted_match(row, version):
            evaluated.append(row.criteria_version)
            return original_match(row, version)

        monkeypatch.setattr(mirror_service, "_version_matches", counted_match)
        result = lookup_local_cves(
            db, "cpe:2.3:a:example:server:1.2.3:*:*:*:*:*:*:*"
        )

    assert result is not None
    assert result.matches[0].cve_id == "CVE-2024-9000"
    assert evaluated == ["1.2.3"]
    engine.dispose()


def test_cancelled_refresh_keeps_completed_baseline_authoritative(tmp_path):
    engine, sessions = _database(tmp_path)
    with sessions() as db:
        db.add(CveMirrorState(
            id=1,
            status="CANCELLED",
            baseline_complete=True,
            error="CVE mirror synchronization cancelled",
        ))
        db.commit()
        result = lookup_local_cves(
            db, "cpe:2.3:a:example:missing:1.0:*:*:*:*:*:*:*"
        )

    assert result is not None
    assert result.authoritative is True
    assert result.matches == ()
    engine.dispose()


def test_cve_lookup_prefers_local_mirror_without_network_request(tmp_path, monkeypatch):
    engine, sessions = _database(tmp_path)
    with sessions() as db:
        import_nvd_feed(db, NVD_FEED)
        db.add(CveMirrorState(id=1, status="READY", baseline_complete=False))
        db.commit()
        monkeypatch.setattr(
            "app.services.cve_service._fetch_nvd",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network fallback used")),
        )
        result = lookup_cves(
            db,
            product="Apache httpd",
            version="2.4.58",
            cpe="cpe:/a:apache:http_server:2.4.58",
        )

    assert result.source == "LOCAL_NVD_MIRROR"
    assert result.cached is True
    assert result.matches[0].cve_id == "CVE-2024-1234"
    engine.dispose()


def test_modified_feed_runner_persists_progress_and_counts(tmp_path, monkeypatch):
    engine, sessions = _database(tmp_path)
    monkeypatch.setattr(
        "app.services.cve_mirror_service._download_feed",
        lambda _feed, cancelled: (
            NVD_FEED,
            {"lastModifiedDate": "2024-02-02T03:04:05.000"},
        ),
    )
    runner = CveMirrorRunner(sessions)
    runner.start()
    assert runner.sync("MODIFIED") is True
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with sessions() as db:
            state = db.get(CveMirrorState, 1)
            if state and state.status != "SYNCING":
                break
        time.sleep(0.02)
    runner.shutdown()

    with sessions() as db:
        state = db.get(CveMirrorState, 1)
        assert state is not None
        assert state.status == "READY"
        assert state.progress_percent == 100
        assert state.record_count == 1
        assert state.cpe_match_count == 1
        assert state.baseline_complete is False
    engine.dispose()
