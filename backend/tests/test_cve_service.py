import io
import json
from sqlalchemy.orm import sessionmaker

from app.database import Base, create_database_engine
from app.services.cve_service import cpe22_to_cpe23, lookup_cves, parse_nvd_response


NVD_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-1234",
            "published": "2024-01-02T03:04:05.000",
            "descriptions": [{"lang": "en", "value": "A representative vulnerability."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}
                }]
            },
        }
    }],
}


class JsonResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_cpe22_to_cpe23_builds_well_formed_application_name():
    assert cpe22_to_cpe23("cpe:/a:apache:http_server:2.4.58") == (
        "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
    )


def test_parse_nvd_response_extracts_cvss_and_description():
    matches, total = parse_nvd_response(NVD_RESPONSE)

    assert total == 1
    assert matches[0].cve_id == "CVE-2024-1234"
    assert matches[0].cvss_score == 8.8
    assert matches[0].severity == "HIGH"
    assert matches[0].description == "A representative vulnerability."


def test_lookup_uses_exact_cpe_and_reuses_local_cache(tmp_path, monkeypatch):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'cve.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    requests = []

    def fake_urlopen(request, timeout):
        requests.append((request.full_url, timeout))
        return JsonResponse(json.dumps(NVD_RESPONSE).encode())

    monkeypatch.setattr("app.services.cve_service.urlopen", fake_urlopen)
    with sessions() as db:
        first = lookup_cves(
            db,
            product="Apache httpd",
            version="2.4.58",
            cpe="cpe:/a:apache:http_server:2.4.58",
        )
        db.commit()
        second = lookup_cves(
            db,
            product="Apache httpd",
            version="2.4.58",
            cpe="cpe:/a:apache:http_server:2.4.58",
        )

    assert len(requests) == 1
    assert "cpeName=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.4.58" in requests[0][0]
    assert first.confidence == "HIGH"
    assert first.cached is False
    assert second.cached is True
    assert second.matches[0].cve_id == "CVE-2024-1234"
    engine.dispose()
