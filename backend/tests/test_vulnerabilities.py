import json
import http.client

import pytest
from sqlalchemy import select

from app.models import AutomationEvent, Device, VulnerabilityScan
from app.services.cve_service import CveLookupResult, CveMatch
from app.services.exploit_intelligence_service import ExploitIntelligence, ExploitIntelligenceResult
from app.services.nse_verification_service import NseObservation, NseVerificationResult
from app.services.nuclei_validation_service import NucleiObservation, NucleiValidationResult
from app.services.port_scan_service import DetectedService, OpenPort, PortScanResult
from app.services.service_enrichment_service import ServiceEnrichmentResult, ToolEvidence
from app.services.vulnerability_service import (
    TlsPosture,
    _banner_service,
    _nse_service,
    _server_header_service,
    recover_interrupted_vulnerability_scans,
    run_vulnerability_scan,
)

DEVICE = {"name": "Lab server", "ip_address": "198.18.1.50", "device_type": "Server", "is_active": True}


def scan_result(*open_ports):
    return PortScanResult(
        scanned_ports=list(range(1, 1001)),
        open_ports=list(open_ports),
        scanner="test top ports",
        duration_ms=1.0,
    )


@pytest.fixture(autouse=True)
def isolate_service_detection(monkeypatch):
    monkeypatch.setattr(
        "app.services.vulnerability_service.enrich_open_services",
        lambda *_args: ServiceEnrichmentResult(),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_service_versions",
        lambda *_args: [],
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.run_nse_verification",
        lambda *_args: NseVerificationResult((), (), 0.0),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.lookup_cves",
        lambda *_args, **_kwargs: CveLookupResult(
            matches=(),
            total_results=0,
            query="test",
            confidence="MEDIUM",
            cached=True,
        ),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.lookup_exploit_intelligence",
        lambda *_args, **_kwargs: ExploitIntelligenceResult({}, ()),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.run_nuclei_validation",
        lambda *_args: NucleiValidationResult((), (), 0.0, True),
    )


def test_automatic_enrichment_precedes_cve_lookup_and_preserves_multiple_products(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    events = []
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result(OpenPort(5000, "http", 1)))
    monkeypatch.setattr("app.services.vulnerability_service._http_headers", lambda *_: {})
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_service_versions", lambda *_: [DetectedService(5000, "http", "Apache httpd", "2.4.62", None, ())])

    def enrich(*_args):
        events.append("enrichment")
        return ServiceEnrichmentResult((
            DetectedService(5000, "http", "Apache HTTP Server", "2.4.62", "WhatWeb plugin", ("cpe:/a:apache:http_server:2.4.62",)),
            DetectedService(5000, "http", "PHP", "8.2.1", "WhatWeb plugin", ("cpe:/a:php:php:8.2.1",)),
            DetectedService(5000, "http", "WordPress", "6.5.2", "WhatWeb plugin", ("cpe:/a:wordpress:wordpress:6.5.2",)),
        ), (ToolEvidence("whatweb", 5000, "COMPLETED", 10, {"raw_output": "x" * 4000, "evidence": {"technologies": ["fixture"]}}),))

    def lookup(_db, **kwargs):
        events.append((kwargs["product"], kwargs["version"]))
        return CveLookupResult((), 0, "fixture", "HIGH", True)

    monkeypatch.setattr("app.services.vulnerability_service.enrich_open_services", enrich)
    monkeypatch.setattr("app.services.vulnerability_service.lookup_cves", lookup)
    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers, json={"profile": "AGGRESSIVE"})
    assert response.status_code == 201
    assert events[0] == "enrichment"
    assert len(events[1:]) == 3  # Apache aliases share a CPE and are queried once.
    assert ("PHP", "8.2.1") in events and ("WordPress", "6.5.2") in events
    report = response.json()
    assert report["tool_runs"][0]["details"]["raw_output"] == "x" * 4000
    stored = client.get(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers).json()[0]
    assert stored["tool_runs"] == report["tool_runs"]


def test_conflicting_versions_are_retained_but_not_used_as_cve_keys(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result(OpenPort(5000, "http", 1)))
    monkeypatch.setattr("app.services.vulnerability_service._http_headers", lambda *_: {})
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_service_versions", lambda *_: [DetectedService(5000, "http", "nginx", "1.24.0", None, ("cpe:/a:nginx:nginx:1.24.0",))])
    monkeypatch.setattr("app.services.vulnerability_service.enrich_open_services", lambda *_: ServiceEnrichmentResult((DetectedService(5000, "http", "nginx", "1.26.0", "WhatWeb plugin", ("cpe:/a:nginx:nginx:1.26.0",)),)))
    monkeypatch.setattr("app.services.vulnerability_service.lookup_cves", lambda *_args, **_kwargs: pytest.fail("Conflicting version was sent to CVE lookup"))
    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers, json={"profile": "AGGRESSIVE"})
    assert response.status_code == 201
    findings = response.json()["findings"]
    assert {item["service_version"] for item in findings if item["category"] == "SERVICE_IDENTIFICATION"} == {"1.24.0", "1.26.0"}
    assert any(item["category"] == "SERVICE_EVIDENCE_CONFLICT" for item in findings)
    assert any(item["category"] == "CVE_CORRELATION" and "consistent version" in item["title"] for item in findings)
    assert any("0/1" in item["title"] for item in findings if item["category"] == "CVE_COVERAGE")


def test_tool_evidence_survives_cve_cache_transaction_rollback(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result(OpenPort(5000, "http", 1)))
    monkeypatch.setattr("app.services.vulnerability_service._http_headers", lambda *_: {})
    monkeypatch.setattr("app.services.vulnerability_service.enrich_open_services", lambda *_: ServiceEnrichmentResult(
        (DetectedService(5000, "http", "PHP", "8.2.1", "WhatWeb plugin", ("cpe:/a:php:php:8.2.1",)),),
        (ToolEvidence("whatweb", 5000, "COMPLETED", 10, {"evidence": {"technology": "PHP"}}),)))

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("NVD unavailable")

    monkeypatch.setattr("app.services.vulnerability_service.lookup_cves", unavailable)
    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)
    assert response.status_code == 201
    assert response.json()["status"] == "COMPLETED"
    assert response.json()["tool_runs"][0]["details"]["evidence"]["technology"] == "PHP"
    assert any(item["category"] == "CVE_LOOKUP" and "incomplete" in item["title"] for item in response.json()["findings"])


def test_unexpected_http_response_is_nonfatal_to_automated_assessment(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result(OpenPort(5000, "http", 1)))

    def malformed(*_args):
        raise http.client.BadStatusLine("not an HTTP response")

    monkeypatch.setattr("app.services.vulnerability_service._http_headers", malformed)
    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)
    assert response.status_code == 201 and response.json()["status"] == "COMPLETED"
    assert any(item["category"] == "HTTP_INSPECTION" for item in response.json()["findings"])


def test_attack_surface_persists_scanner_and_effective_version_probe_provenance(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        lambda _ip: PortScanResult(
            scanned_ports=list(range(1, 1001)),
            open_ports=[OpenPort(445, "SMB", 1.0)],
            scanner="Nmap top ports", duration_ms=1.0,
            provenance={
                "engine_version": "7.991",
                "execution_context": "Docker toolbox aegis-network-tools",
                "tcp_scan_type": "-sS",
                "command": "docker exec aegis-network-tools nmap --top-ports 1000 198.18.1.50",
            },
        ),
    )

    with client.app.state.session_factory() as db:
        scan = run_vulnerability_scan(db.get(Device, device["id"]), db, "AGGRESSIVE")
        finding = next(item for item in scan.findings if item.category == "SCAN_PROVENANCE")
        provenance = json.loads(finding.description)
    assert provenance["engine_version"] == "7.991"
    assert provenance["tcp_scan_type"] == "-sS"
    assert provenance["service_detection_flags"] == "-sV --version-all"
    assert provenance["service_detection_ports"] == "445"
    assert provenance["service_detection_host_timeout"] == "180s"
    assert provenance["service_detection_tcp_scan_type"] == "-sT"


def test_attack_surface_records_curated_nse_configuration_evidence(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        lambda _ip: scan_result(OpenPort(445, "SMB", 1.0)),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.run_nse_verification",
        lambda *_args: NseVerificationResult(
            requested_scripts=("smb-os-discovery", "smb-protocols", "smb2-security-mode"),
            observations=(
                NseObservation(
                    "smb-os-discovery",
                    445,
                    "OS: Windows 11 Pro 22631; Computer name: LAB-PC",
                ),
                NseObservation("smb-protocols", 445, "NT LM 0.12 (SMBv1) [dangerous]"),
                NseObservation(
                    "smb2-security-mode",
                    445,
                    "Message signing enabled but not required",
                ),
            ),
            duration_ms=12.0,
        ),
    )

    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    )

    assert response.status_code == 201
    findings = response.json()["findings"]
    assert any(item["category"] == "NSE_CHECK" for item in findings)
    validated = [item for item in findings if item["category"] == "NSE_VALIDATION"]
    assert {item["title"] for item in validated} == {
        "SMBv1 protocol enabled",
        "SMB message signing is not required",
    }
    assert all(item["match_confidence"] == "HIGH" for item in validated)
    identity = next(item for item in findings if item["category"] == "DEVICE_IDENTITY")
    assert "Windows 11 Pro 22631" in identity["description"]


def test_attack_surface_records_bounded_nuclei_template_evidence(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        lambda _ip: scan_result(OpenPort(8080, "http", 1.0)),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._http_headers",
        lambda *_args: {},
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.run_nuclei_validation",
        lambda *_args: NucleiValidationResult(
            targets=("http://198.18.1.50:8080",),
            observations=(NucleiObservation(
                template_id="exposed-environment-file",
                name="Exposed environment file",
                severity="HIGH",
                description="A public environment file was detected.",
                remediation="Remove public access to the environment file.",
                matched_at="http://198.18.1.50:8080/.env",
                matcher_name="dotenv",
                reference="https://example.test/security/exposed-files",
                cve_id=None,
                port=8080,
            ),),
            duration_ms=15.0,
            completed=True,
        ),
    )

    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    )

    assert response.status_code == 201
    findings = response.json()["findings"]
    assert any(item["category"] == "NUCLEI_CHECK" for item in findings)
    finding = next(item for item in findings if item["category"] == "NUCLEI_VALIDATION")
    assert finding["severity"] == "HIGH"
    assert finding["validation_tool"] == "Nuclei"
    assert finding["validation_check_id"] == "exposed-environment-file"
    assert finding["validation_target"] == "http://198.18.1.50:8080/.env"
    assert finding["validation_reference"] == "https://example.test/security/exposed-files"
    assert finding["match_confidence"] == "HIGH"


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "scan-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_defensive_scan_records_service_and_header_findings(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result(OpenPort(445, "SMB", 1.0), OpenPort(80, "HTTP", 1.2)))
    monkeypatch.setattr("app.services.vulnerability_service._http_headers", lambda *_args: {"server": "test"})
    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "COMPLETED"
    assert any(item["severity"] == "HIGH" and item["port"] == 445 for item in body["findings"])
    assert sum(item["category"] == "HTTP_HEADER" for item in body["findings"]) == 3
    assert client.get(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers).json()[0]["id"] == body["id"]


def test_scan_with_no_common_ports_records_positive_information(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result())
    body = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers).json()
    assert body["findings"][0]["severity"] == "INFO"


def test_scan_releases_sqlite_write_lock_before_network_probe(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    session_factory = client.app.state.session_factory

    def probe_without_holding_a_write_transaction(_ip):
        with session_factory() as observer:
            running = observer.scalar(
                select(VulnerabilityScan).where(VulnerabilityScan.status == "RUNNING")
            )
            assert running is not None
            observer.add(AutomationEvent(
                event_type="CONCURRENT_WRITE_TEST",
                severity="INFO",
                message="The scan released its initial write transaction.",
            ))
            observer.commit()
        return scan_result()

    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        probe_without_holding_a_write_transaction,
    )
    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans",
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["status"] == "COMPLETED"


def test_interrupted_vulnerability_scan_is_failed_on_restart(client, admin_headers):
    device = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        scan = VulnerabilityScan(device_id=device["id"], status="RUNNING", profile="FAST")
        db.add(scan)
        db.commit()
        scan_id = scan.id

    assert recover_interrupted_vulnerability_scans(session_factory) == 1

    with session_factory() as db:
        recovered = db.get(VulnerabilityScan, scan_id)
        assert recovered is not None
        assert recovered.status == "FAILED"
        assert recovered.completed_at is not None
        assert [item.category for item in recovered.findings] == ["SCAN_STATUS"]


def test_scan_allows_registered_target_on_public_lan(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json={**DEVICE, "ip_address": "198.19.4.14"}, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result())

    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)

    assert response.status_code == 201
    assert response.json()["status"] == "COMPLETED"


def test_scan_allows_registered_public_target_outside_connected_lan(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json={**DEVICE, "ip_address": "8.8.8.8"}, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result())

    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)

    assert response.status_code == 201


def test_scan_allows_registered_documentation_target(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json={**DEVICE, "ip_address": "203.0.113.25"}, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_nmap_top_tcp_ports", lambda _ip: scan_result())

    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)

    assert response.status_code == 201


def test_attack_surface_scan_records_banner_version_and_tls_posture(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        lambda _ip: scan_result(OpenPort(22, "SSH", 1.0), OpenPort(443, "HTTPS", 1.2)),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._service_banner",
        lambda *_args: "SSH-2.0-OpenSSH_9.3",
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._http_headers",
        lambda *_args: {
            "server": "nginx/1.24.0",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'none'",
        },
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._tls_posture",
        lambda *_args: TlsPosture(
            protocol="TLSv1",
            cipher="AES256-SHA",
            certificate_sha256="a" * 64,
            certificate_verified=False,
            verification_error="self-signed certificate",
        ),
    )

    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    )

    assert response.status_code == 201
    categories = {finding["category"] for finding in response.json()["findings"]}
    assert {
        "SERVICE_BANNER",
        "VERSION_DISCLOSURE",
        "TLS_POSTURE",
        "TLS_PROTOCOL",
        "TLS_CERTIFICATE",
    } <= categories


def test_safe_banners_create_exact_application_fingerprints():
    ssh = _banner_service(22, "ssh", "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3")
    http = _server_header_service(443, "nginx/1.24.0")

    assert ssh is not None
    assert (ssh.product, ssh.version) == ("OpenSSH", "9.3p1")
    assert ssh.cpes == ("cpe:/a:openbsd:openssh:9.3p1",)
    assert http is not None
    assert (http.product, http.version) == ("nginx", "1.24.0")
    assert http.cpes == ("cpe:/a:nginx:nginx:1.24.0",)

    samba = _nse_service(NseObservation(
        "smb-os-discovery",
        445,
        "OS: Unix (Samba 4.18.6); Computer name: FILESERVER",
    ))
    assert samba is not None
    assert (samba.product, samba.version) == ("Samba", "4.18.6")
    assert samba.cpes == ("cpe:/a:samba:samba:4.18.6",)


def test_fast_scan_adaptively_refines_only_unresolved_open_services(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        lambda _ip: scan_result(OpenPort(9999, "unknown", 1.0)),
    )
    calls = []

    def service_scan(_ip, ports, profile):
        calls.append((ports, profile))
        if profile == "FAST":
            return [DetectedService(9999, "unknown", None, None, None, ())]
        return [DetectedService(
            9999,
            "http",
            "nginx",
            "1.24.0",
            None,
            ("cpe:/a:nginx:nginx:1.24.0",),
        )]

    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_service_versions",
        service_scan,
    )

    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans",
        headers=headers,
    )

    assert response.status_code == 201
    assert calls == [([9999], "FAST"), ([9999], "ADAPTIVE")]
    findings = response.json()["findings"]
    assert any(
        item["category"] == "CVE_COVERAGE"
        and item["title"] == "CVE evidence coverage: 1/1 open services ready"
        for item in findings
    )
    assert not any(item["category"] == "CVE_CORRELATION" for item in findings)


def test_attack_surface_correlates_detected_cpe_with_nvd_cve(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        lambda _ip: scan_result(OpenPort(80, "http", 1.0)),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_service_versions",
        lambda *_args: [DetectedService(
            port=80,
            name="http",
            product="Apache httpd",
            version="2.4.58",
            extra_info=None,
            cpes=("cpe:/a:apache:http_server:2.4.58",),
        )],
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.lookup_cves",
        lambda *_args, **_kwargs: CveLookupResult(
            matches=(CveMatch(
                cve_id="CVE-2024-TEST",
                description="Test vulnerability record.",
                cvss_score=8.1,
                severity="HIGH",
                published="2024-01-01T00:00:00.000",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-TEST",
            ),),
            total_results=1,
            query="cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
            confidence="HIGH",
            cached=False,
        ),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._http_headers",
        lambda *_args: {
            "server": "Apache/2.4.58",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'none'",
        },
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.lookup_exploit_intelligence",
        lambda *_args, **_kwargs: ExploitIntelligenceResult(
            records={
                "CVE-2024-TEST": ExploitIntelligence(
                    cve_id="CVE-2024-TEST",
                    known_exploited=True,
                    kev_date_added="2024-04-01",
                    kev_required_action="Apply the vendor update.",
                    epss_score=0.8123,
                    epss_percentile=0.991,
                ),
            },
            warnings=(),
        ),
    )

    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)

    assert response.status_code == 201
    finding = next(item for item in response.json()["findings"] if item["cve_id"] == "CVE-2024-TEST")
    assert finding["port"] == 80
    assert finding["cvss_score"] == 8.1
    assert finding["match_confidence"] == "HIGH"
    assert finding["service_cpe"] == "cpe:/a:apache:http_server:2.4.58"
    assert finding["known_exploited"] is True
    assert finding["kev_date_added"] == "2024-04-01"
    assert finding["kev_required_action"] == "Apply the vendor update."
    assert finding["epss_score"] == 0.8123
    assert finding["epss_percentile"] == 0.991


def test_attack_surface_scan_is_admin_only(client):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    created = client.post(
        "/api/auth/users",
        headers=headers,
        json={
            "username": "scan-operator",
            "password": "operator-password-is-long",
            "role": "OPERATOR",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "scan-operator", "password": "operator-password-is-long"},
    )

    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )

    assert response.status_code == 403
    history = client.get(
        f"/api/devices/{device['id']}/vulnerability-scans",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )
    assert history.status_code == 200


def test_attack_surface_comparison_tracks_new_and_resolved_findings(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    results = iter([[OpenPort(23, "Telnet", 1.0)], []])
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_nmap_top_tcp_ports",
        lambda _ip: scan_result(*next(results)),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._service_banner",
        lambda *_args: None,
    )

    first = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    ).json()
    baseline = client.get(
        f"/api/devices/{device['id']}/vulnerability-scans/comparison", headers=headers
    ).json()
    assert baseline["current_scan_id"] == first["id"]
    assert baseline["previous_scan_id"] is None
    assert baseline["risk_score"] == 40
    assert [item["title"] for item in baseline["new_findings"]] == ["Telnet service exposed"]

    second = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    ).json()
    comparison = client.get(
        f"/api/devices/{device['id']}/vulnerability-scans/comparison", headers=headers
    ).json()
    assert comparison["current_scan_id"] == second["id"]
    assert comparison["previous_scan_id"] == first["id"]
    assert comparison["risk_score"] == 0
    assert comparison["new_findings"] == []
    assert [item["title"] for item in comparison["resolved_findings"]] == [
        "Telnet service exposed"
    ]
