import base64
import json
from types import SimpleNamespace

import pytest

from app.services.nse_verification_service import NseObservation, NseVerificationResult
from app.services.port_scan_service import DetectedService, OpenPort, parse_nmap_service_scan
from app.services.service_enrichment_service import (
    ToolEvidence, _execute, enrich_open_services, parse_openssl, parse_sslscan,
    parse_whatweb, service_route,
)


def service(port, name, tunnel=None):
    return DetectedService(port, name, None, None, None, (), tunnel)


@pytest.mark.parametrize("port,name,tunnel,expected", [
    (443, "http", "ssl", ("https", True)),
    (5000, "http", None, ("http", False)),
    (5000, "http", "ssl", ("https", True)),
    (7070, "realserver", "ssl", (None, True)),
    (993, "imaps", None, (None, True)),
    (443, "ssh", None, (None, False)),
    (8443, "unknown", None, ("https", True)),
    (445, "microsoft-ds", None, (None, False)),
    (443, "http", None, ("http", False)),
])
def test_route_prefers_observed_protocol(port, name, tunnel, expected):
    assert service_route(OpenPort(port, "unknown", None), service(port, name, tunnel)) == expected


def test_service_parser_preserves_non_http_tls_tunnel():
    xml = '<nmaprun><host><ports><port portid="7070" protocol="tcp"><state state="open"/><service name="realserver" tunnel="ssl"/></port></ports></host></nmaprun>'
    assert parse_nmap_service_scan(xml)[0].tunnel == "ssl"


def test_whatweb_keeps_separate_products_and_does_not_invent_versions():
    target = "https://198.18.1.50:8443/"
    report = json.dumps([{"target": target, "http_status": 200, "plugins": {
        "nginx": {"version": ["1.24.0"]}, "PHP": {"version": ["8.2.1"]},
        "WordPress": {"version": ["6.5.2"]}, "Apache": {"string": ["Apache"]},
        "jQuery": {"version": ["1.2", "3.7.1"]}, "UnknownPlugin": {"version": ["1.0"]},
        "Country": {"string": ["Turkey"]},
    }}])
    identities, evidence = parse_whatweb(report, 8443, target)
    assert {(item.product, item.version) for item in identities} == {
        ("nginx", "1.24.0"), ("PHP", "8.2.1"), ("WordPress", "6.5.2"),
    }
    assert all(item.port == 8443 and item.cpes for item in identities)
    assert len(evidence["technologies"]) == 7
    assert next(row for row in evidence["technologies"] if row["technology"] == "Apache")["observed_values"] == ["Apache"]


@pytest.mark.parametrize("output", ["[]", "{", '[{"target":"http://elsewhere/","http_status":200}]'])
def test_whatweb_requires_response_from_selected_endpoint(output):
    with pytest.raises(RuntimeError):
        parse_whatweb(output, 80, "http://198.18.1.50:80/")


def test_sslscan_supported_legacy_protocols_and_weak_ciphers_are_posture_not_cves():
    output = '''<?xml version="1.0"?><document><ssltest>
      <protocol type="tls" version="1.0" enabled="1"/>
      <protocol type="tls" version="1.2" enabled="1"/>
      <protocol type="ssl" version="3" enabled="0"/>
      <cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA"/>
      <cipher status="rejected" cipher="RC4-SHA"/>
      <cipher status="preferred" sslversion="TLSv1.2" cipher="ECDHE-RSA-AES128-GCM-SHA256"/>
      <certificates><certificate><subject>AnyDesk Client</subject></certificate></certificates>
    </ssltest></document>'''
    evidence, issues = parse_sslscan(output, 7070)
    assert len(evidence["ciphers"]) == 2
    assert evidence["certificates"][0]["subject"] == "AnyDesk Client"
    assert {item.category for item in issues} == {"TLS_PROTOCOL", "TLS_CIPHER"}


@pytest.mark.parametrize("output", ["", "<document>", '<document><ssltest><protocol type="tls" version="1.2" enabled="0"/></ssltest></document>'])
def test_sslscan_failure_is_not_secure_posture(output):
    with pytest.raises(RuntimeError):
        parse_sslscan(output, 443)


def test_openssl_requires_peer_certificate_and_negotiated_session():
    pem = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"fixture-der").decode() + "\n-----END CERTIFICATE-----"
    report = f"{pem}\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nVerify return code: 64 (IP address mismatch)\n"
    result = parse_openssl(report)
    assert result["protocol"] == "TLSv1.3"
    assert result["verification"] == "IP address mismatch"
    assert len(result["certificate_sha256"]) == 64
    with pytest.raises(RuntimeError):
        parse_openssl("no peer certificate available\nCipher is NONE")


def test_planner_selects_only_relevant_tools_and_reuses_smb(monkeypatch):
    calls = []

    def execute(tool, port, command, target, timeout):
        calls.append((tool, port, command, timeout))
        return ToolEvidence(tool, port, "COMPLETED", 1.0), [], []

    monkeypatch.setattr("app.services.service_enrichment_service._execute", execute)
    nse = NseVerificationResult(("smb-protocols", "smb2-security-mode"),
                                (NseObservation("smb2-security-mode", 445, "Signing required"),), 30.0)
    ports = [OpenPort(port, "unknown", None) for port in [22, 445, 5000, 7070]]
    result = enrich_open_services("198.18.1.50", ports,
                                  [service(22, "ssh"), service(445, "microsoft-ds"), service(5000, "http"), service(7070, "realserver", "ssl")], nse)
    assert [(tool, port) for tool, port, *_ in calls] == [("whatweb", 5000), ("openssl", 7070), ("sslscan", 7070)]
    assert result.tool_runs[0].tool == "Nmap SMB"
    assert result.tool_runs[0].details["reused_nse_result"] is True
    assert result.tool_runs[0].duration_ms == 30.0
    assert "--follow-redirect=never" in calls[0][2]
    assert "-showcerts" in calls[1][2] and "-brief" not in calls[1][2]
    assert "--no-heartbleed" in calls[2][2]


def test_planner_records_limits_and_unknown_smb_instead_of_false_success(monkeypatch):
    monkeypatch.setattr("app.services.service_enrichment_service._execute", lambda tool, port, *_: (ToolEvidence(tool, port, "COMPLETED", 1), [], []))
    ports = [OpenPort(445, "SMB", None)] + [OpenPort(port, "http", None) for port in range(5000, 5100)]
    result = enrich_open_services("198.18.1.50", ports, [], NseVerificationResult((), (), 0))
    assert result.tool_runs[0].status == "NO_EVIDENCE"
    assert sum(row.status == "COMPLETED" for row in result.tool_runs) == 6
    assert len(result.tool_runs) == 66
    assert result.tool_runs[-1].details["skipped_run_count"] == 36


def test_tool_timeout_discards_partial_identities_but_preserves_output(monkeypatch):
    monkeypatch.setattr("app.services.service_enrichment_service._run_lab_tool", lambda *_args, **_kwargs: SimpleNamespace(exit_code=124, truncated=False, output="partial evidence"))
    run, identities, issues = _execute("whatweb", 80, ["whatweb"], "http://198.18.1.50:80/", 10)
    assert run.status == "INCOMPLETE"
    assert identities == issues == []
    assert run.details["raw_output"] == "partial evidence"


def test_tool_unavailability_is_nonfatal(monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("whatweb is not installed")
    monkeypatch.setattr("app.services.service_enrichment_service._run_lab_tool", fail)
    run, identities, _ = _execute("whatweb", 80, ["whatweb"], "http://198.18.1.50:80/", 10)
    assert run.status == "UNAVAILABLE" and not identities


def test_planner_does_not_probe_closed_or_absent_ports(monkeypatch):
    monkeypatch.setattr("app.services.service_enrichment_service._execute", lambda *_: pytest.fail("Unexpected tool run"))
    assert not enrich_open_services("198.18.1.50", [], [], NseVerificationResult((), (), 0)).tool_runs


def test_exhausted_host_budget_skips_remaining_tools(monkeypatch):
    times = iter([0, 46])
    monkeypatch.setattr("app.services.service_enrichment_service.time.monotonic", lambda: next(times))
    monkeypatch.setattr("app.services.service_enrichment_service._execute", lambda *_: pytest.fail("Host budget exceeded"))
    result = enrich_open_services("198.18.1.50", [OpenPort(5000, "http", None)], [], NseVerificationResult((), (), 0))
    assert result.tool_runs[0].status == "SKIPPED"
