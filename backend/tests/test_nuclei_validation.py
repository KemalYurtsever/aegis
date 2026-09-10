import json
import subprocess
from types import SimpleNamespace

from app.services.nuclei_validation_service import (
    MAX_WEB_TARGETS,
    parse_nuclei_jsonl,
    run_nuclei_validation,
    web_targets,
)
from app.services.port_scan_service import OpenPort


NUCLEI_RECORD = {
    "template-id": "exposed-environment-file",
    "matcher-name": "dotenv",
    "matched-at": "http://192.168.1.25:8080/.env?token=must-not-be-stored",
    "info": {
        "name": "Exposed environment file",
        "severity": "high",
        "description": "A public environment file was detected.",
        "remediation": "Remove public access to the environment file.",
        "reference": ["https://example.test/security/exposed-files"],
        "classification": {"cve-id": ["CVE-2024-12345"]},
    },
}


def test_nuclei_parser_keeps_bounded_evidence_for_the_registered_target():
    unrelated = {**NUCLEI_RECORD, "matched-at": "http://203.0.113.10:8080/.env"}
    output = "\n".join((json.dumps(NUCLEI_RECORD), json.dumps(unrelated), "not-json"))

    observations = parse_nuclei_jsonl(
        output,
        expected_ip="192.168.1.25",
        targets=("http://192.168.1.25:8080",),
    )

    assert len(observations) == 1
    finding = observations[0]
    assert finding.template_id == "exposed-environment-file"
    assert finding.severity == "HIGH"
    assert finding.matched_at == "http://192.168.1.25:8080/.env"
    assert "token" not in finding.matched_at
    assert finding.cve_id == "CVE-2024-12345"
    assert finding.remediation == "Remove public access to the environment file."
    assert finding.port == 8080


def test_web_targets_use_detected_protocols_and_enforce_per_host_limit():
    open_ports = [
        OpenPort(443, "https", None),
        OpenPort(8080, "http-proxy", None),
        OpenPort(9000, "ssl/http", None),
        *(OpenPort(10_000 + index, "http", None) for index in range(MAX_WEB_TARGETS + 2)),
    ]

    targets, skipped = web_targets("192.168.1.25", open_ports)

    assert "https://192.168.1.25:443" in targets
    assert "http://192.168.1.25:8080" in targets
    assert len(targets) == MAX_WEB_TARGETS
    assert skipped == 5


def test_nuclei_command_is_signed_noninteractive_and_rate_limited(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "app.services.nuclei_validation_service._nuclei_runtime",
        lambda: (
            ["docker", "exec", "aegis-network-tools", "nuclei"],
            "/nuclei-templates",
        ),
    )

    def fake_run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        kwargs["stdout"].write((json.dumps(NUCLEI_RECORD) + "\n").encode())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("app.services.nuclei_validation_service.subprocess.run", fake_run)

    result = run_nuclei_validation(
        "192.168.1.25",
        [OpenPort(8080, "http", None)],
        "FAST",
    )

    command = captured["command"]
    assert command[:4] == ["docker", "exec", "aegis-network-tools", "nuclei"]
    assert "-disable-unsigned-templates" in command
    assert "-no-interactsh" in command
    assert "-disable-redirects" in command
    assert command[command.index("-rate-limit") + 1] == "15"
    assert command[command.index("-severity") + 1] == "medium,high,critical"
    assert command.count("-templates") == 3
    assert captured["kwargs"]["timeout"] == 25
    assert captured["kwargs"]["shell"] is False
    assert result.completed is True
    assert len(result.observations) == 1


def test_nuclei_timeout_retains_any_completed_matches(monkeypatch):
    monkeypatch.setattr(
        "app.services.nuclei_validation_service._nuclei_runtime",
        lambda: (["nuclei"], ""),
    )

    def fake_run(command, **kwargs):
        kwargs["stdout"].write((json.dumps(NUCLEI_RECORD) + "\n").encode())
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr("app.services.nuclei_validation_service.subprocess.run", fake_run)

    result = run_nuclei_validation(
        "192.168.1.25",
        [OpenPort(8080, "http", None)],
        "FAST",
    )

    assert result.completed is False
    assert "25-second budget" in result.error
    assert len(result.observations) == 1
