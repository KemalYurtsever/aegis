import importlib.util
import hashlib
import hmac
import json
from pathlib import Path
from types import SimpleNamespace


AGENT_PATH = Path(__file__).parents[2] / "agent" / "aegis_agent.py"
SPEC = importlib.util.spec_from_file_location("aegis_agent_client", AGENT_PATH)
agent = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(agent)


class FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_agent_health_check_uses_dedicated_ingress(monkeypatch):
    captured = {}

    def open_request(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return FakeResponse(200, {"status": "healthy", "service": "AEGIS agent ingress"})

    monkeypatch.setattr(agent.urllib.request, "urlopen", open_request)
    health = agent.check_server()
    assert captured == {"url": f"{agent.SERVER_URL}/api/agent/health", "timeout": 10}
    assert health["status"] == "healthy"


def test_agent_loads_windows_powershell_bom_config(monkeypatch, tmp_path):
    config = tmp_path / "agent-config.json"
    config.write_bytes(b'\xef\xbb\xbf{"server_url":"http://192.0.2.10:8002","token":"secret"}')
    monkeypatch.setenv("AEGIS_AGENT_CONFIG_FILE", str(config))
    assert agent.load_config()["server_url"] == "http://192.0.2.10:8002"


def test_agent_once_checks_health_and_submits(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(agent, "AGENT_TOKEN", "x" * 32)
    monkeypatch.setattr(agent, "check_server", lambda: calls.append("health") or {"status": "healthy"})
    monkeypatch.setattr(agent, "submit", lambda: calls.append("submit") or {"id": 1})
    result = agent.main(["--once", "--log-file", str(tmp_path / "agent.log")])
    assert result == 0
    assert calls == ["health", "submit"]
    assert (tmp_path / "agent.log").is_file()


def test_agent_check_does_not_require_token(monkeypatch):
    monkeypatch.setattr(agent, "AGENT_TOKEN", "")
    monkeypatch.setattr(agent, "check_server", lambda: {"status": "healthy", "service": "test"})
    monkeypatch.setattr(agent, "submit", lambda: (_ for _ in ()).throw(AssertionError("submit called")))
    assert agent.main(["--check"]) == 0


def test_agent_health_failure_has_nonzero_exit(monkeypatch):
    monkeypatch.setattr(agent, "check_server", lambda: (_ for _ in ()).throw(OSError("unreachable")))
    assert agent.main(["--check"]) == 2


def test_fixed_command_never_uses_a_shell(monkeypatch):
    captured = {}
    monkeypatch.setattr(agent.shutil, "which", lambda name: f"/tools/{name}")

    def run(arguments, **options):
        captured["arguments"] = arguments
        captured["options"] = options
        return SimpleNamespace(returncode=0, stdout="safe output", stderr="")

    monkeypatch.setattr(agent.subprocess, "run", run)
    assert agent.run_fixed_command(["example", "--fixed"]) == "safe output"
    assert captured["arguments"] == ["/tools/example", "--fixed"]
    assert captured["options"]["shell"] is False


def test_agent_processes_only_allowlisted_diagnostic_jobs(monkeypatch):
    submitted = []
    monkeypatch.setattr(
        agent,
        "poll_diagnostic_job",
        lambda: {"id": 7, "job_type": "TOP_PROCESSES", "parameters": {"max_records": 10}},
    )
    monkeypatch.setitem(agent.DIAGNOSTIC_COLLECTORS, "TOP_PROCESSES", lambda parameters: {"limit": parameters["max_records"]})
    monkeypatch.setattr(
        agent,
        "submit_diagnostic_result",
        lambda *args, **kwargs: submitted.append((args, kwargs)) or {},
    )
    assert agent.process_next_diagnostic_job() is True
    assert submitted == [((7, "COMPLETED"), {"result": {"limit": 10}})]


def test_safe_validation_file_simulations_cleanup_generated_workspaces(monkeypatch):
    monkeypatch.setattr(agent, "AGENT_TOKEN", "validation-token-value" * 2)
    nonce = "safe-validation-nonce-12345"
    for simulation_type in (
        "SYNTHETIC_CREDENTIAL",
        "TEMPORARY_MARKER",
        "SAFE_FILE_ACTIVITY",
        "DETECTION_VARIATION",
        "SIGNED_CANARY_ARTIFACT",
    ):
        result = agent.collect_validation_simulation({
            "_job_id": 10,
            "simulation_type": simulation_type,
            "nonce": nonce,
            "max_records": 12,
        })
        assert result["simulation_type"] == simulation_type
        assert result["cleanup_verified"] is True
    assert agent.collect_validation_simulation({
        "_job_id": 10,
        "simulation_type": "SAFE_FILE_ACTIVITY",
        "nonce": nonce,
        "max_records": 12,
    })["encryption_performed"] is False


def test_validation_callback_is_hmac_signed(monkeypatch):
    captured = {}
    monkeypatch.setattr(agent, "AGENT_TOKEN", "x" * 32)

    def open_request(request, timeout):
        captured.update(request=request, timeout=timeout)
        return FakeResponse(204, {})

    monkeypatch.setattr(agent.urllib.request, "urlopen", open_request)
    result = agent.submit_validation_callback(17, "nonce-value-long-enough")
    expected = hmac.new(b"x" * 32, b"nonce-value-long-enough", hashlib.sha256).hexdigest()
    assert captured["request"].full_url.endswith("/api/agent/jobs/17/validation-callback")
    assert captured["request"].headers["X-aegis-validation-signature"] == expected
    assert captured["timeout"] == 10
    assert result["command_execution"] is False


def test_password_policy_audit_uses_only_fixed_policy_command(monkeypatch):
    captured = {}
    monkeypatch.setattr(agent.platform, "system", lambda: "Windows")

    def run(arguments, timeout):
        captured.update(arguments=arguments, timeout=timeout)
        return "Minimum password age (days): 1"

    monkeypatch.setattr(agent, "run_fixed_command", run)
    result = agent.collect_validation_simulation({
        "_job_id": 18,
        "simulation_type": "PASSWORD_POLICY_AUDIT",
        "nonce": "password-policy-nonce-12345",
    })

    assert captured == {"arguments": ["net", "accounts"], "timeout": 15}
    assert result["simulation_type"] == "PASSWORD_POLICY_AUDIT"
    assert result["password_material_accessed"] is False


def test_segmentation_probe_sends_no_application_data(monkeypatch):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    captured = {}

    def connect(target, timeout):
        captured.update(target=target, timeout=timeout)
        return Connection()

    monkeypatch.setattr(agent.socket, "create_connection", connect)
    result = agent.collect_validation_simulation({
        "_job_id": 9,
        "simulation_type": "SEGMENTATION_PROBE",
        "nonce": "segmentation-nonce-12345",
        "target_device_id": 4,
        "target_address": "198.18.56.201",
        "target_port": 443,
    })
    assert captured == {"target": ("198.18.56.201", 443), "timeout": 3}
    assert result["connected"] is True
    assert result["application_data_sent"] is False
