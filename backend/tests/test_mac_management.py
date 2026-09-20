import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.services import mac_management_service as mac


GUID = "11111111-1111-1111-1111-111111111111"
CURRENT = "02:00:00:00:00:01"
TARGET = "02:11:22:33:44:55"
FACTORY = "00:11:22:33:44:55"


@pytest.fixture
def adapters(monkeypatch):
    monkeypatch.setattr(mac, "_ISSUED_PREVIEWS", {})
    state = {"platform": "windows", "can_apply": True, "message": "Synthetic test",
             "adapters": [{"interface_id": GUID, "name": "Synthetic Ethernet", "description": "Fixture",
                           "status": "Up", "current_mac": CURRENT, "permanent_mac": FACTORY,
                           "override_mac": None, "supports_override": True}]}
    monkeypatch.setattr(mac, "adapter_status", lambda: deepcopy(state))
    return state


@pytest.mark.parametrize("value", [TARGET, TARGET.lower(), TARGET.replace(":", "-"), TARGET.replace(":", "")])
def test_mac_formats_canonicalize(value):
    assert mac.normalize_mac(value) == TARGET


@pytest.mark.parametrize("value", ["", "xyz", "0" * 12, "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb",
                                   "02:11-22:33:44:55", "';Start-Process calc;'"])
def test_invalid_multicast_and_shell_text_rejected(value):
    with pytest.raises(ValueError):
        mac.normalize_mac(value)


def test_random_addresses_are_unicast_local_and_distinct():
    excluded = [CURRENT, TARGET, FACTORY]
    for _ in range(64):
        address = mac.random_local_mac(excluded)
        assert int(address[:2], 16) & 3 == 2
        assert address not in excluded


def test_random_collision_retry_and_exhaustion(monkeypatch):
    values = iter([bytes.fromhex(CURRENT.replace(":", "")), bytes.fromhex(TARGET.replace(":", ""))])
    monkeypatch.setattr(mac.secrets, "token_bytes", lambda _n: next(values))
    assert mac.random_local_mac([CURRENT]) == TARGET
    monkeypatch.setattr(mac.secrets, "token_bytes", lambda _n: bytes.fromhex(CURRENT.replace(":", "")))
    with pytest.raises(mac.MacManagementError, match="distinct"):
        mac.random_local_mac([CURRENT])


def test_plan_is_read_only_and_fixed_driver_operation(adapters, monkeypatch):
    monkeypatch.setattr(mac, "_run_script", lambda *_: pytest.fail("Plan must not execute any mutation"))
    plan = mac.prepare_change(GUID, "manual", TARGET.lower())
    assert plan["previous_mac"] == CURRENT and plan["target_mac"] == TARGET
    assert "Set-NetAdapterAdvancedProperty -RegistryValue '" + TARGET.replace(":", "") + "' -NoRestart" in plan["script"]
    assert "Where-Object" in plan["script"] and GUID in plan["script"]
    assert "Restart-NetAdapter" in plan["script"]
    assert "Reset-NetAdapterAdvancedProperty" in mac.prepare_change(GUID, "restore")["script"]


def test_random_preview_is_exactly_the_address_applied(adapters, monkeypatch):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    plan = mac.prepare_change(GUID, "random")
    calls = []
    def execute(script):
        calls.append(script)
        return json.dumps({"actual_mac": plan["target_mac"], "verified": True})
    monkeypatch.setattr(mac, "_run_script", execute)
    result = mac.apply_change(GUID, "random", plan["target_mac"], plan["previous_mac"], plan["plan_token"])
    assert result["status"] == "APPLIED"
    assert calls == [plan["script"]]


def test_replacement_cannot_differ_from_prepared_preview(adapters, monkeypatch):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    plan = mac.prepare_change(GUID, "manual", TARGET)
    monkeypatch.setattr(mac, "_run_script", lambda *_: json.dumps({"actual_mac": FACTORY, "verified": True}))
    with pytest.raises(mac.MacManagementError, match="preview"):
        mac.apply_change(GUID, "manual", FACTORY, CURRENT, plan["plan_token"])


@pytest.mark.parametrize("altered", ["signature", "mode", "interface", "previous", "missing", "unregistered"])
def test_altered_or_unissued_preview_rejected_before_mutation(adapters, monkeypatch, altered):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    monkeypatch.setattr(mac, "_run_script", lambda *_: pytest.fail("Invalid preview executed"))
    plan = mac.prepare_change(GUID, "manual", TARGET)
    arguments = [GUID, "manual", TARGET, CURRENT, plan["plan_token"]]
    if altered == "signature":
        arguments[4] = plan["plan_token"][:-1] + ("1" if plan["plan_token"][-1] == "0" else "0")
    elif altered == "mode":
        arguments[1] = "random"
    elif altered == "interface":
        arguments[0] = "22222222-2222-2222-2222-222222222222"
    elif altered == "previous":
        arguments[3] = FACTORY
    elif altered == "missing":
        arguments[4] = ""
    else:
        mac._ISSUED_PREVIEWS.clear()
    with pytest.raises(mac.MacManagementError, match="preview"):
        mac.apply_change(*arguments)


def test_preview_expiry_and_replay_rejected_without_second_mutation(adapters, monkeypatch):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    now = [1000.0]
    monkeypatch.setattr(mac.time, "time", lambda: now[0])
    expired = mac.prepare_change(GUID, "manual", TARGET)
    now[0] += 301
    calls = []
    monkeypatch.setattr(mac, "_run_script", lambda script: calls.append(script) or json.dumps({"actual_mac": TARGET, "verified": True}))
    with pytest.raises(mac.MacManagementError, match="Expired"):
        mac.apply_change(GUID, "manual", TARGET, CURRENT, expired["plan_token"])
    fresh = mac.prepare_change(GUID, "manual", TARGET)
    assert mac.apply_change(GUID, "manual", TARGET, CURRENT, fresh["plan_token"])["status"] == "APPLIED"
    with pytest.raises(mac.MacManagementError, match="already used"):
        mac.apply_change(GUID, "manual", TARGET, CURRENT, fresh["plan_token"])
    assert len(calls) == 1


def test_restore_preview_checks_factory_address_again(adapters, monkeypatch):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    monkeypatch.setattr(mac, "_run_script", lambda *_: pytest.fail("Changed factory preview executed"))
    plan = mac.prepare_change(GUID, "restore")
    adapters["adapters"][0]["permanent_mac"] = TARGET
    with pytest.raises(mac.MacManagementError, match="factory address changed"):
        mac.apply_change(GUID, "restore", None, CURRENT, plan["plan_token"])


def test_preview_registry_is_bounded(adapters):
    for _ in range(140):
        mac.prepare_change(GUID, "manual", TARGET)
    assert len(mac._ISSUED_PREVIEWS) == 128


def test_stale_preview_rejected_before_mutation(adapters, monkeypatch):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    monkeypatch.setattr(mac, "_run_script", lambda *_: pytest.fail("Stale plan executed"))
    plan = mac.prepare_change(GUID, "manual", TARGET)
    adapters["adapters"][0]["current_mac"] = FACTORY
    with pytest.raises(mac.MacManagementError, match="after preview"):
        mac.apply_change(GUID, "manual", TARGET, CURRENT, plan["plan_token"])


def test_driver_mismatch_is_not_reported_as_success(adapters, monkeypatch):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    monkeypatch.setattr(mac, "_run_script", lambda *_: json.dumps({"actual_mac": CURRENT, "verified": False}))
    plan = mac.prepare_change(GUID, "manual", TARGET)
    assert mac.apply_change(GUID, "manual", TARGET, CURRENT, plan["plan_token"])["status"] == "NOT_VERIFIED"
    monkeypatch.setattr(mac, "_run_script", lambda *_: "not JSON")
    with pytest.raises(mac.MacManagementError, match="could not be verified"):
        mac.apply_change(GUID, "manual", TARGET, CURRENT, mac.prepare_change(GUID, "manual", TARGET)["plan_token"])


def test_unsupported_driver_and_unknown_permanent_address(adapters):
    adapters["adapters"][0]["supports_override"] = False
    with pytest.raises(mac.MacManagementError, match="driver"):
        mac.prepare_change(GUID, "manual", TARGET)
    adapters["adapters"][0]["supports_override"] = True
    adapters["adapters"][0]["permanent_mac"] = None
    with pytest.raises(mac.MacManagementError, match="Permanent"):
        mac.prepare_change(GUID, "restore")


def test_other_local_adapter_collision_rejected(adapters):
    adapters["adapters"].append({**adapters["adapters"][0], "interface_id": "22222222-2222-2222-2222-222222222222", "current_mac": TARGET})
    with pytest.raises(ValueError, match="Another local adapter"):
        mac.prepare_change(GUID, "manual", TARGET)


def test_linux_docker_does_not_attempt_host_access(monkeypatch):
    monkeypatch.setattr(mac, "host_windows", lambda: False)
    monkeypatch.setattr(mac, "_run_script", lambda *_: pytest.fail("Docker attempted Windows host access"))
    assert mac.adapter_status()["platform"] == "unsupported"
    assert not mac.adapter_status()["can_apply"]


def test_windows_query_normalizes_single_adapter_array(monkeypatch):
    monkeypatch.setattr(mac, "host_windows", lambda: True)
    monkeypatch.setattr(mac, "windows_elevated", lambda: False)
    row = {"interface_id": "{" + GUID + "}", "name": "Fixture", "current_mac": CURRENT.replace(":", "-"),
           "permanent_mac": FACTORY.replace(":", ""), "override_mac": "", "supports_override": True}
    monkeypatch.setattr(mac, "_run_script", lambda *_: json.dumps([row]))
    state = mac.adapter_status()
    assert state["adapters"][0]["current_mac"] == CURRENT
    assert state["adapters"][0]["permanent_mac"] == FACTORY
    assert not state["can_apply"]


def test_powershell_invocation_is_fixed_argv_no_shell(monkeypatch):
    captured = []
    def run(argv, **kwargs):
        captured.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="[]")
    monkeypatch.setattr(mac.subprocess, "run", run)
    assert mac._run_script(mac._READ_SCRIPT) == "[]"
    assert captured[0][1]["shell"] is False
    assert "-EncodedCommand" in captured[0][0]
    assert captured[0][1]["timeout"] == 25


@pytest.mark.parametrize("mode", ["manual", "random", "restore"])
def test_generated_change_script_parses_without_execution(adapters, mode):
    import shutil
    import subprocess
    executable = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if not executable:
        pytest.skip("Windows PowerShell parser required")
    script = mac.prepare_change(GUID, mode, TARGET if mode == "manual" else None)["script"]
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command",
                             "$s=[Console]::In.ReadToEnd(); [ScriptBlock]::Create($s) | Out-Null"],
                            input=script, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_mac_api_admin_capability_and_acknowledgement(client, admin_headers, adapters, monkeypatch):
    assert client.get("/api/system/mac/adapters").status_code == 401
    assert client.get("/api/system/mac/adapters", headers=admin_headers).status_code == 200
    for role in ["OPERATOR", "VIEWER"]:
        username = "mac-" + role.lower()
        client.post("/api/auth/users", headers=admin_headers,
                    json={"username": username, "password": "synthetic-long-role-password", "role": role})
        token = client.post("/api/auth/login", json={"username": username, "password": "synthetic-long-role-password"}).json()["token"]
        headers = {"Authorization": "Bearer " + token}
        assert client.get("/api/system/mac/adapters", headers=headers).status_code == 403
        assert client.post("/api/system/mac/plan", headers=headers,
                           json={"interface_id": GUID, "mode": "random"}).status_code == 403
        assert client.post("/api/system/mac/apply", headers=headers,
                           json={"interface_id": GUID, "mode": "manual", "mac_address": TARGET,
                                 "expected_mac": CURRENT, "plan_token": "synthetic-unused-token", "acknowledgement": "CHANGE LOCAL MAC"}).status_code == 403
    payload = {"interface_id": GUID, "mode": "manual", "mac_address": TARGET, "expected_mac": CURRENT,
               "plan_token": mac.prepare_change(GUID, "manual", TARGET)["plan_token"]}
    assert client.post("/api/system/mac/apply", headers=admin_headers, json=payload).status_code == 422
    monkeypatch.setattr(mac, "windows_elevated", lambda: False)
    assert client.post("/api/system/mac/apply", headers=admin_headers,
                       json={**payload, "acknowledgement": "CHANGE LOCAL MAC"}).status_code == 403
    assert client.post("/api/system/mac/plan", headers=admin_headers,
                       json={"interface_id": "not-a-guid", "mode": "random"}).status_code == 422
    assert client.post("/api/system/mac/plan", headers=admin_headers,
                       json={"interface_id": GUID, "mode": "manual", "mac_address": "0" * 12}).status_code == 400
    assert client.post("/api/system/mac/plan", headers=admin_headers,
                       json={"interface_id": GUID, "mode": "random", "arbitrary_command": "calc"}).status_code == 422


@pytest.mark.parametrize("mode", ["manual", "random", "restore"])
def test_mac_api_applies_exact_server_preview_once(client, admin_headers, adapters, monkeypatch, mode):
    monkeypatch.setattr(mac, "windows_elevated", lambda: True)
    calls = []
    target = FACTORY if mode == "restore" else TARGET
    monkeypatch.setattr(mac, "_run_script", lambda script: calls.append(script) or json.dumps({"actual_mac": target, "verified": True}))
    response = client.post("/api/system/mac/plan", headers=admin_headers,
                           json={"interface_id": GUID, "mode": mode, "mac_address": None if mode == "restore" else TARGET})
    assert response.status_code == 200
    assert response.json()["target_mac"] == target
    payload = {"interface_id": GUID, "mode": mode, "mac_address": None if mode == "restore" else TARGET, "expected_mac": CURRENT,
               "plan_token": response.json()["plan_token"], "acknowledgement": "CHANGE LOCAL MAC"}
    assert client.post("/api/system/mac/apply", headers=admin_headers, json=payload).json()["status"] == "APPLIED"
    assert client.post("/api/system/mac/apply", headers=admin_headers, json=payload).status_code == 409
    assert len(calls) == 1
