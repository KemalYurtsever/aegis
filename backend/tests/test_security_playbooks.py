from __future__ import annotations

import json
from concurrent.futures import Future
from dataclasses import dataclass, field

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.database import create_database_engine, migrate_security_playbook_columns
from app.models import Device, SecurityPlaybookRun, VulnerabilityScan, utc_now
from app.schemas import DnsQueryRead, LabCommandRead, TraceRouteRead
from app.services.security_playbook_service import (
    SecurityPlaybookRunner,
    build_playbook_run,
    load_playbook_run,
)


DEVICE = {
    "name": "Playbook target",
    "ip_address": "198.18.77.25",
    "device_type": "Server",
    "is_active": True,
}

EXPECTED_STEPS = [
    "powershell_tcp",
    "traceroute",
    "attack_surface",
    "dns_identity",
]


@dataclass
class FakePlaybookRunner:
    session_factory: object
    submitted: list[int] = field(default_factory=list)
    cancelled: list[int] = field(default_factory=list)

    def submit(self, run_id: int) -> bool:
        self.submitted.append(run_id)
        return True

    def cancel(self, run_id: int) -> bool:
        self.cancelled.append(run_id)
        now = utc_now()
        with self.session_factory() as db:
            run = db.get(SecurityPlaybookRun, run_id)
            if run is None:
                return False
            run.cancel_requested = True
            if run.status == "QUEUED":
                run.status = "CANCELLED"
                run.completed_at = now
                for step in run.steps:
                    step.status = "CANCELLED"
                    step.completed_at = now
                run.summary_json = json.dumps({
                    "total_steps": len(run.steps),
                    "completed_steps": 0,
                    "failed_steps": 0,
                    "cancelled_steps": len(run.steps),
                })
            db.commit()
        return True

    def shutdown(self, *args, **kwargs) -> None:
        return None


def install_fake_runner(client, monkeypatch) -> FakePlaybookRunner:
    runner = FakePlaybookRunner(client.app.state.session_factory)
    monkeypatch.setattr(client.app.state, "playbook_runner", runner, raising=False)
    return runner


def create_device(client, headers, **overrides):
    response = client.post("/api/devices", headers=headers, json=DEVICE | overrides)
    assert response.status_code == 201
    return response.json()


def test_admin_queues_playbook_with_ordered_persistent_steps(client, admin_headers, monkeypatch):
    runner = install_fake_runner(client, monkeypatch)
    device = create_device(client, admin_headers)

    response = client.post(
        "/api/security/playbooks/runs",
        headers=admin_headers,
        json={"device_id": device["id"], "profile": "DETAILED"},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["device_id"] == device["id"]
    assert body["profile"] == "DETAILED"
    assert body["status"] == "QUEUED"
    assert body["cancel_requested"] is False
    assert body["started_at"] is None
    assert body["completed_at"] is None
    assert [step["position"] for step in body["steps"]] == [1, 2, 3, 4]
    assert [step["step_key"] for step in body["steps"]] == EXPECTED_STEPS
    assert {step["status"] for step in body["steps"]} == {"PENDING"}
    assert runner.submitted == [body["id"]]

    stored = client.get(
        f"/api/security/playbooks/runs/{body['id']}", headers=admin_headers
    )
    assert stored.status_code == 200
    assert [step["step_key"] for step in stored.json()["steps"]] == EXPECTED_STEPS


def test_playbook_validates_registered_device_and_profile(client, admin_headers, monkeypatch):
    runner = install_fake_runner(client, monkeypatch)

    missing = client.post(
        "/api/security/playbooks/runs",
        headers=admin_headers,
        json={"device_id": 999_999, "profile": "FAST"},
    )
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Device not found"

    invalid_profile = client.post(
        "/api/security/playbooks/runs",
        headers=admin_headers,
        json={"device_id": 1, "profile": "STEALTH"},
    )
    assert invalid_profile.status_code == 422
    assert runner.submitted == []


def test_playbook_history_supports_device_filter_and_get(client, admin_headers, monkeypatch):
    runner = install_fake_runner(client, monkeypatch)
    first = create_device(client, admin_headers)
    second = create_device(
        client,
        admin_headers,
        name="Second target",
        ip_address="198.18.77.26",
    )

    first_run = client.post(
        "/api/security/playbooks/runs",
        headers=admin_headers,
        json={"device_id": first["id"], "profile": "FAST"},
    ).json()
    second_run = client.post(
        "/api/security/playbooks/runs",
        headers=admin_headers,
        json={"device_id": second["id"], "profile": "AGGRESSIVE"},
    ).json()

    history = client.get(
        "/api/security/playbooks/runs?limit=1", headers=admin_headers
    )
    assert history.status_code == 200
    assert [item["id"] for item in history.json()] == [second_run["id"]]

    filtered = client.get(
        f"/api/security/playbooks/runs?device_id={first['id']}",
        headers=admin_headers,
    )
    assert filtered.status_code == 200
    assert [item["id"] for item in filtered.json()] == [first_run["id"]]

    run_index = client.get(
        "/api/security/playbooks/run-index?limit=10", headers=admin_headers
    )
    assert run_index.status_code == 200
    assert [item["id"] for item in run_index.json()] == [second_run["id"], first_run["id"]]
    assert "steps" not in run_index.json()[0]

    found = client.get(
        f"/api/security/playbooks/runs/{second_run['id']}", headers=admin_headers
    )
    assert found.status_code == 200
    assert found.json()["profile"] == "AGGRESSIVE"
    assert client.get(
        "/api/security/playbooks/runs/999999", headers=admin_headers
    ).status_code == 404
    assert runner.submitted == [first_run["id"], second_run["id"]]


def test_admin_can_request_playbook_cancellation(client, admin_headers, monkeypatch):
    runner = install_fake_runner(client, monkeypatch)
    device = create_device(client, admin_headers)
    created = client.post(
        "/api/security/playbooks/runs",
        headers=admin_headers,
        json={"device_id": device["id"], "profile": "FAST"},
    ).json()

    response = client.post(
        f"/api/security/playbooks/runs/{created['id']}/cancel",
        headers=admin_headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == created["id"]
    assert response.json()["cancel_requested"] is True
    assert runner.cancelled == [created["id"]]


def test_playbooks_require_an_administrator(client, admin_headers, monkeypatch):
    runner = install_fake_runner(client, monkeypatch)
    device = create_device(client, admin_headers)
    created = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "username": "playbook-operator",
            "password": "operator-password-is-long",
            "role": "OPERATOR",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={
            "username": "playbook-operator",
            "password": "operator-password-is-long",
        },
    )
    operator_headers = {"Authorization": f"Bearer {login.json()['token']}"}

    assert client.post(
        "/api/security/playbooks/runs",
        headers=operator_headers,
        json={"device_id": device["id"], "profile": "FAST"},
    ).status_code == 403
    assert client.get(
        "/api/security/playbooks/runs", headers=operator_headers
    ).status_code == 403
    assert runner.submitted == []


def test_runner_persists_partial_progress_and_continues_after_step_failure(
    client, admin_headers, monkeypatch
):
    device_data = create_device(client, admin_headers)
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        device = db.get(Device, device_data["id"])
        run = build_playbook_run(device, "FAST", "test-admin")
        db.add(run)
        db.commit()
        run_id = run.id

    monkeypatch.setattr(
        "app.services.security_playbook_service.test_connection_ports",
        lambda _target, ports, timeout: {
            "reachable": True,
            "port_count": len(ports),
            "timeout": timeout,
        },
    )

    def unavailable_trace(_device):
        raise RuntimeError("trace unavailable")

    monkeypatch.setattr(
        "app.services.security_playbook_service.trace_registered_device",
        unavailable_trace,
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.query_dns",
        lambda target: {"query": target, "addresses": [target]},
    )

    runner = SecurityPlaybookRunner(session_factory)
    monkeypatch.setattr(
        runner,
        "_run_attack_surface",
        lambda _target: {
            "scan_id": 42,
            "status": "COMPLETED",
            "profile": "FAST",
            "finding_count": 3,
            "cve_candidates": 1,
        },
    )
    try:
        runner._execute_run(run_id)
    finally:
        runner.shutdown()

    with session_factory() as db:
        stored = load_playbook_run(run_id, db)
        assert stored is not None
        assert stored.status == "PARTIAL"
        assert stored.current_step is None
        assert stored.completed_at is not None
        assert stored.error is None
        statuses = {step.step_key: step.status for step in stored.steps}
        assert statuses == {
            "powershell_tcp": "COMPLETED",
            "traceroute": "FAILED",
            "attack_surface": "COMPLETED",
            "dns_identity": "COMPLETED",
        }
        failed_step = next(step for step in stored.steps if step.step_key == "traceroute")
        assert failed_step.error == "trace unavailable"
        assert all(step.completed_at is not None for step in stored.steps)
        assert stored.summary == {
            "total_steps": 4,
            "completed_steps": 3,
            "failed_steps": 1,
            "cancelled_steps": 0,
            "vulnerability_scan_id": 42,
            "findings": 3,
            "cve_candidates": 1,
        }


def test_runner_completes_all_steps_forwards_profile_and_bounds_output(
    client, admin_headers, monkeypatch
):
    device_data = create_device(client, admin_headers)
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        device = db.get(Device, device_data["id"])
        run = build_playbook_run(device, "AGGRESSIVE", "test-admin")
        db.add(run)
        db.commit()
        run_id = run.id

    calls = {}

    def tcp_result(target, ports, timeout):
        calls["tcp"] = (target, len(ports), timeout)
        return "é" * 60_000

    def vulnerability_result(device, db, profile):
        calls["vulnerability"] = (device.ip_address, profile)
        scan = VulnerabilityScan(
            device_id=device.id,
            profile=profile,
            status="COMPLETED",
            completed_at=utc_now(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    monkeypatch.setattr(
        "app.services.security_playbook_service.test_connection_ports", tcp_result
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.trace_registered_device",
        lambda device: {"target": device.ip_address, "hops": []},
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.run_vulnerability_scan",
        vulnerability_result,
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.query_dns",
        lambda target: {"query": target, "addresses": [target]},
    )

    runner = SecurityPlaybookRunner(session_factory)
    try:
        runner._execute_run(run_id)
    finally:
        runner.shutdown()

    with session_factory() as db:
        stored = load_playbook_run(run_id, db)
        assert stored is not None
        assert stored.status == "COMPLETED"
        assert stored.profile == "AGGRESSIVE"
        assert stored.current_step is None
        assert all(step.status == "COMPLETED" for step in stored.steps)
        tcp_step = next(step for step in stored.steps if step.step_key == "powershell_tcp")
        assert len(tcp_step.output.encode("utf-8")) <= 100_000
        assert tcp_step.output.endswith("\n[stored output truncated]")
        attack_step = next(step for step in stored.steps if step.step_key == "attack_surface")
        attack_output = json.loads(attack_step.output)
        assert attack_output["profile"] == "AGGRESSIVE"
        assert stored.summary["vulnerability_scan_id"] == attack_output["scan_id"]

    assert calls == {
        "tcp": (device_data["ip_address"], 64, 3),
        "vulnerability": (device_data["ip_address"], "AGGRESSIVE"),
    }


def test_runner_honors_cancellation_between_steps(client, admin_headers, monkeypatch):
    device_data = create_device(client, admin_headers)
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        device = db.get(Device, device_data["id"])
        run = build_playbook_run(device, "FAST", "test-admin")
        db.add(run)
        db.commit()
        run_id = run.id

    runner = SecurityPlaybookRunner(session_factory)
    calls = []

    def cancel_after_first_step(*_args):
        calls.append("powershell_tcp")
        assert runner.cancel(run_id) is True
        return {"message": "current step completed before cancellation"}

    def unexpected_step(*_args):
        calls.append("unexpected")
        return {}

    monkeypatch.setattr(
        "app.services.security_playbook_service.test_connection_ports",
        cancel_after_first_step,
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.trace_registered_device",
        unexpected_step,
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.query_dns",
        unexpected_step,
    )
    monkeypatch.setattr(runner, "_run_attack_surface", unexpected_step)
    try:
        runner._execute_run(run_id)
    finally:
        runner.shutdown()

    with session_factory() as db:
        stored = load_playbook_run(run_id, db)
        assert stored is not None
        assert stored.status == "CANCELLED"
        assert stored.cancel_requested is True
        assert stored.current_step is None
        assert [step.status for step in stored.steps] == [
            "COMPLETED",
            "CANCELLED",
            "CANCELLED",
            "CANCELLED",
        ]
        assert stored.summary == {
            "total_steps": 4,
            "completed_steps": 1,
            "failed_steps": 0,
            "cancelled_steps": 3,
        }
    assert calls == ["powershell_tcp"]


def test_runner_recovers_interrupted_runs_without_starting_background_work(
    client, admin_headers
):
    device_data = create_device(client, admin_headers)
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        device = db.get(Device, device_data["id"])
        run = build_playbook_run(device, "DETAILED", "test-admin")
        now = utc_now()
        run.status = "RUNNING"
        run.started_at = now
        run.current_step = run.steps[1].name
        run.steps[0].status = "COMPLETED"
        run.steps[0].started_at = now
        run.steps[0].completed_at = now
        run.steps[1].status = "RUNNING"
        run.steps[1].started_at = now
        db.add(run)
        db.commit()
        run_id = run.id

    runner = SecurityPlaybookRunner(session_factory)
    try:
        runner._recover_interrupted_runs()
    finally:
        runner.shutdown()

    with session_factory() as db:
        stored = load_playbook_run(run_id, db)
        assert stored is not None
        assert stored.status == "FAILED"
        assert stored.completed_at is not None
        assert stored.current_step is None
        assert "application stopped" in stored.error.lower()
        assert [step.status for step in stored.steps] == [
            "COMPLETED",
            "FAILED",
            "CANCELLED",
            "CANCELLED",
        ]
        assert stored.steps[1].error == "Interrupted by application restart"
        assert stored.summary == {
            "total_steps": 4,
            "completed_steps": 1,
            "failed_steps": 1,
            "cancelled_steps": 2,
        }


def test_runner_marks_unsuccessful_commands_failed_and_keeps_their_output(
    client, admin_headers, monkeypatch
):
    device_data = create_device(client, admin_headers)
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        device = db.get(Device, device_data["id"])
        run = build_playbook_run(device, "FAST", "test-admin")
        db.add(run)
        db.commit()
        run_id = run.id

    monkeypatch.setattr(
        "app.services.security_playbook_service.test_connection_ports",
        lambda *_args: LabCommandRead(
            tool="test-connection",
            target=device_data["ip_address"],
            exit_code=124,
            output="PowerShell command timed out",
            duration_ms=1000,
        ),
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.trace_registered_device",
        lambda _device: TraceRouteRead(
            device_id=device_data["id"],
            device_name=device_data["name"],
            target=device_data["ip_address"],
            completed=False,
            hops=[],
        ),
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.query_dns",
        lambda query: DnsQueryRead(
            query=query,
            canonical_name=None,
            addresses=[query],
            reverse_name=None,
        ),
    )
    runner = SecurityPlaybookRunner(session_factory)
    monkeypatch.setattr(
        runner,
        "_run_attack_surface",
        lambda _target: {"scan_id": 7, "finding_count": 0, "cve_candidates": 0},
    )
    try:
        runner._execute_run(run_id)
    finally:
        runner.shutdown()

    with session_factory() as db:
        stored = load_playbook_run(run_id, db)
        assert stored is not None
        assert stored.status == "PARTIAL"
        tcp_step, trace_step = stored.steps[:2]
        assert tcp_step.status == "FAILED"
        assert "timed out" in tcp_step.output
        assert tcp_step.error == "Command exceeded its time limit"
        assert trace_step.status == "FAILED"
        assert "Completed: no" in trace_step.output
        assert "did not complete" in trace_step.error.lower()


def test_only_one_active_playbook_can_exist_per_device(client, admin_headers):
    device_data = create_device(client, admin_headers)
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        device = db.get(Device, device_data["id"])
        db.add(build_playbook_run(device, "FAST", "test-admin"))
        db.commit()
        db.add(build_playbook_run(device, "DETAILED", "test-admin"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


class DeferredExecutor:
    def __init__(self):
        self.jobs = []
        self.submitted_ids = []

    def submit(self, function, run_id):
        future = Future()
        self.jobs.append((future, function, run_id))
        self.submitted_ids.append(run_id)
        return future

    def run_next(self):
        future, function, run_id = self.jobs.pop(0)
        assert future.set_running_or_notify_cancel()
        try:
            result = function(run_id)
        except Exception as exc:
            future.set_exception(exc)
        else:
            future.set_result(result)

    def shutdown(self, *, wait=True, cancel_futures=False):
        if cancel_futures:
            for future, _function, _run_id in self.jobs:
                future.cancel()


def test_queue_pump_starts_the_next_persisted_run_when_capacity_frees(
    client, admin_headers, monkeypatch
):
    first = create_device(client, admin_headers)
    second = create_device(
        client,
        admin_headers,
        name="Second playbook target",
        ip_address="198.18.77.26",
    )
    session_factory = client.app.state.session_factory
    with session_factory() as db:
        runs = [
            build_playbook_run(db.get(Device, item["id"]), "FAST", "test-admin")
            for item in (first, second)
        ]
        db.add_all(runs)
        db.commit()
        run_ids = [run.id for run in runs]

    monkeypatch.setattr(
        "app.services.security_playbook_service.test_connection_ports",
        lambda target, *_args: LabCommandRead(
            tool="test-connection", target=target, exit_code=0, output="ok", duration_ms=1
        ),
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.trace_registered_device",
        lambda device: TraceRouteRead(
            device_id=device.id,
            device_name=device.name,
            target=device.ip_address,
            completed=True,
            hops=[],
        ),
    )
    monkeypatch.setattr(
        "app.services.security_playbook_service.query_dns",
        lambda query: DnsQueryRead(
            query=query, canonical_name=None, addresses=[query], reverse_name=None
        ),
    )
    runner = SecurityPlaybookRunner(session_factory, max_pending=1)
    runner._executor.shutdown(wait=True, cancel_futures=True)
    deferred = DeferredExecutor()
    runner._executor = deferred
    monkeypatch.setattr(
        runner,
        "_run_attack_surface",
        lambda _target: {"scan_id": 8, "finding_count": 0, "cve_candidates": 0},
    )
    try:
        runner.start()
        assert deferred.submitted_ids == [run_ids[0]]
        deferred.run_next()
        assert deferred.submitted_ids == run_ids
        deferred.run_next()
    finally:
        runner.shutdown()

    with session_factory() as db:
        assert [load_playbook_run(run_id, db).status for run_id in run_ids] == [
            "COMPLETED",
            "COMPLETED",
        ]


def test_pre_release_playbook_table_migrates_active_queue_slot(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'old-playbooks.db'}")
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE security_playbook_runs (
                id INTEGER PRIMARY KEY,
                device_id INTEGER NOT NULL,
                status VARCHAR(10) NOT NULL,
                completed_at DATETIME,
                error VARCHAR(1000)
            )
        """))
        connection.execute(text("""
            CREATE TABLE security_playbook_steps (
                id INTEGER PRIMARY KEY,
                run_id INTEGER NOT NULL,
                status VARCHAR(10) NOT NULL,
                completed_at DATETIME
            )
        """))
        connection.execute(text(
            "INSERT INTO security_playbook_runs (id, device_id, status) "
            "VALUES (1, 9, 'QUEUED'), (2, 9, 'RUNNING'), (3, 10, 'COMPLETED')"
        ))
        connection.execute(text(
            "INSERT INTO security_playbook_steps (id, run_id, status) "
            "VALUES (1, 1, 'PENDING'), (2, 2, 'RUNNING')"
        ))

    migrate_security_playbook_columns(engine)

    with engine.begin() as connection:
        assert "active_slot" in {
            column["name"] for column in inspect(connection).get_columns("security_playbook_runs")
        }
        rows = connection.execute(text(
            "SELECT id, status, active_slot FROM security_playbook_runs ORDER BY id"
        )).all()
        assert rows == [
            (1, "QUEUED", 1),
            (2, "FAILED", None),
            (3, "COMPLETED", None),
        ]
        assert connection.execute(text(
            "SELECT status FROM security_playbook_steps WHERE run_id = 2"
        )).scalar_one() == "CANCELLED"
    engine.dispose()
