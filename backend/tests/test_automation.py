from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.models import MaintenanceWindow, utc_now
from app.services.automation_service import local_summary, report_path, window_is_active
from app.services.ping_service import PingResult


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "automation-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def device_payload(name, address):
    return {"name": name, "ip_address": address, "device_type": "Server", "is_active": True}


def test_automation_settings_maintenance_and_summary(client):
    headers = admin_headers(client)
    overview = client.get("/api/automation/overview", headers=headers)
    assert overview.status_code == 200
    assert overview.json()["settings"]["incidents_enabled"] is True

    now = utc_now()
    created = client.post("/api/automation/maintenance-windows", headers=headers, json={
        "name": "Nightly lab maintenance",
        "starts_at": (now - timedelta(minutes=5)).isoformat(),
        "ends_at": (now + timedelta(minutes=5)).isoformat(),
        "repeat": "DAILY",
        "reason": "Lab updates",
    })
    assert created.status_code == 201
    assert created.json()["active_now"] is True

    summary = client.post("/api/automation/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["source"] == "BUILT_IN"
    assert "active alerts" in summary.json()["text"]


def test_maintenance_window_can_be_paused_and_resumed(client):
    headers = admin_headers(client)
    now = utc_now()
    created = client.post("/api/automation/maintenance-windows", headers=headers, json={
        "name": "Switch replacement",
        "starts_at": (now - timedelta(minutes=10)).isoformat(),
        "ends_at": (now + timedelta(minutes=50)).isoformat(),
        "reason": "Scheduled replacement",
    })
    assert created.status_code == 201
    assert created.json()["enabled"] is True
    assert created.json()["active_now"] is True

    window_id = created.json()["id"]
    paused = client.patch(
        f"/api/automation/maintenance-windows/{window_id}",
        headers=headers,
        json={"enabled": False},
    )
    assert paused.status_code == 200
    assert paused.json()["enabled"] is False
    assert paused.json()["active_now"] is False

    resumed = client.patch(
        f"/api/automation/maintenance-windows/{window_id}",
        headers=headers,
        json={"enabled": True},
    )
    assert resumed.status_code == 200
    assert resumed.json()["enabled"] is True
    assert resumed.json()["active_now"] is True


def test_maintenance_window_schedule_can_be_updated(client):
    headers = admin_headers(client)
    now = utc_now()
    created = client.post("/api/automation/maintenance-windows", headers=headers, json={
        "name": "Original window",
        "device_group": "Servers",
        "starts_at": (now + timedelta(hours=1)).isoformat(),
        "ends_at": (now + timedelta(hours=2)).isoformat(),
        "reason": "Initial timing",
    })
    assert created.status_code == 201

    updated_starts = now + timedelta(hours=3)
    updated = client.patch(
        f"/api/automation/maintenance-windows/{created.json()['id']}",
        headers=headers,
        json={
            "name": "Network upgrade",
            "device_group": "Network",
            "starts_at": updated_starts.isoformat(),
            "ends_at": (updated_starts + timedelta(hours=2)).isoformat(),
            "repeat": "WEEKLY",
            "reason": "Core switch replacement",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Network upgrade"
    assert updated.json()["device_group"] == "Network"
    assert updated.json()["repeat"] == "WEEKLY"
    assert updated.json()["reason"] == "Core switch replacement"

    invalid = client.patch(
        f"/api/automation/maintenance-windows/{created.json()['id']}",
        headers=headers,
        json={"ends_at": (updated_starts - timedelta(minutes=1)).isoformat()},
    )
    assert invalid.status_code == 422

    malformed = client.patch(
        f"/api/automation/maintenance-windows/{created.json()['id']}",
        headers=headers,
        json={"name": None},
    )
    assert malformed.status_code == 422


def test_active_maintenance_suppresses_new_alerts(client, monkeypatch):
    headers = admin_headers(client)
    now = utc_now()
    client.post("/api/automation/maintenance-windows", headers=headers, json={
        "name": "All-device maintenance",
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "ends_at": (now + timedelta(minutes=10)).isoformat(),
    })
    device = client.post("/api/devices", headers=headers, json=device_payload(
        "Maintained server", "192.168.70.10"
    )).json()
    client.put(f"/api/devices/{device['id']}/alert-rule", headers=headers, json={
        "enabled": True, "consecutive_failures": 1, "latency_threshold_ms": 10,
    })
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("OFFLINE", None, "no_reply"),
    )
    checked = client.post(f"/api/devices/{device['id']}/check", headers=headers)
    assert checked.status_code == 201
    assert client.get("/api/alerts", headers=headers).json() == []


def test_related_alerts_are_correlated_into_one_incident(client, monkeypatch):
    headers = admin_headers(client)
    first = client.post("/api/devices", headers=headers, json=device_payload(
        "First server", "192.168.80.10"
    )).json()
    second = client.post("/api/devices", headers=headers, json=device_payload(
        "Second server", "192.168.80.11"
    )).json()
    for device in (first, second):
        client.put(f"/api/devices/{device['id']}/alert-rule", headers=headers, json={
            "enabled": True, "consecutive_failures": 1, "latency_threshold_ms": 10,
        })
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("OFFLINE", None, "no_reply"),
    )
    client.post(f"/api/devices/{first['id']}/check", headers=headers)
    client.post(f"/api/devices/{second['id']}/check", headers=headers)

    cycle = client.post("/api/automation/run", headers=headers)
    assert cycle.status_code == 200
    incidents = client.get("/api/automation/incidents", headers=headers).json()
    assert len(incidents) == 1
    assert incidents[0]["status"] == "OPEN"
    assert len(incidents[0]["alert_ids"]) == 2

    updated = client.patch(
        f"/api/automation/incidents/{incidents[0]['id']}",
        json={"assigned_to": "  on-call engineer ", "operator_note": "  Checking the shared switch.  "},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["assigned_to"] == "on-call engineer"
    assert updated.json()["operator_note"] == "Checking the shared switch."

    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("ONLINE", 1.0),
    )
    client.post(f"/api/devices/{first['id']}/check", headers=headers)
    client.post(f"/api/devices/{second['id']}/check", headers=headers)
    assert client.post("/api/automation/run", headers=headers).status_code == 200
    resolved = client.get("/api/automation/incidents", headers=headers).json()
    assert len(resolved) == 1
    assert resolved[0]["status"] == "RESOLVED"
    assert resolved[0]["resolved_at"] is not None


def test_drift_and_scheduled_report(client, monkeypatch, tmp_path):
    headers = admin_headers(client)
    monkeypatch.setattr(
        "app.services.automation_service.get_settings",
        lambda: SimpleNamespace(
            report_directory=str(tmp_path / "reports"),
            foundry_local_url=None,
            foundry_local_model=None,
        ),
    )
    device = client.post("/api/devices", headers=headers, json=device_payload(
        "Baseline server", "192.168.90.10"
    )).json()
    first = client.post("/api/automation/baselines/refresh", headers=headers)
    assert first.json()["changes"] == 0

    updated = client.put(f"/api/devices/{device['id']}", headers=headers, json={
        **device_payload("Baseline server", "192.168.90.10"),
        "operating_system": "Windows Server 2025",
    })
    assert updated.status_code == 200
    second = client.post("/api/automation/baselines/refresh", headers=headers)
    assert second.json()["changes"] == 1
    events = client.get("/api/automation/events", headers=headers).json()
    assert events[0]["event_type"] == "CONFIGURATION_DRIFT"
    device_events = client.get(
        f"/api/automation/events?device_id={device['id']}&limit=10",
        headers=headers,
    ).json()
    assert len(device_events) == 1
    assert device_events[0]["device_id"] == device["id"]

    generated = client.post("/api/automation/reports/generate", headers=headers)
    assert generated.status_code == 201
    report = generated.json()
    assert report["device_count"] == 1
    downloaded = client.get(
        f"/api/automation/reports/{report['filename']}/download", headers=headers
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"].startswith("application/json")


def test_stale_warning_is_escalated_once(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", headers=headers, json=device_payload(
        "Slow server", "192.168.95.10"
    )).json()
    client.put(f"/api/devices/{device['id']}/alert-rule", headers=headers, json={
        "enabled": True, "consecutive_failures": 2, "latency_threshold_ms": 10,
    })
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("ONLINE", 50),
    )
    client.post(f"/api/devices/{device['id']}/check", headers=headers)
    original_now = utc_now()
    monkeypatch.setattr(
        "app.services.automation_service.utc_now",
        lambda: original_now + timedelta(minutes=6),
    )
    settings = client.get("/api/automation/overview", headers=headers).json()["settings"]
    settings["alert_escalation_minutes"] = 5
    for field in ("id", "last_report_at", "last_discovery_at", "last_discovery_network", "last_vulnerability_at", "updated_at"):
        settings.pop(field, None)
    assert client.put("/api/automation/settings", headers=headers, json=settings).status_code == 200
    cycle = client.post("/api/automation/run", headers=headers)
    assert cycle.json()["escalated_alerts"] == 1
    alert = client.get("/api/alerts", headers=headers).json()[0]
    assert alert["severity"] == "CRITICAL"
    assert alert["message"].startswith("Escalated: ")


def test_maintenance_window_recurrence_boundaries():
    starts_at = datetime(2026, 8, 28, 1, 0, tzinfo=timezone.utc)
    ends_at = starts_at + timedelta(hours=1)
    daily = MaintenanceWindow(
        name="Daily",
        starts_at=starts_at,
        ends_at=ends_at,
        repeat="DAILY",
        enabled=True,
    )
    weekly = MaintenanceWindow(
        name="Weekly",
        starts_at=starts_at,
        ends_at=ends_at,
        repeat="WEEKLY",
        enabled=True,
    )

    assert window_is_active(daily, starts_at + timedelta(days=3, minutes=30))
    assert not window_is_active(daily, starts_at + timedelta(days=3, hours=2))
    assert window_is_active(weekly, starts_at + timedelta(days=14, minutes=30))
    assert not window_is_active(weekly, starts_at + timedelta(days=13, minutes=30))
    daily.enabled = False
    assert not window_is_active(daily, starts_at + timedelta(days=3, minutes=30))


def test_report_path_rejects_traversal_and_accepts_local_file(monkeypatch, tmp_path):
    report = tmp_path / "availability.json"
    report.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "app.services.automation_service.get_settings",
        lambda: SimpleNamespace(report_directory=str(tmp_path)),
    )

    assert report_path("availability.json") == report.resolve()
    with pytest.raises(ValueError, match="Invalid report filename"):
        report_path("../monitoring.db")
    with pytest.raises(FileNotFoundError):
        report_path("missing.json")


def test_local_summary_never_calls_a_non_loopback_model(client, monkeypatch):
    monkeypatch.setattr(
        "app.services.automation_service.get_settings",
        lambda: SimpleNamespace(
            foundry_local_url="http://192.168.1.50:5272",
            foundry_local_model="lab-model",
        ),
    )
    with client.app.state.session_factory() as db:
        summary = local_summary(db)

    assert summary.source == "BUILT_IN"
    assert "Current AEGIS health" in summary.text


def test_repeated_automation_cycles_do_not_duplicate_diagnostics(client, monkeypatch):
    headers = admin_headers(client)
    devices = [
        client.post(
            "/api/devices",
            headers=headers,
            json=device_payload(name, address),
        ).json()
        for name, address in (
            ("Diagnostic first", "192.168.100.10"),
            ("Diagnostic second", "192.168.100.11"),
        )
    ]
    for device in devices:
        client.put(
            f"/api/devices/{device['id']}/alert-rule",
            headers=headers,
            json={"enabled": True, "consecutive_failures": 1, "latency_threshold_ms": 10},
        )
        token = client.post(
            f"/api/devices/{device['id']}/agent/enroll", headers=headers
        ).json()["token"]
        metric = {
            "hostname": device["name"],
            "platform": "Windows test",
            "agent_version": "0.3.0",
            "report_interval_seconds": 60,
            "diagnostics_enabled": True,
            "cpu_percent": 10,
            "memory_percent": 20,
            "disk_percent": 30,
            "memory_used_bytes": 200,
            "memory_total_bytes": 1000,
            "disk_used_bytes": 300,
            "disk_total_bytes": 1000,
        }
        assert client.post(
            "/api/agent/metrics",
            headers={"X-Agent-Token": token},
            json=metric,
        ).status_code == 201

    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("OFFLINE", None, "no_reply"),
    )
    for device in devices:
        client.post(f"/api/devices/{device['id']}/check", headers=headers)

    with client.app.state.session_factory() as db:
        from app.services.automation_service import get_automation_settings

        get_automation_settings(db).diagnostics_enabled = True
        db.commit()

    first_cycle = client.post("/api/automation/run", headers=headers).json()
    second_cycle = client.post("/api/automation/run", headers=headers).json()
    assert first_cycle["diagnostics"] == 6
    assert second_cycle["diagnostics"] == 0
    for device in devices:
        jobs = client.get(
            f"/api/devices/{device['id']}/diagnostic-jobs", headers=headers
        ).json()
        assert len(jobs) == 3
        assert {job["job_type"] for job in jobs} == {
            "NETWORK_CONNECTIONS",
            "TOP_PROCESSES",
            "SECURITY_LOG_SUMMARY",
        }
