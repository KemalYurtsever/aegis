PAYLOAD = {
    "hostname": "lab-linux", "platform": "Linux 6.x", "agent_version": "0.1.0",
    "report_interval_seconds": 60,
    "cpu_percent": 12.0, "memory_percent": 45.0, "disk_percent": 30.0,
    "memory_used_bytes": 450, "memory_total_bytes": 1000,
    "disk_used_bytes": 300, "disk_total_bytes": 1000,
}


def create_remote_device(client):
    return client.post("/api/devices", json={
        "name": "Linux Agent", "ip_address": "198.18.56.90", "device_type": "Server",
        "description": None, "is_active": True,
    }).json()


def test_agent_enrollment_submission_and_revocation(client):
    device = create_remote_device(client)
    enrolled = client.post(f"/api/devices/{device['id']}/agent/enroll")
    assert enrolled.status_code == 201
    token = enrolled.json()["token"]
    assert len(token) >= 32

    assert client.post("/api/agent/metrics", json=PAYLOAD).status_code == 422
    assert client.post("/api/agent/metrics", json=PAYLOAD, headers={"X-Agent-Token": "x" * 32}).status_code == 401
    submitted = client.post("/api/agent/metrics", json=PAYLOAD, headers={"X-Agent-Token": token})
    assert submitted.status_code == 201
    assert submitted.json()["device_id"] == device["id"]

    status = client.get(f"/api/devices/{device['id']}/agent").json()
    assert status["hostname"] == "lab-linux"
    assert status["last_seen_at"] is not None
    assert status["health_status"] == "REPORTING"
    assert status["report_interval_seconds"] == 60
    assert len(client.get(f"/api/devices/{device['id']}/metrics").json()) == 1

    assert client.delete(f"/api/devices/{device['id']}/agent").status_code == 204
    assert client.post("/api/agent/metrics", json=PAYLOAD, headers={"X-Agent-Token": token}).status_code == 401


def test_reenrollment_invalidates_old_token(client):
    device = create_remote_device(client)
    first = client.post(f"/api/devices/{device['id']}/agent/enroll").json()["token"]
    second = client.post(f"/api/devices/{device['id']}/agent/enroll").json()["token"]
    assert first != second
    assert client.post("/api/agent/metrics", json=PAYLOAD, headers={"X-Agent-Token": first}).status_code == 401
    assert client.post("/api/agent/metrics", json=PAYLOAD, headers={"X-Agent-Token": second}).status_code == 201


def test_agent_health_transitions_from_reporting_to_delayed_and_offline():
    now = datetime.now(timezone.utc)
    enrollment = AgentEnrollment(
        device_id=1,
        token_hash="a" * 64,
        enabled=True,
        created_at=now,
        last_seen_at=now - timedelta(seconds=30),
        report_interval_seconds=60,
    )
    assert serialize_enrollment(enrollment, now).health_status == "REPORTING"
    enrollment.last_seen_at = now - timedelta(seconds=180)
    assert serialize_enrollment(enrollment, now).health_status == "DELAYED"
    enrollment.last_seen_at = now - timedelta(seconds=360)
    assert serialize_enrollment(enrollment, now).health_status == "OFFLINE"


def test_agent_fleet_overview_counts_waiting_and_reporting(client):
    device = create_remote_device(client)
    enrolled = client.post(f"/api/devices/{device['id']}/agent/enroll").json()

    waiting = client.get("/api/agents/overview").json()
    assert waiting["total_agents"] == 1
    assert waiting["waiting_agents"] == 1
    assert waiting["agents"][0]["device_name"] == "Linux Agent"

    client.post("/api/agent/metrics", json=PAYLOAD, headers={"X-Agent-Token": enrolled["token"]})
    reporting = client.get("/api/agents/overview").json()
    assert reporting["reporting_agents"] == 1
    assert reporting["waiting_agents"] == 0
from datetime import datetime, timedelta, timezone

from app.models import AgentEnrollment
from app.routers.agents import serialize_enrollment
