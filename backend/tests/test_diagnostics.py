import hashlib
import hmac
from datetime import timedelta

from sqlalchemy import create_engine, text

from app.database import migrate_diagnostic_job_types
from app.models import DiagnosticJob, utc_now


def authenticate_admin(client):
    created = client.post(
        "/api/auth/setup",
        json={"username": "diagnostic-admin", "password": "correct-horse-battery-staple"},
    )
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {created.json()['token']}"}


def create_enrolled_device(client, headers):
    device = client.post(
        "/api/devices",
        headers=headers,
        json={
            "name": "Diagnostic Host",
            "ip_address": "192.168.56.200",
            "device_type": "Server",
            "description": None,
            "is_active": True,
        },
    ).json()
    enrollment = client.post(f"/api/devices/{device['id']}/agent/enroll", headers=headers).json()
    metric = {
        "hostname": "diagnostic-host",
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
    submitted = client.post(
        "/api/agent/metrics",
        headers={"X-Agent-Token": enrollment["token"]},
        json=metric,
    )
    assert submitted.status_code == 201
    return device, enrollment["token"]


def test_admin_creates_agent_executes_and_reads_diagnostic_job(client):
    headers = authenticate_admin(client)
    device, token = create_enrolled_device(client, headers)

    created = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
        json={"job_type": "NETWORK_CONNECTIONS", "max_records": 25, "duration_seconds": 10},
    )
    assert created.status_code == 201
    assert created.json()["status"] == "PENDING"
    assert created.json()["requested_by"] == "diagnostic-admin"
    job_id = created.json()["id"]

    assert client.get("/api/agent/jobs/next", headers={"X-Agent-Token": "x" * 32}).status_code == 401
    claimed = client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token})
    assert claimed.status_code == 200
    assert claimed.json() == {
        "id": job_id,
        "job_type": "NETWORK_CONNECTIONS",
        "parameters": {"max_records": 25},
    }
    assert client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token}).status_code == 204

    result = {"total_connections": 1, "connections": [{"local_address": "127.0.0.1:8002"}]}
    completed = client.post(
        f"/api/agent/jobs/{job_id}/result",
        headers={"X-Agent-Token": token},
        json={"status": "COMPLETED", "result": result, "error": None},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "COMPLETED"
    assert completed.json()["result"] == result

    repeated = client.post(
        f"/api/agent/jobs/{job_id}/result",
        headers={"X-Agent-Token": token},
        json={"status": "COMPLETED", "result": {"ignored": True}, "error": None},
    )
    assert repeated.status_code == 200
    assert repeated.json()["result"] == result

    history = client.get(f"/api/devices/{device['id']}/diagnostic-jobs", headers=headers)
    assert history.status_code == 200
    assert history.json()[0]["id"] == job_id


def test_diagnostic_jobs_require_admin_and_are_allowlisted(client):
    admin_headers = authenticate_admin(client)
    device, _token = create_enrolled_device(client, admin_headers)
    operator = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={"username": "operator", "password": "operator-password-123", "role": "OPERATOR"},
    )
    assert operator.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator-password-123"},
    ).json()
    operator_headers = {"Authorization": f"Bearer {login['token']}"}

    forbidden = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=operator_headers,
        json={"job_type": "TOP_PROCESSES"},
    )
    assert forbidden.status_code == 403
    invalid = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=admin_headers,
        json={"job_type": "ARBITRARY_SHELL"},
    )
    assert invalid.status_code == 422


def test_pending_diagnostic_can_be_cancelled(client):
    headers = authenticate_admin(client)
    device, token = create_enrolled_device(client, headers)
    created = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
        json={"job_type": "FIREWALL_RULES"},
    ).json()
    cancelled = client.post(f"/api/diagnostic-jobs/{created['id']}/cancel", headers=headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"
    assert client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token}).status_code == 204


def test_diagnostic_result_size_is_bounded(client):
    headers = authenticate_admin(client)
    device, token = create_enrolled_device(client, headers)
    job = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
        json={"job_type": "SECURITY_LOG_SUMMARY"},
    ).json()
    client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token})
    oversized = client.post(
        f"/api/agent/jobs/{job['id']}/result",
        headers={"X-Agent-Token": token},
        json={"status": "COMPLETED", "result": {"output": "x" * 51_000}, "error": None},
    )
    assert oversized.status_code == 413


def test_safe_validation_callback_is_nonce_bound_and_preserved(client):
    headers = authenticate_admin(client)
    device, token = create_enrolled_device(client, headers)
    created = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "CALLBACK_CANARY",
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    )
    assert created.status_code == 201
    assert created.json()["parameters"]["simulation_type"] == "CALLBACK_CANARY"
    job_id = created.json()["id"]
    nonce = created.json()["parameters"]["nonce"]

    claimed = client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token})
    assert claimed.status_code == 200
    assert claimed.json()["parameters"]["nonce"] == nonce

    invalid = client.post(
        f"/api/agent/jobs/{job_id}/validation-callback",
        headers={
            "X-Agent-Token": token,
            "X-Aegis-Validation-Signature": "0" * 64,
        },
    )
    assert invalid.status_code == 401

    signature = hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
    callback = client.post(
        f"/api/agent/jobs/{job_id}/validation-callback",
        headers={
            "X-Agent-Token": token,
            "X-Aegis-Validation-Signature": signature,
        },
    )
    assert callback.status_code == 204

    completed = client.post(
        f"/api/agent/jobs/{job_id}/result",
        headers={"X-Agent-Token": token},
        json={"status": "COMPLETED", "result": {"callback_submitted": True}},
    )
    assert completed.status_code == 200
    assert completed.json()["result"]["callback_submitted"] is True
    assert completed.json()["result"]["callback"]["verified"] is True


def test_claimed_diagnostic_rejects_callbacks_and_results_after_expiry(client):
    headers = authenticate_admin(client)
    device, token = create_enrolled_device(client, headers)
    created = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "CALLBACK_CANARY",
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    ).json()
    client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token})

    with client.app.state.session_factory() as db:
        job = db.get(DiagnosticJob, created["id"])
        job.expires_at = utc_now() - timedelta(seconds=1)
        db.commit()

    signature = hmac.new(
        token.encode(),
        created["parameters"]["nonce"].encode(),
        hashlib.sha256,
    ).hexdigest()
    callback = client.post(
        f"/api/agent/jobs/{created['id']}/validation-callback",
        headers={
            "X-Agent-Token": token,
            "X-Aegis-Validation-Signature": signature,
        },
    )
    result = client.post(
        f"/api/agent/jobs/{created['id']}/result",
        headers={"X-Agent-Token": token},
        json={"status": "COMPLETED", "result": {"late": True}},
    )
    listed = client.get(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
    ).json()

    assert callback.status_code == 409
    assert result.status_code == 409
    assert listed[0]["status"] == "EXPIRED"


def test_server_callback_evidence_survives_result_without_payload(client):
    headers = authenticate_admin(client)
    device, token = create_enrolled_device(client, headers)
    created = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "CALLBACK_CANARY",
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    ).json()
    client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token})
    signature = hmac.new(
        token.encode(),
        created["parameters"]["nonce"].encode(),
        hashlib.sha256,
    ).hexdigest()
    client.post(
        f"/api/agent/jobs/{created['id']}/validation-callback",
        headers={
            "X-Agent-Token": token,
            "X-Aegis-Validation-Signature": signature,
        },
    )

    completed = client.post(
        f"/api/agent/jobs/{created['id']}/result",
        headers={"X-Agent-Token": token},
        json={"status": "COMPLETED", "result": None},
    )

    assert completed.status_code == 200
    assert completed.json()["result"]["callback"]["verified"] is True


def test_safe_validation_requires_exact_authorization_and_one_active_job(client):
    headers = authenticate_admin(client)
    device, _token = create_enrolled_device(client, headers)
    url = f"/api/devices/{device['id']}/diagnostic-jobs"

    missing_phrase = client.post(
        url,
        headers=headers,
        json={"job_type": "VALIDATION_SIMULATION", "simulation_type": "TEMPORARY_MARKER"},
    )
    assert missing_phrase.status_code == 422

    first = client.post(
        url,
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "TEMPORARY_MARKER",
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    )
    assert first.status_code == 201

    second = client.post(
        url,
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "SIGNED_CANARY_ARTIFACT",
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    )
    assert second.status_code == 409


def test_segmentation_validation_accepts_only_registered_destination(client):
    headers = authenticate_admin(client)
    source, _token = create_enrolled_device(client, headers)
    destination = client.post(
        "/api/devices",
        headers=headers,
        json={"name": "Validation target", "ip_address": "192.168.56.201", "device_type": "Server"},
    ).json()

    missing = client.post(
        f"/api/devices/{source['id']}/diagnostic-jobs",
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "SEGMENTATION_PROBE",
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    )
    assert missing.status_code == 422

    same_device = client.post(
        f"/api/devices/{source['id']}/diagnostic-jobs",
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "SEGMENTATION_PROBE",
            "target_device_id": source["id"],
            "target_port": 443,
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    )
    assert same_device.status_code == 422

    created = client.post(
        f"/api/devices/{source['id']}/diagnostic-jobs",
        headers=headers,
        json={
            "job_type": "VALIDATION_SIMULATION",
            "simulation_type": "SEGMENTATION_PROBE",
            "target_device_id": destination["id"],
            "target_port": 443,
            "authorization_phrase": "RUN SAFE VALIDATION",
        },
    )
    assert created.status_code == 201
    assert created.json()["parameters"] | {} == {
        "simulation_type": "SEGMENTATION_PROBE",
        "nonce": created.json()["parameters"]["nonce"],
        "max_records": 25,
        "target_device_id": destination["id"],
        "target_address": "192.168.56.201",
        "target_port": 443,
    }


def test_validation_parameters_are_rejected_for_other_diagnostics(client):
    headers = authenticate_admin(client)
    device, _token = create_enrolled_device(client, headers)
    response = client.post(
        f"/api/devices/{device['id']}/diagnostic-jobs",
        headers=headers,
        json={"job_type": "TOP_PROCESSES", "simulation_type": "TEMPORARY_MARKER"},
    )
    assert response.status_code == 422


def test_diagnostic_type_migration_preserves_existing_history(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy-diagnostics.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE devices (id INTEGER PRIMARY KEY)"))
        connection.execute(text("INSERT INTO devices (id) VALUES (1)"))
        connection.execute(text("""
            CREATE TABLE diagnostic_jobs (
                id INTEGER PRIMARY KEY,
                device_id INTEGER NOT NULL,
                job_type VARCHAR(40) NOT NULL CHECK (job_type IN ('TOP_PROCESSES')),
                status VARCHAR(12) NOT NULL,
                requested_by VARCHAR(80) NOT NULL,
                parameters_json TEXT NOT NULL,
                result_json TEXT,
                error VARCHAR(1000),
                created_at DATETIME NOT NULL,
                claimed_at DATETIME,
                completed_at DATETIME,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
            )
        """))
        connection.execute(text("""
            INSERT INTO diagnostic_jobs
            (id, device_id, job_type, status, requested_by, parameters_json, created_at, expires_at)
            VALUES (7, 1, 'TOP_PROCESSES', 'COMPLETED', 'admin', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """))

    migrate_diagnostic_job_types(engine)

    with engine.connect() as connection:
        definition = connection.execute(text(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='diagnostic_jobs'"
        )).scalar_one()
        preserved = connection.execute(text(
            "SELECT id, job_type, status FROM diagnostic_jobs WHERE id=7"
        )).one()
    assert "VALIDATION_SIMULATION" in definition
    assert preserved == (7, "TOP_PROCESSES", "COMPLETED")
