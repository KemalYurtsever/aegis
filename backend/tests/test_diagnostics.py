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
            "ip_address": "198.18.56.200",
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
