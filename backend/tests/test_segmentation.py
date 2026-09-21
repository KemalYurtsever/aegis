def enrolled_source(client, admin_headers):
    source = client.post("/api/devices", headers=admin_headers, json={
        "name": "Source agent", "ip_address": "198.18.70.10",
    }).json()
    token = client.post(f"/api/devices/{source['id']}/agent/enroll", headers=admin_headers).json()["token"]
    assert client.post("/api/agent/metrics", headers={"X-Agent-Token": token}, json={
        "hostname": "source-agent", "platform": "test", "agent_version": "0.3.0",
        "report_interval_seconds": 60, "diagnostics_enabled": True,
        "cpu_percent": 10, "memory_percent": 10, "disk_percent": 10,
        "memory_used_bytes": 100, "memory_total_bytes": 1000,
        "disk_used_bytes": 100, "disk_total_bytes": 1000,
    }).status_code == 201
    return source, token


def test_policy_compares_agent_report_with_expected_tcp_reachability(client, admin_headers):
    source, token = enrolled_source(client, admin_headers)
    target = client.post("/api/devices", headers=admin_headers, json={
        "name": "Target", "ip_address": "198.18.70.20",
    }).json()
    policy_payload = {
        "source_device_id": source["id"], "target_device_id": target["id"],
        "target_port": 443, "expected_reachability": "DENY",
        "description": "  Lab isolation rule  ",
    }
    policy_response = client.post("/api/segmentation-policies", headers=admin_headers, json=policy_payload)
    assert policy_response.status_code == 201
    policy = policy_response.json()
    assert policy["description"] == "Lab isolation rule"
    assert client.post("/api/segmentation-policies", headers=admin_headers, json=policy_payload).status_code == 409
    assert client.post(f"/api/segmentation-policies/{policy['id']}/checks", headers=admin_headers, json={}).status_code == 422

    queued = client.post(f"/api/segmentation-policies/{policy['id']}/checks", headers=admin_headers, json={
        "authorization_phrase": "RUN SAFE VALIDATION",
    })
    assert queued.status_code == 201
    assert queued.json()["status"] == "PENDING"
    job = client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token}).json()
    assert job["parameters"]["target_address"] == target["ip_address"]
    assert job["parameters"]["target_port"] == 443
    assert client.post(f"/api/agent/jobs/{job['id']}/result", headers={"X-Agent-Token": token}, json={
        "status": "COMPLETED",
        "result": {
            "simulation_type": "SEGMENTATION_PROBE",
            "target_address": target["ip_address"], "target_device_id": target["id"],
            "target_port": 443, "connected": False, "application_data_sent": False,
            "error_type": "TimeoutError",
        },
    }).status_code == 200
    result = client.get(f"/api/segmentation-policies/{policy['id']}/checks", headers=admin_headers).json()[0]
    assert result["status"] == "MATCH"
    assert result["observed_connected"] is False
    assert "cannot be distinguished" in result["interpretation"]

    listed = client.get(f"/api/segmentation-policies?source_device_id={source['id']}", headers=admin_headers)
    assert [item["id"] for item in listed.json()] == [policy["id"]]


def test_policy_reports_deviation_and_rejects_mismatched_agent_evidence(client, admin_headers):
    source, token = enrolled_source(client, admin_headers)
    target = client.post("/api/devices", headers=admin_headers, json={
        "name": "Target", "ip_address": "198.18.70.21",
    }).json()
    policy = client.post("/api/segmentation-policies", headers=admin_headers, json={
        "source_device_id": source["id"], "target_device_id": target["id"],
        "target_port": 8443, "expected_reachability": "ALLOW",
    }).json()
    for address, target_id, expected_status in (
        (target["ip_address"], target["id"], "DEVIATION"),
        ("198.18.70.99", target["id"], "INCONCLUSIVE"),
        (target["ip_address"], source["id"], "INCONCLUSIVE"),
    ):
        client.post(f"/api/segmentation-policies/{policy['id']}/checks", headers=admin_headers, json={
            "authorization_phrase": "RUN SAFE VALIDATION",
        })
        job = client.get("/api/agent/jobs/next", headers={"X-Agent-Token": token}).json()
        client.post(f"/api/agent/jobs/{job['id']}/result", headers={"X-Agent-Token": token}, json={
            "status": "COMPLETED",
            "result": {
                "simulation_type": "SEGMENTATION_PROBE", "target_address": address,
                "target_device_id": target_id,
                "target_port": 8443, "connected": False, "application_data_sent": False,
            },
        })
        latest = client.get(f"/api/segmentation-policies/{policy['id']}/checks", headers=admin_headers).json()[0]
        assert latest["status"] == expected_status


def test_policy_requires_admin_and_agent_opt_in(client, admin_headers):
    source = client.post("/api/devices", headers=admin_headers, json={
        "name": "Unenrolled", "ip_address": "198.18.72.10",
    }).json()
    target = client.post("/api/devices", headers=admin_headers, json={
        "name": "Target", "ip_address": "198.18.72.20",
    }).json()
    payload = {"source_device_id": source["id"], "target_device_id": target["id"],
               "target_port": 80, "expected_reachability": "ALLOW"}
    client.post("/api/auth/users", headers=admin_headers, json={
        "username": "segment-operator", "password": "operator-correct-horse-battery-staple", "role": "OPERATOR",
    })
    token = client.post("/api/auth/login", json={
        "username": "segment-operator", "password": "operator-correct-horse-battery-staple",
    }).json()["token"]
    operator_headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/segmentation-policies", headers=operator_headers, json=payload).status_code == 403
    assert client.get("/api/segmentation-policies", headers=operator_headers).status_code == 403

    policy = client.post("/api/segmentation-policies", headers=admin_headers, json=payload).json()
    assert client.post(f"/api/segmentation-policies/{policy['id']}/checks", headers=admin_headers, json={
        "authorization_phrase": "RUN SAFE VALIDATION",
    }).status_code == 409
    assert client.post(f"/api/segmentation-policies/{policy['id']}/checks", headers=operator_headers, json={
        "authorization_phrase": "RUN SAFE VALIDATION",
    }).status_code == 403


def test_deleting_registered_source_removes_its_segmentation_policy(client, admin_headers):
    source = client.post("/api/devices", headers=admin_headers, json={
        "name": "Source", "ip_address": "198.18.73.10",
    }).json()
    target = client.post("/api/devices", headers=admin_headers, json={
        "name": "Target", "ip_address": "198.18.73.20",
    }).json()
    policy = client.post("/api/segmentation-policies", headers=admin_headers, json={
        "source_device_id": source["id"], "target_device_id": target["id"],
        "target_port": 443, "expected_reachability": "ALLOW",
    })
    assert policy.status_code == 201
    assert client.delete(f"/api/devices/{source['id']}", headers=admin_headers).status_code == 204
    assert client.get("/api/segmentation-policies", headers=admin_headers).json() == []
