def component_map(payload):
    return {item["name"]: item for item in payload["components"]}


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "status-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_system_readiness_reports_core_components(client):
    response = client.get("/api/system/readiness", headers=admin_headers(client))

    assert response.status_code == 200
    payload = response.json()
    components = component_map(payload)
    assert payload["status"] == "HEALTHY"
    assert components["Database"]["status"] == "HEALTHY"
    assert "Connection ready" in components["Database"]["message"]
    assert "foreign-key enforcement enabled" in components["Database"]["message"]
    assert "Deep integrity is checked" in components["Database"]["message"]
    assert components["Monitoring scheduler"]["status"] == "DISABLED"
    assert components["Backup scheduler"]["status"] == "DISABLED"
    assert components["Storage"]["status"] == "HEALTHY"


def test_system_readiness_warns_when_enabled_scheduler_is_stopped(client):
    headers = admin_headers(client)
    client.app.state.monitor_scheduler.enabled = True

    response = client.get("/api/system/readiness", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "WARNING"
    assert component_map(payload)["Monitoring scheduler"] == {
        "name": "Monitoring scheduler",
        "status": "WARNING",
        "message": "Enabled but not running.",
    }


def test_system_readiness_is_admin_only(client):
    headers = admin_headers(client)
    created = client.post(
        "/api/auth/users",
        headers=headers,
        json={
            "username": "status-viewer",
            "password": "viewer-password-is-long",
            "role": "VIEWER",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "status-viewer", "password": "viewer-password-is-long"},
    )

    response = client.get(
        "/api/system/readiness",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )

    assert response.status_code == 403
