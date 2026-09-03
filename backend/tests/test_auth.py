def setup(client, username="admin", password="correct-horse-battery-staple"):
    return client.post("/api/auth/setup", json={"username": username, "password": password})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_first_run_setup_login_logout_and_protection(client):
    assert client.get("/api/auth/status").json()["setup_required"] is True
    created = setup(client)
    assert created.status_code == 201
    token = created.json()["token"]
    assert created.json()["user"]["role"] == "ADMIN"
    assert client.post("/api/auth/setup", json={"username": "second", "password": "another-long-password"}).status_code == 409

    client.app.state.auth_required = True
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/dashboard", headers=auth(token)).status_code == 200
    assert client.post("/api/auth/logout", headers=auth(token)).status_code == 204
    assert client.get("/api/dashboard", headers=auth(token)).status_code == 401

    logged_in = client.post("/api/auth/login", json={"username": "ADMIN", "password": "correct-horse-battery-staple"})
    assert logged_in.status_code == 200
    assert logged_in.json()["user"]["username"] == "admin"


def test_roles_enforce_admin_management_and_viewer_read_only(client):
    admin_token = setup(client).json()["token"]
    client.app.state.auth_required = True
    viewer = client.post(
        "/api/auth/users",
        headers=auth(admin_token),
        json={"username": "viewer", "password": "viewer-password-123", "role": "VIEWER"},
    )
    assert viewer.status_code == 201
    viewer_login = client.post("/api/auth/login", json={"username": "viewer", "password": "viewer-password-123"}).json()
    viewer_headers = auth(viewer_login["token"])
    assert client.get("/api/devices", headers=viewer_headers).status_code == 200
    assert client.post(
        "/api/devices", headers=viewer_headers,
        json={"name": "Forbidden", "ip_address": "198.18.1.20", "device_type": "Other", "is_active": True},
    ).status_code == 403
    assert client.get("/api/auth/users", headers=viewer_headers).status_code == 403
    last_admin = client.get("/api/auth/users", headers=auth(admin_token)).json()[0]
    protected = client.put(
        f"/api/auth/users/{last_admin['id']}", headers=auth(admin_token),
        json={"role": "VIEWER", "is_active": True, "password": None},
    )
    assert protected.status_code == 409
    assert "last active administrator" in protected.json()["detail"]


def test_operator_can_manage_devices_but_not_users(client):
    admin_token = setup(client).json()["token"]
    client.app.state.auth_required = True
    client.post(
        "/api/auth/users", headers=auth(admin_token),
        json={"username": "operator", "password": "operator-password-123", "role": "OPERATOR"},
    )
    operator_token = client.post(
        "/api/auth/login", json={"username": "operator", "password": "operator-password-123"}
    ).json()["token"]
    operator_headers = auth(operator_token)
    assert client.post(
        "/api/devices", headers=operator_headers,
        json={"name": "Managed", "ip_address": "198.18.1.30", "device_type": "Other", "is_active": True},
    ).status_code == 201
    assert client.get("/api/auth/users", headers=operator_headers).status_code == 403

    audit = client.get("/api/auth/audit-events", headers=auth(admin_token))
    assert audit.status_code == 200
    device_event = next(event for event in audit.json() if event["path"] == "/api/devices")
    assert device_event["username"] == "operator"
    assert device_event["role"] == "OPERATOR"
    assert device_event["method"] == "POST"
    assert device_event["status_code"] == 201
    assert device_event["client_ip"] == "testclient"
    assert "password" not in device_event
    assert client.get("/api/auth/audit-events", headers=operator_headers).status_code == 403
