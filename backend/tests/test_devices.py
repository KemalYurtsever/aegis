DEVICE = {
    "name": " Ubuntu Server ",
    "ip_address": "192.168.56.20",
    "device_type": "Server",
    "description": " Isolated test VM ",
    "is_active": True,
}


def create_device(client, headers=None, **overrides):
    payload = DEVICE | overrides
    return client.post("/api/devices", headers=headers, json=payload)


def test_device_crud(client):
    created = create_device(client)
    assert created.status_code == 201
    body = created.json()
    assert body["name"] == "Ubuntu Server"
    assert body["description"] == "Isolated test VM"
    assert body["ip_address"] == "192.168.56.20"

    listed = client.get("/api/devices")
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    device_id = body["id"]
    retrieved = client.get(f"/api/devices/{device_id}")
    assert retrieved.status_code == 200

    updated_payload = DEVICE | {"name": "Linux Lab Server", "is_active": False}
    updated = client.put(f"/api/devices/{device_id}", json=updated_payload)
    assert updated.status_code == 200
    assert updated.json()["name"] == "Linux Lab Server"
    assert updated.json()["is_active"] is False

    deleted = client.delete(f"/api/devices/{device_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/devices/{device_id}").status_code == 404


def test_admin_can_clear_all_devices_and_attachment_files(client, admin_headers, tmp_path, monkeypatch):
    import base64
    from types import SimpleNamespace

    monkeypatch.setattr(
        "app.routers.devices.get_settings",
        lambda: SimpleNamespace(attachment_directory=str(tmp_path / "attachments")),
    )
    first = create_device(client, ip_address="192.168.56.20", name="First", headers=admin_headers)
    second = create_device(client, ip_address="192.168.56.21", name="Second", headers=admin_headers)
    assert first.status_code == 201
    assert second.status_code == 201
    first_id = first.json()["id"]
    assert client.post(
        f"/api/devices/{first_id}/notes",
        headers=admin_headers,
        json={"body": "Disposable lab note"},
    ).status_code == 201
    attachment = client.post(
        f"/api/devices/{first_id}/attachments",
        headers=admin_headers,
        json={
            "original_name": "lab.txt",
            "media_type": "text/plain",
            "content_base64": base64.b64encode(b"temporary evidence").decode(),
        },
    )
    assert attachment.status_code == 201
    stored_file = next((tmp_path / "attachments").iterdir())

    rejected = client.post(
        "/api/devices/actions/clear-all",
        headers=admin_headers,
        json={"confirmation": "clear"},
    )
    assert rejected.status_code == 400
    assert len(client.get("/api/devices", headers=admin_headers).json()) == 2

    cleared = client.post(
        "/api/devices/actions/clear-all",
        headers=admin_headers,
        json={"confirmation": "CLEAR ALL DEVICES"},
    )

    assert cleared.status_code == 200
    assert cleared.json() == {"deleted_devices": 2, "deleted_attachments": 1}
    assert client.get("/api/devices", headers=admin_headers).json() == []
    assert not stored_file.exists()


def test_clear_all_devices_requires_admin(client, admin_headers):
    created = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={
            "username": "operator",
            "password": "operator-correct-horse-battery-staple",
            "role": "OPERATOR",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator-correct-horse-battery-staple"},
    )
    operator_headers = {"Authorization": f"Bearer {login.json()['token']}"}

    response = client.post(
        "/api/devices/actions/clear-all",
        headers=operator_headers,
        json={"confirmation": "CLEAR ALL DEVICES"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Administrator role required"


def test_rejects_invalid_ip(client):
    response = create_device(client, ip_address="999.1.2.3")

    assert response.status_code == 422
    assert client.get("/api/devices").json() == []


def test_rejects_duplicate_ip(client):
    assert create_device(client).status_code == 201
    duplicate = create_device(client, name="Duplicate")

    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "A device with this IP address already exists"


def test_normalizes_ipv6_address(client):
    response = create_device(client, ip_address="2001:0db8:0000:0000:0000:0000:0000:0001")

    assert response.status_code == 201
    assert response.json()["ip_address"] == "2001:db8::1"


def test_unknown_device_returns_404(client):
    response = client.get("/api/devices/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Device not found"


def test_device_notes_are_normalized_listed_and_deleted(client):
    device = create_device(client).json()
    created = client.post(
        f"/api/devices/{device['id']}/notes",
        json={"body": "  Replaced the lab cable.  "},
    )
    assert created.status_code == 201
    note = created.json()
    assert note["body"] == "Replaced the lab cable."
    assert note["author"] == "local-user"

    listed = client.get(f"/api/devices/{device['id']}/notes")
    assert [item["id"] for item in listed.json()] == [note["id"]]

    deleted = client.delete(f"/api/devices/{device['id']}/notes/{note['id']}")
    assert deleted.status_code == 204
    assert client.get(f"/api/devices/{device['id']}/notes").json() == []


def test_device_attachments_are_validated_stored_and_listed(client, tmp_path, monkeypatch):
    import base64
    from types import SimpleNamespace

    monkeypatch.setattr(
        "app.routers.devices.get_settings",
        lambda: SimpleNamespace(attachment_directory=str(tmp_path / "attachments")),
    )
    device = create_device(client).json()
    content = b"technician evidence\n"
    created = client.post(f"/api/devices/{device['id']}/attachments", json={
        "original_name": "../lab-note.txt",
        "media_type": "text/plain",
        "content_base64": base64.b64encode(content).decode(),
    })
    assert created.status_code == 201
    attachment = created.json()
    assert attachment["original_name"] == "_lab-note.txt"
    assert attachment["size_bytes"] == len(content)
    stored = list((tmp_path / "attachments").iterdir())
    assert len(stored) == 1
    assert stored[0].suffix == ".blob"

    activity = client.get(f"/api/devices/{device['id']}/activity").json()
    assert any(item["category"] == "ATTACHMENT" for item in activity)
    downloaded = client.get(
        f"/api/devices/{device['id']}/attachments/{attachment['id']}/download"
    )
    assert downloaded.status_code == 200
    assert downloaded.content == content
    assert downloaded.headers["content-type"] == "application/octet-stream"

    fake_png = client.post(f"/api/devices/{device['id']}/attachments", json={
        "original_name": "fake.png",
        "media_type": "image/png",
        "content_base64": base64.b64encode(b"not a png").decode(),
    })
    assert fake_png.status_code == 422

    deleted = client.delete(
        f"/api/devices/{device['id']}/attachments/{attachment['id']}"
    )
    assert deleted.status_code == 204
    assert not stored[0].exists()


def test_attachment_route_accepts_documented_size_above_global_body_limit(client, tmp_path, monkeypatch):
    import base64
    from types import SimpleNamespace

    monkeypatch.setattr(
        "app.routers.devices.get_settings",
        lambda: SimpleNamespace(attachment_directory=str(tmp_path / "attachments")),
    )
    device = create_device(client).json()
    content = b"a" * 1_100_000

    response = client.post(f"/api/devices/{device['id']}/attachments", json={
        "original_name": "large-lab-note.txt",
        "media_type": "text/plain",
        "content_base64": base64.b64encode(content).decode(),
    })

    assert response.status_code == 201
    assert response.json()["size_bytes"] == len(content)


def test_asset_metadata_is_normalized_and_validated(client):
    response = create_device(
        client,
        asset_tag="  LAB-0042  ",
        owner="  Infrastructure Team ",
        location="  Server Room A ",
        operating_system="  Windows Server 2025 ",
        criticality="HIGH",
        maintenance_reason="  Planned firmware update ",
    )
    assert response.status_code == 201
    device = response.json()
    assert device["asset_tag"] == "LAB-0042"
    assert device["owner"] == "Infrastructure Team"
    assert device["location"] == "Server Room A"
    assert device["operating_system"] == "Windows Server 2025"
    assert device["criticality"] == "HIGH"
    assert device["maintenance_reason"] == "Planned firmware update"

    invalid = create_device(client, ip_address="192.168.56.21", criticality="URGENT")
    assert invalid.status_code == 422


def test_device_tags_are_normalized_and_persisted(client):
    response = create_device(
        client,
        tags=[" Production ", "edge", "production", "Finance Lab"],
    )
    assert response.status_code == 201
    device = response.json()
    assert device["tags"] == ["production", "edge", "finance lab"]

    updated = client.put(
        f"/api/devices/{device['id']}",
        json=DEVICE | {"tags": ["core/network"]},
    )
    assert updated.status_code == 200
    assert updated.json()["tags"] == ["core/network"]

    invalid = create_device(client, ip_address="192.168.56.21", tags=["not@valid"])
    assert invalid.status_code == 422


def test_device_persists_across_database_reconnection(tmp_path):
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from app.database import Base, create_database_engine
    from app.models import Device

    database_url = f"sqlite:///{tmp_path / 'persistent.db'}"
    first_engine = create_database_engine(database_url)
    Base.metadata.create_all(first_engine)
    first_session_factory = sessionmaker(bind=first_engine, expire_on_commit=False)

    with first_session_factory() as session:
        session.add(Device(name="Persistent Device", ip_address="192.168.56.50", device_type="Server"))
        session.commit()
    first_engine.dispose()

    restarted_engine = create_database_engine(database_url)
    restarted_session_factory = sessionmaker(bind=restarted_engine, expire_on_commit=False)
    with restarted_session_factory() as session:
        restored = session.scalar(select(Device).where(Device.ip_address == "192.168.56.50"))
        assert restored is not None
        assert restored.name == "Persistent Device"
    restarted_engine.dispose()
