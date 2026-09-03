def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "inventory-admin", "password": "a-secure-test-password"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_dhcp_import_adds_and_updates_by_mac_without_overwriting_manual_name(client):
    headers = admin_headers(client)
    created = client.post(
        "/api/inventory/dhcp-leases/import",
        headers=headers,
        json={
            "rows": [{
                "hostname": "lab-printer",
                "ip_address": "198.18.50.20",
                "mac_address": "00-11-22-33-44-55",
                "vlan": "20",
                "lease_expires_at": "2026-08-16T12:00:00Z",
            }]
        },
    )
    assert created.status_code == 200
    assert created.json() == {
        "rows_received": 1,
        "devices_added": 1,
        "devices_updated": 0,
        "rows_skipped": 0,
        "conflicts": [],
    }
    device = client.get("/api/devices", headers=headers).json()[0]
    assert device["name"] == "lab-printer"
    assert device["mac_address"] == "00:11:22:33:44:55"
    assert device["inventory_source"] == "DHCP_IMPORT"
    assert device["vlan"] == "20"

    renamed = client.put(
        f"/api/devices/{device['id']}",
        headers=headers,
        json={
            "name": "Reception Printer",
            "ip_address": device["ip_address"],
            "device_type": "Printer",
            "description": "Manually named",
            "is_active": True,
        },
    )
    assert renamed.status_code == 200

    updated = client.post(
        "/api/inventory/dhcp-leases/import",
        headers=headers,
        json={
            "rows": [{
                "hostname": "printer-from-dhcp",
                "ip_address": "198.18.50.21",
                "mac_address": "0011.2233.4455",
                "vlan": "30",
            }]
        },
    )
    assert updated.status_code == 200
    assert updated.json()["devices_updated"] == 1
    devices = client.get("/api/devices", headers=headers).json()
    assert len(devices) == 1
    assert devices[0]["name"] == "Reception Printer"
    assert devices[0]["ip_address"] == "198.18.50.21"
    assert devices[0]["vlan"] == "30"


def test_dhcp_import_reports_mac_and_ip_ownership_conflict(client):
    headers = admin_headers(client)
    first = client.post(
        "/api/inventory/dhcp-leases/import",
        headers=headers,
        json={"rows": [
            {"ip_address": "198.19.10.10", "mac_address": "00:11:22:33:44:55"},
            {"ip_address": "198.19.10.11", "mac_address": "00:11:22:33:44:66"},
        ]},
    )
    assert first.status_code == 200

    conflict = client.post(
        "/api/inventory/dhcp-leases/import",
        headers=headers,
        json={"rows": [{"ip_address": "198.19.10.11", "mac_address": "00:11:22:33:44:55"}]},
    )
    assert conflict.status_code == 200
    result = conflict.json()
    assert result["rows_skipped"] == 1
    assert result["devices_updated"] == 0
    assert len(result["conflicts"]) == 1


def test_dhcp_import_validates_addresses_and_requires_admin(client):
    bad = client.post(
        "/api/inventory/dhcp-leases/import",
        json={"rows": [{"ip_address": "not-an-ip", "mac_address": "not-a-mac"}]},
    )
    assert bad.status_code == 403

    headers = admin_headers(client)
    bad = client.post(
        "/api/inventory/dhcp-leases/import",
        headers=headers,
        json={"rows": [{"ip_address": "not-an-ip", "mac_address": "not-a-mac"}]},
    )
    assert bad.status_code == 422


def test_inventory_health_finds_lease_monitoring_and_duplicate_mac_issues(client):
    headers = admin_headers(client)
    now = datetime.now(timezone.utc)
    with client.app.state.session_factory() as db:
        expired = Device(
            name="Expired lease", ip_address="198.18.80.10", mac_address="00:11:22:33:44:55",
            device_type="Other", is_active=True, lease_expires_at=now - timedelta(hours=1),
        )
        expiring = Device(
            name="Expiring lease", ip_address="198.18.80.11", mac_address="00:11:22:33:44:55",
            device_type="Other", is_active=True, lease_expires_at=now + timedelta(hours=2),
        )
        db.add_all([expired, expiring]); db.flush()
        db.add(MonitorResult(
            device_id=expired.id,
            timestamp=now - timedelta(hours=48),
            status="ONLINE",
            latency_ms=1,
        ))
        db.commit()

    response = client.get("/api/inventory/health?stale_hours=24", headers=headers)
    assert response.status_code == 200
    health = response.json()
    assert health["expired_leases"] == 1
    assert health["expiring_leases"] == 1
    assert health["never_checked"] == 1
    assert health["stale_checks"] == 1
    assert health["duplicate_mac_records"] == 2
    assert health["total_issues"] == 6
from datetime import datetime, timedelta, timezone

from app.models import Device, MonitorResult

