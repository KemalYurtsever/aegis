from app.services import snmp_service


def create_device(client, headers):
    return client.post("/api/devices", headers=headers, json={"name": "Lab switch", "ip_address": "198.18.1.2", "device_type": "Switch", "is_active": True}).json()


def test_snmp_configuration_and_successful_poll(client, admin_headers, monkeypatch):
    device = create_device(client, admin_headers)
    monkeypatch.setenv("AEGIS_SNMP_COMMUNITY", "private-secret")
    configured = client.put(f"/api/devices/{device['id']}/snmp", headers=admin_headers, json={"enabled": True, "port": 1161, "community_env": "AEGIS_SNMP_COMMUNITY"})
    assert configured.status_code == 200
    assert configured.json()["secret_configured"] is True

    async def fake_query(host, port, community, timeout=2.0):
        assert (host, port, community) == ("198.18.1.2", 1161, "private-secret")
        return {"system_name": "lab-sw-01", "description": "Test switch", "location": "Lab", "uptime_ticks": 12345, "interface_count": 24}
    monkeypatch.setattr(snmp_service, "query_snmp", fake_query)
    result = client.post(f"/api/devices/{device['id']}/snmp/poll", headers=admin_headers)
    assert result.status_code == 201
    assert result.json()["status"] == "SUCCESS"
    assert result.json()["interface_count"] == 24
    assert len(client.get(f"/api/devices/{device['id']}/snmp/history", headers=admin_headers).json()) == 1


def test_snmp_missing_secret_is_recorded_without_exposing_it(client, admin_headers):
    device = create_device(client, admin_headers)
    result = client.post(f"/api/devices/{device['id']}/snmp/poll", headers=admin_headers).json()
    assert result["status"] == "FAILED"
    assert "AEGIS_SNMP_COMMUNITY" in result["error"]
