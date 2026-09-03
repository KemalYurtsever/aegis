from app.services.discovery_service import LocalNetwork


def test_topology_groups_vlan_gateway_infrastructure_and_endpoints(client, monkeypatch):
    setup = client.post("/api/auth/setup", json={
        "username": "topology-admin",
        "password": "a-secure-test-password",
    }).json()
    client.app.state.auth_required = True
    headers = {"Authorization": f"Bearer {setup['token']}"}
    monkeypatch.setattr(
        "app.routers.topology.get_primary_private_network",
        lambda: LocalNetwork("Wi-Fi", "198.19.4.125", "198.19.4.0/24", "198.19.4.1"),
    )
    devices = [
        ("Building gateway", "198.19.4.1", "Router"),
        ("Floor switch", "198.19.4.2", "Switch"),
        ("Lab workstation", "198.19.4.20", "Workstation"),
    ]
    client.post("/api/inventory/dhcp-leases/import", headers=headers, json={"rows": [
        {"hostname": name, "ip_address": address, "vlan": "LAB-20"}
        for name, address, _device_type in devices
    ]})
    inventory = {device["ip_address"]: device for device in client.get("/api/devices", headers=headers).json()}
    for name, address, device_type in devices:
        created = inventory[address]
        client.put(f"/api/devices/{created['id']}", headers=headers, json={
            "name": name,
            "ip_address": address,
            "device_type": device_type,
            "is_active": True,
        })

    response = client.get("/api/topology", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["interface_name"] == "Wi-Fi"
    assert len(body["groups"]) == 1
    group = body["groups"][0]
    assert group["label"] == "VLAN LAB-20 · 198.19.4.0/24"
    assert group["gateway_ip"] == "198.19.4.1"
    assert [device["role"] for device in group["devices"]] == ["GATEWAY", "INFRASTRUCTURE", "ENDPOINT"]

    source, target = group["devices"][1:]
    created_link = client.post("/api/topology/links", headers=headers, json={
        "source_device_id": source["device_id"],
        "target_device_id": target["device_id"],
        "relationship_type": "UPLINK",
        "description": "  Confirmed lab cable  ",
    })
    assert created_link.status_code == 201
    assert created_link.json()["description"] == "Confirmed lab cable"
    refreshed = client.get("/api/topology", headers=headers).json()
    assert refreshed["links"][0]["source_name"] == "Floor switch"
    assert refreshed["links"][0]["target_name"] == "Lab workstation"
    assert client.delete(
        f"/api/topology/links/{created_link.json()['id']}", headers=headers
    ).status_code == 204

    self_link = client.post("/api/topology/links", headers=headers, json={
        "source_device_id": source["device_id"],
        "target_device_id": source["device_id"],
    })
    assert self_link.status_code == 422
