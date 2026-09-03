import socket
from types import SimpleNamespace

from app.schemas import TraceRouteHop, TraceRouteRead
from app.services.security_toolbox_service import host_network_policy, parse_traceroute, query_dns, wireless_adapters


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "toolbox-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_parse_traceroute_handles_responses_and_timeouts():
    output = """
      1    <1 ms    <1 ms     1 ms  198.18.1.1
      2     *        *        *     Request timed out.
      3    12 ms    11 ms    12 ms  198.19.30.40
    """

    hops = parse_traceroute(output)

    assert [(hop.hop, hop.address, hop.latency_ms, hop.timed_out) for hop in hops] == [
        (1, "198.18.1.1", 1.0, False),
        (2, None, None, True),
        (3, "198.19.30.40", 11.0, False),
    ]


def test_dns_query_validates_input_and_returns_structured_addresses(monkeypatch):
    monkeypatch.setattr(
        "app.services.security_toolbox_service.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
        ],
    )
    monkeypatch.setattr(
        "app.services.security_toolbox_service.socket.getfqdn",
        lambda _query: "host.lab.example",
    )

    result = query_dns("host.lab.example")

    assert result.addresses == ["192.0.2.10"]
    assert result.canonical_name is None


def test_wireless_inventory_omits_mac_and_link_local_addresses(monkeypatch):
    address = SimpleNamespace(family=socket.AF_INET, address="198.18.5.20")
    link_local = SimpleNamespace(family=socket.AF_INET6, address="fe80::1%12")
    monkeypatch.setattr(
        "app.services.security_toolbox_service.psutil.net_if_addrs",
        lambda: {"Wi-Fi": [address, link_local], "Ethernet": [address]},
    )
    monkeypatch.setattr(
        "app.services.security_toolbox_service.psutil.net_if_stats",
        lambda: {"Wi-Fi": SimpleNamespace(isup=True, speed=866)},
    )
    monkeypatch.setattr(
        "app.services.security_toolbox_service.get_primary_private_network",
        lambda: SimpleNamespace(interface_name="Wi-Fi"),
    )

    adapters = wireless_adapters()

    assert len(adapters) == 1
    assert adapters[0].name == "Wi-Fi"
    assert adapters[0].addresses == ["198.18.5.20"]
    assert adapters[0].active_for_discovery is True


def test_windows_host_network_policy_returns_structured_firewall_and_routes(monkeypatch):
    monkeypatch.setattr("app.services.security_toolbox_service.platform.system", lambda: "Windows")

    def powershell_result(script):
        if "Get-NetFirewallProfile" in script:
            return [{"Name": "Private", "Enabled": True, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}]
        if "Get-NetFirewallRule" in script:
            return [{"DisplayName": "Allow LIIMS", "Direction": "Inbound", "Action": "Allow", "Profile": "Private"}]
        return [
            {"DestinationPrefix": "0.0.0.0/0", "NextHop": "198.18.1.1", "InterfaceAlias": "Wi-Fi", "RouteMetric": 25},
            {"DestinationPrefix": "198.18.1.0/24", "NextHop": "0.0.0.0", "InterfaceAlias": "Wi-Fi", "RouteMetric": 281},
        ]

    monkeypatch.setattr("app.services.security_toolbox_service._run_powershell_json", powershell_result)

    result = host_network_policy()

    assert result.firewall_profiles[0].default_inbound_action == "Block"
    assert result.firewall_rules[0].name == "Allow LIIMS"
    assert result.routes[0].is_default is True
    assert result.routes[1].next_hop is None


def test_traceroute_endpoint_uses_registered_device_only(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post(
        "/api/devices",
        headers=headers,
        json={
            "name": "Lab router",
            "ip_address": "198.18.5.1",
            "device_type": "Router",
            "is_active": True,
        },
    ).json()
    monkeypatch.setattr(
        "app.routers.security.trace_registered_device",
        lambda item: TraceRouteRead(
            device_id=item.id,
            device_name=item.name,
            target=item.ip_address,
            completed=True,
            hops=[TraceRouteHop(hop=1, address=item.ip_address, latency_ms=1.0, timed_out=False)],
        ),
    )

    response = client.post(
        "/api/security/toolbox/traceroute",
        headers=headers,
        json={"device_id": device["id"]},
    )
    missing = client.post(
        "/api/security/toolbox/traceroute",
        headers=headers,
        json={"device_id": 99999},
    )

    assert response.status_code == 200
    assert response.json()["hops"][0]["address"] == "198.18.5.1"
    assert missing.status_code == 404


def test_toolbox_is_admin_only(client):
    headers = admin_headers(client)
    created = client.post(
        "/api/auth/users",
        headers=headers,
        json={
            "username": "toolbox-operator",
            "password": "operator-password-is-long",
            "role": "OPERATOR",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "toolbox-operator", "password": "operator-password-is-long"},
    )
    operator_headers = {"Authorization": f"Bearer {login.json()['token']}"}

    response = client.get("/api/security/toolbox/wireless", headers=operator_headers)

    assert response.status_code == 403
