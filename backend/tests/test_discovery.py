import ipaddress
import threading
import pytest

from app.services.discovery_service import LocalNetwork, arp_scan_options, discovery_address_allowed, discover_responsive_hosts, select_windows_lan_candidate
from app.services.ping_service import PingResult


NETWORK = LocalNetwork(
    interface_name="Wi-Fi", local_ip="198.18.1.20", network="198.18.1.0/24", gateway="198.18.1.1"
)


def test_discovery_imports_new_devices_and_skips_existing(client, admin_headers, monkeypatch):
    client.post(
        "/api/devices",
        headers=admin_headers,
        json={"name": "Router", "ip_address": "198.18.1.1", "device_type": "Router", "description": None, "is_active": True},
    )
    monkeypatch.setattr("app.services.discovery_service.get_primary_private_network", lambda: NETWORK)
    monkeypatch.setattr(
        "app.services.discovery_service.discover_responsive_hosts",
        lambda _network: [("198.18.1.1", "AA:BB:CC:DD:EE:01"), ("198.18.1.50", "AA:BB:CC:DD:EE:50")],
    )
    monkeypatch.setattr("app.services.discovery_service.resolve_hostnames", lambda _addresses: {"198.18.1.50": "printer.office"})
    monkeypatch.setattr("app.services.mdns_service.discover_mdns", lambda _network: {})

    response = client.post("/api/discovery/import", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["addresses_scanned"] == 254
    assert body["responsive_devices"] == 2
    assert body["devices_added"] == 1
    assert body["devices_skipped"] == 1
    assert body["added_devices"][0]["ip_address"] == "198.18.1.50"
    assert body["added_devices"][0]["name"] == "printer.office"
    assert body["added_devices"][0]["mac_address"] == "AA:BB:CC:DD:EE:50"
    assert "MAC address: AA:BB:CC:DD:EE:50" in body["added_devices"][0]["description"]


def test_discovery_network_errors_are_safe(client, monkeypatch):
    def fail():
        raise RuntimeError("No private network found")

    monkeypatch.setattr("app.routers.discovery.get_primary_private_network", fail)
    response = client.get("/api/discovery/network")
    assert response.status_code == 400
    assert response.json()["detail"] == "No private network found"


def test_windows_candidate_selection_skips_vpn_and_virtual_adapters():
    candidates = [
        {"InterfaceAlias": "Mullvad", "InterfaceDescription": "Mullvad Tunnel", "IPAddress": "198.19.68.42", "PrefixLength": 32},
        {"InterfaceAlias": "vEthernet", "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter", "IPAddress": "198.19.224.1", "PrefixLength": 20},
        {"InterfaceAlias": "WiFi", "InterfaceDescription": "Intel Wi-Fi", "IPAddress": "198.18.1.20", "PrefixLength": 24},
    ]

    selected = select_windows_lan_candidate(candidates)

    assert selected["InterfaceAlias"] == "WiFi"


def test_windows_candidate_selection_rejects_tunnel_only_configuration():
    with pytest.raises(RuntimeError, match="No suitable physical LAN adapter"):
        select_windows_lan_candidate(
            {"InterfaceAlias": "VPN", "InterfaceDescription": "WireGuard Tunnel", "IPAddress": "198.19.0.2", "PrefixLength": 32}
        )


def test_public_lan_discovery_requires_explicit_opt_in():
    public_address = ipaddress.ip_address("8.8.8.8")
    assert discovery_address_allowed(public_address, allow_public_lan=False) is False
    assert discovery_address_allowed(public_address, allow_public_lan=True) is True
    assert discovery_address_allowed(ipaddress.ip_address("198.18.1.20"), allow_public_lan=False) is True


def test_discovery_merges_arp_hosts_that_block_ping(monkeypatch):
    monkeypatch.setattr(
        "app.services.discovery_service.check_ip",
        lambda address, **_kwargs: PingResult("ONLINE", 1.0) if address == "198.18.1.20" else PingResult("OFFLINE", None),
    )
    monkeypatch.setattr("app.services.discovery_service.read_windows_arp_table", lambda: {})
    monkeypatch.setattr(
        "app.services.discovery_service.active_arp_discovery",
        lambda _network: {"198.18.1.50": "AA:BB:CC:DD:EE:50"},
    )

    hosts = discover_responsive_hosts(NETWORK)

    assert ("198.18.1.20", None) in hosts
    assert ("198.18.1.50", "AA:BB:CC:DD:EE:50") in hosts


def test_arp_discovery_is_rate_limited():
    options = arp_scan_options(10)
    assert options["inter"] == 0.1
    assert options["retry"] == 0
    assert options["timeout"] == 2


def test_ping_and_arp_discovery_run_concurrently(monkeypatch):
    network = LocalNetwork("Wi-Fi", "198.18.1.1", "198.18.1.0/30", "198.18.1.1")
    ping_started = threading.Event()
    arp_started = threading.Event()

    def fake_check_ip(_address, **_kwargs):
        ping_started.set()
        assert arp_started.wait(1.0)
        return PingResult("OFFLINE", None)

    def fake_arp(_network):
        arp_started.set()
        assert ping_started.wait(1.0)
        return {}

    monkeypatch.setattr("app.services.discovery_service.check_ip", fake_check_ip)
    monkeypatch.setattr("app.services.discovery_service.active_arp_discovery", fake_arp)
    monkeypatch.setattr("app.services.discovery_service.read_windows_arp_table", lambda: {})

    assert discover_responsive_hosts(network) == []
