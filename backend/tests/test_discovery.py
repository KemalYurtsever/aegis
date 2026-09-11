import ipaddress
import socket
import threading
from types import SimpleNamespace
import pytest

from app.services.discovery_service import LocalNetwork, discovery_address_allowed, discover_responsive_hosts, read_windows_arp_table, select_windows_lan_candidate, select_windows_route_network
from app.services.ping_service import PingResult


NETWORK = LocalNetwork(
    interface_name="Wi-Fi", local_ip="192.168.1.20", network="192.168.1.0/24", gateway="192.168.1.1"
)


def test_discovery_imports_new_devices_and_skips_existing(client, admin_headers, monkeypatch):
    client.post(
        "/api/devices",
        headers=admin_headers,
        json={"name": "Router", "ip_address": "192.168.1.1", "device_type": "Router", "description": None, "is_active": True},
    )
    monkeypatch.setattr("app.services.discovery_service.get_primary_private_network", lambda: NETWORK)
    monkeypatch.setattr(
        "app.services.discovery_service.discover_responsive_hosts",
        lambda _network: [("192.168.1.1", "AA:BB:CC:DD:EE:01"), ("192.168.1.50", "AA:BB:CC:DD:EE:50")],
    )
    resolved_addresses = []

    def resolve_new_hosts(addresses):
        resolved_addresses.extend(addresses)
        return {"192.168.1.50": "printer.office"}

    monkeypatch.setattr("app.services.discovery_service.resolve_hostnames", resolve_new_hosts)
    monkeypatch.setattr("app.services.mdns_service.discover_mdns", lambda *_args: {})

    response = client.post("/api/discovery/import", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["addresses_scanned"] == 254
    assert body["responsive_devices"] == 2
    assert body["devices_added"] == 1
    assert body["devices_skipped"] == 1
    assert body["added_devices"][0]["ip_address"] == "192.168.1.50"
    assert body["added_devices"][0]["name"] == "printer.office"
    assert body["added_devices"][0]["mac_address"] == "AA:BB:CC:DD:EE:50"
    assert "MAC address: AA:BB:CC:DD:EE:50" in body["added_devices"][0]["description"]
    assert resolved_addresses == ["192.168.1.50"]


def test_discovery_persists_mdns_friendly_name_model_and_services(client, admin_headers, monkeypatch):
    monkeypatch.setattr("app.services.discovery_service.get_primary_private_network", lambda: NETWORK)
    monkeypatch.setattr(
        "app.services.discovery_service.discover_responsive_hosts",
        lambda _network: [("192.168.1.60", "AA:BB:CC:DD:EE:60")],
    )
    monkeypatch.setattr("app.services.discovery_service.resolve_hostnames", lambda _addresses: {})
    monkeypatch.setattr(
        "app.services.mdns_service.discover_mdns",
        lambda *_args: {
            "192.168.1.60": {
                "hostname": "cast-device.local",
                "display_name": "Living Room TV",
                "model": "Chromecast Ultra",
                "services": ["googlecast", "http"],
            }
        },
    )

    response = client.post("/api/discovery/import", headers=admin_headers)

    assert response.status_code == 200
    device = response.json()["added_devices"][0]
    assert device["name"] == "Living Room TV"
    assert device["discovered_model"] == "Chromecast Ultra"
    assert device["discovered_services"] == "googlecast,http"


def test_discovery_does_not_import_subnet_network_or_broadcast_addresses(client, admin_headers, monkeypatch):
    monkeypatch.setattr("app.services.discovery_service.get_primary_private_network", lambda: NETWORK)
    monkeypatch.setattr(
        "app.services.discovery_service.discover_responsive_hosts",
        lambda _network: [
            ("192.168.1.0", None),
            ("192.168.1.50", "AA:BB:CC:DD:EE:50"),
            ("192.168.1.255", None),
        ],
    )
    monkeypatch.setattr("app.services.discovery_service.resolve_hostnames", lambda _addresses: {})
    monkeypatch.setattr(
        "app.services.mdns_service.discover_mdns",
        lambda *_args: {
            "192.168.1.0": {"services": ["http"]},
            "192.168.1.60": {"services": ["googlecast"]},
            "192.168.1.255": {"services": ["http"]},
        },
    )

    response = client.post("/api/discovery/import", headers=admin_headers)

    assert response.status_code == 200
    addresses = {device["ip_address"] for device in response.json()["added_devices"]}
    assert addresses == {"192.168.1.50", "192.168.1.60"}


def test_arp_table_ignores_broadcast_and_multicast_mac_addresses(monkeypatch):
    monkeypatch.setattr(
        "app.services.discovery_service.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                "  192.168.1.20    02-11-22-33-44-55    dynamic\n"
                "  192.168.1.255   ff-ff-ff-ff-ff-ff    static\n"
                "  224.0.0.251     01-00-5e-00-00-fb    static\n"
            ),
        ),
    )

    assert read_windows_arp_table() == {
        "192.168.1.20": "02:11:22:33:44:55",
    }


def test_discovery_network_errors_are_safe(client, monkeypatch):
    def fail():
        raise RuntimeError("No private network found")

    monkeypatch.setattr("app.routers.discovery.get_primary_private_network", fail)
    response = client.get("/api/discovery/network")
    assert response.status_code == 400
    assert response.json()["detail"] == "No private network found"


def test_windows_candidate_selection_skips_vpn_and_virtual_adapters():
    candidates = [
        {"InterfaceAlias": "Mullvad", "InterfaceDescription": "Mullvad Tunnel", "IPAddress": "10.165.68.42", "PrefixLength": 32},
        {"InterfaceAlias": "vEthernet", "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter", "IPAddress": "172.28.224.1", "PrefixLength": 20},
        {"InterfaceAlias": "WiFi", "InterfaceDescription": "Intel Wi-Fi", "IPAddress": "192.168.1.20", "PrefixLength": 24},
    ]

    selected = select_windows_lan_candidate(candidates)

    assert selected["InterfaceAlias"] == "WiFi"


def test_windows_candidate_selection_rejects_tunnel_only_configuration():
    with pytest.raises(RuntimeError, match="No suitable physical LAN adapter"):
        select_windows_lan_candidate(
            {"InterfaceAlias": "VPN", "InterfaceDescription": "WireGuard Tunnel", "IPAddress": "10.0.0.2", "PrefixLength": 32}
        )


def test_public_lan_discovery_requires_explicit_opt_in():
    public_address = ipaddress.ip_address("172.2.4.35")
    assert discovery_address_allowed(public_address, allow_public_lan=False) is False
    assert discovery_address_allowed(public_address, allow_public_lan=True) is True
    assert discovery_address_allowed(ipaddress.ip_address("192.168.1.20"), allow_public_lan=False) is True


def test_route_table_selects_fast_physical_windows_network():
    route_output = """
              0.0.0.0          0.0.0.0       10.0.0.1       10.0.0.2      5
              0.0.0.0          0.0.0.0    192.168.1.1   192.168.1.20     35
    """
    addresses = {
        "WireGuard VPN": [SimpleNamespace(family=socket.AF_INET, address="10.0.0.2", netmask="255.255.255.255")],
        "WiFi": [SimpleNamespace(family=socket.AF_INET, address="192.168.1.20", netmask="255.255.255.0")],
    }
    stats = {
        "WireGuard VPN": SimpleNamespace(isup=True),
        "WiFi": SimpleNamespace(isup=True),
    }

    network = select_windows_route_network(route_output, addresses, stats, False)

    assert network == LocalNetwork("WiFi", "192.168.1.20", "192.168.1.0/24", "192.168.1.1")


def test_discovery_merges_arp_hosts_that_block_ping(monkeypatch):
    monkeypatch.setattr(
        "app.services.discovery_service.check_ip",
        lambda address, **_kwargs: PingResult("ONLINE", 1.0) if address == "192.168.1.20" else PingResult("OFFLINE", None),
    )
    monkeypatch.setattr(
        "app.services.discovery_service.read_windows_arp_table",
        lambda: {"192.168.1.50": "AA:BB:CC:DD:EE:50"},
    )

    hosts = discover_responsive_hosts(NETWORK)

    assert ("192.168.1.20", None) in hosts
    assert ("192.168.1.50", "AA:BB:CC:DD:EE:50") in hosts


def test_discovery_reads_neighbor_cache_after_ping_sweep(monkeypatch):
    network = LocalNetwork("Wi-Fi", "192.168.1.1", "192.168.1.0/30", "192.168.1.1")
    probes_complete = threading.Event()
    lock = threading.Lock()
    completed = 0

    def fake_check_ip(_address, **_kwargs):
        nonlocal completed
        with lock:
            completed += 1
            if completed == 2:
                probes_complete.set()
        return PingResult("OFFLINE", None)

    def fake_neighbors():
        assert probes_complete.is_set()
        return {}

    monkeypatch.setattr("app.services.discovery_service.check_ip", fake_check_ip)
    monkeypatch.setattr("app.services.discovery_service.read_windows_arp_table", fake_neighbors)

    assert discover_responsive_hosts(network) == []
