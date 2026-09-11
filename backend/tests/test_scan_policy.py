from ipaddress import ip_network

from app.services.scan_policy import (
    is_host_in_network,
    mac_target_rejection_reason,
    scan_target_allowed,
    scan_target_rejection_reason,
    unicast_target_rejection_reason,
)


LOCAL_NETWORKS = (ip_network("198.18.10.0/24"),)


def test_unicast_policy_rejects_addresses_that_do_not_identify_one_host():
    assert "unspecified" in unicast_target_rejection_reason("0.0.0.0").lower()
    assert "multicast" in unicast_target_rejection_reason("224.0.0.251").lower()
    assert "broadcast" in unicast_target_rejection_reason("255.255.255.255").lower()
    assert unicast_target_rejection_reason("8.8.8.8") is None
    assert unicast_target_rejection_reason("127.0.0.1") is None


def test_mac_policy_rejects_broadcast_multicast_and_unspecified_addresses():
    assert "broadcast" in mac_target_rejection_reason("FF:FF:FF:FF:FF:FF").lower()
    assert "multicast" in mac_target_rejection_reason("01:00:5E:00:00:FB").lower()
    assert "unspecified" in mac_target_rejection_reason("00:00:00:00:00:00").lower()
    assert mac_target_rejection_reason("02:11:22:33:44:55") is None


def test_scan_policy_rejects_active_subnet_network_and_broadcast_addresses():
    assert "network address" in scan_target_rejection_reason("198.18.10.0", LOCAL_NETWORKS)
    assert "broadcast address" in scan_target_rejection_reason("198.18.10.255", LOCAL_NETWORKS)
    assert scan_target_rejection_reason("198.18.10.20", LOCAL_NETWORKS) is None
    assert scan_target_rejection_reason("8.8.8.8", LOCAL_NETWORKS) is None


def test_host_membership_excludes_ipv4_network_and_broadcast_addresses():
    assert is_host_in_network("198.18.10.20", "198.18.10.0/24") is True
    assert is_host_in_network("198.18.10.0", "198.18.10.0/24") is False
    assert is_host_in_network("198.18.10.255", "198.18.10.0/24") is False
    assert is_host_in_network("198.18.11.20", "198.18.10.0/24") is False
    assert is_host_in_network("198.18.10.0", "198.18.10.0/31") is True
    assert is_host_in_network("malformed", "198.18.10.0/24") is False
    assert is_host_in_network("2001:db8::10", "198.18.10.0/24") is False


def test_boolean_scan_policy_wraps_the_rejection_reason(monkeypatch):
    monkeypatch.setattr(
        "app.services.scan_policy._local_ipv4_networks",
        lambda: LOCAL_NETWORKS,
    )

    assert scan_target_allowed("198.18.10.20") is True
    assert scan_target_allowed("198.18.10.255") is False
    assert scan_target_allowed("8.8.8.8", "FF:FF:FF:FF:FF:FF") is False
