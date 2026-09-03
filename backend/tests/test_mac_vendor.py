from app.services.mac_vendor_service import lookup_mac_vendor


def test_locally_administered_mac_is_identified_without_external_lookup():
    assert lookup_mac_vendor("02:00:00:00:00:01") == "Locally administered / randomized"


def test_invalid_mac_has_no_vendor():
    assert lookup_mac_vendor("not-a-mac") is None
