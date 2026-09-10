from app.services.discovery_service import is_generic_ptr_hostname
from app.services.mdns_service import classify_device, mdns_identity, service_instance_name


def test_generic_provider_ptr_is_not_treated_as_device_name():
    assert is_generic_ptr_hostname("172.2.4.14", "172-2-4-14.lightspeed.example.net") is True
    assert is_generic_ptr_hostname("172.2.4.14", "office-printer.local") is False


def test_service_classification_is_conservative():
    assert classify_device(["ipp", "http"]) == "Printer"
    assert classify_device(["smb"]) == "Workstation"
    assert classify_device(["ssh"]) == "Server"
    assert classify_device(["http"]) is None


def test_mdns_identity_extracts_friendly_name_and_model_from_txt_records():
    display_name, model = mdns_identity(
        {b"fn": b"Living Room TV", b"md": b"Chromecast Ultra"},
        "Fallback name",
    )

    assert display_name == "Living Room TV"
    assert model == "Chromecast Ultra"


def test_mdns_identity_uses_instance_name_and_cleans_product_model():
    instance = service_instance_name(
        "Office\\032Printer._ipp._tcp.local.",
        "_ipp._tcp.local.",
    )
    display_name, model = mdns_identity({b"product": b"(LaserJet Pro M404)"}, instance)

    assert display_name == "Office Printer"
    assert model == "LaserJet Pro M404"
