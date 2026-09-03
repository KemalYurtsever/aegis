from app.services.discovery_service import is_generic_ptr_hostname
from app.services.mdns_service import classify_device


def test_generic_provider_ptr_is_not_treated_as_device_name():
    assert is_generic_ptr_hostname("172.2.4.14", "172-2-4-14.lightspeed.example.net") is True
    assert is_generic_ptr_hostname("172.2.4.14", "office-printer.local") is False


def test_service_classification_is_conservative():
    assert classify_device(["ipp", "http"]) == "Printer"
    assert classify_device(["smb"]) == "Workstation"
    assert classify_device(["ssh"]) == "Server"
    assert classify_device(["http"]) is None
