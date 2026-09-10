from types import SimpleNamespace

from app.services.nmap_top_ports import NMAP_TOP_1000_TCP_PORTS
from app.services.port_scan_service import (
    OpenPort,
    parse_nmap_port_scan,
    parse_nmap_service_scan,
    scan_nmap_top_tcp_ports,
    scan_nmap_service_versions,
)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="connect" protocol="tcp" numservices="5" services="1-3,5,80" />
  <host>
    <ports>
      <port protocol="tcp" portid="22"><state state="closed" /><service name="ssh" /></port>
      <port protocol="tcp" portid="80"><state state="open" /><service name="http" /></port>
    </ports>
  </host>
</nmaprun>
"""

SERVICE_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="80">
    <state state="open" />
    <service name="http" product="Apache httpd" version="2.4.58" extrainfo="Ubuntu">
      <cpe>cpe:/a:apache:http_server:2.4.58</cpe>
    </service>
  </port>
</ports></host></nmaprun>
"""


def test_parse_nmap_port_scan_expands_ports_and_keeps_only_open_results():
    scanned, open_ports = parse_nmap_port_scan(NMAP_XML)

    assert scanned == [1, 2, 3, 5, 80]
    assert [(item.port, item.service) for item in open_ports] == [(80, "http")]


def test_nmap_top_1000_scan_uses_docker_compatible_connect_scan(monkeypatch):
    captured = {}
    xml = NMAP_XML.replace(
        'numservices="5" services="1-3,5,80"',
        'numservices="1000" services="1-1000"',
    )

    def fake_run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        return SimpleNamespace(returncode=0, stdout=xml, stderr="")

    monkeypatch.setattr(
        "app.services.port_scan_service.nmap_command_prefix",
        lambda: ["docker", "exec", "aegis-network-tools", "nmap"],
    )
    monkeypatch.setattr("app.services.port_scan_service.subprocess.run", fake_run)

    result = scan_nmap_top_tcp_ports("192.168.1.10")

    assert result.scanner == "Nmap top ports"
    assert len(result.scanned_ports) == 1000
    assert [item.port for item in result.open_ports] == [80]
    assert captured["command"][:4] == ["docker", "exec", "aegis-network-tools", "nmap"]
    assert "-Pn" in captured["command"]
    assert "-sT" in captured["command"]
    assert captured["command"][captured["command"].index("--top-ports") + 1] == "1000"
    assert captured["kwargs"]["timeout"] == 20
    assert captured["command"][captured["command"].index("--min-rate") + 1] == "500"
    assert captured["command"][captured["command"].index("--max-retries") + 1] == "0"


def test_local_fallback_scans_the_nmap_ranked_top_1000(monkeypatch):
    captured = {}

    def fake_scan(target, ports):
        captured.update(target=target, ports=ports)
        return [OpenPort(port=80, service="HTTP", response_time_ms=0.5)]

    monkeypatch.setattr("app.services.port_scan_service.nmap_command_prefix", lambda: None)
    monkeypatch.setattr("app.services.port_scan_service.scan_tcp_ports", fake_scan)

    result = scan_nmap_top_tcp_ports("192.168.1.10")

    assert result.scanner == "Nmap-ranked socket scan"
    assert len(result.scanned_ports) == 1000
    assert captured == {"target": "192.168.1.10", "ports": list(NMAP_TOP_1000_TCP_PORTS)}
    assert [item.port for item in result.open_ports] == [80]


def test_nmap_ranked_port_list_is_unique_and_contains_major_services():
    assert len(NMAP_TOP_1000_TCP_PORTS) == 1000
    assert len(set(NMAP_TOP_1000_TCP_PORTS)) == 1000
    assert {22, 53, 80, 443, 445}.issubset(NMAP_TOP_1000_TCP_PORTS)


def test_parse_nmap_service_scan_keeps_product_version_and_cpe():
    services = parse_nmap_service_scan(SERVICE_XML)

    assert len(services) == 1
    assert services[0].port == 80
    assert services[0].product == "Apache httpd"
    assert services[0].version == "2.4.58"
    assert services[0].cpes == ("cpe:/a:apache:http_server:2.4.58",)


def test_service_detection_uses_fast_version_probe_on_open_ports(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        return SimpleNamespace(returncode=0, stdout=SERVICE_XML, stderr="")

    monkeypatch.setattr(
        "app.services.port_scan_service.nmap_command_prefix",
        lambda: ["docker", "exec", "aegis-network-tools", "nmap"],
    )
    monkeypatch.setattr("app.services.port_scan_service.subprocess.run", fake_run)

    services = scan_nmap_service_versions("192.168.1.10", [443, 80, 80])

    assert services[0].product == "Apache httpd"
    assert "-sV" in captured["command"]
    assert captured["command"][captured["command"].index("--version-intensity") + 1] == "0"
    assert captured["command"][captured["command"].index("--host-timeout") + 1] == "5s"
    assert captured["command"][captured["command"].index("-p") + 1] == "80,443"
    assert captured["kwargs"]["timeout"] == 6


def test_service_detection_profiles_control_probe_depth(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=SERVICE_XML, stderr="")

    monkeypatch.setattr(
        "app.services.port_scan_service.nmap_command_prefix",
        lambda: ["nmap"],
    )
    monkeypatch.setattr("app.services.port_scan_service.subprocess.run", fake_run)

    scan_nmap_service_versions("192.168.1.10", [80], "DETAILED")
    scan_nmap_service_versions("192.168.1.10", [80], "AGGRESSIVE")

    detailed_command, detailed_options = calls[0]
    aggressive_command, aggressive_options = calls[1]
    assert "--version-light" in detailed_command
    assert detailed_options["timeout"] == 100
    assert "--version-all" in aggressive_command
    assert aggressive_options["timeout"] == 200
