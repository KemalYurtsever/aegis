import socket
from types import SimpleNamespace

from app.schemas import LabCommandRead, TraceRouteHop, TraceRouteRead
from app.services.discovery_service import LocalNetwork
from app.services.port_scan_service import OpenPort, PortScanResult
from app.services.security_toolbox_service import (
    _filter_output,
    _run_lab_tool,
    arp_scan,
    avahi_browse,
    curl_request,
    dnsrecon_standard,
    dig_query,
    fping_probe,
    host_query,
    host_network_policy,
    nikto_scan,
    nmap_tcp_scan,
    nmap_udp_scan,
    openssl_probe,
    parse_traceroute,
    query_dns,
    smb_posture_scan,
    smbclient_scan,
    test_connection_ports as run_test_connection_ports,
    whatweb_scan,
    wireless_adapters,
)


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "toolbox-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_tls_scan_uses_registered_device_and_validates_port(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", headers=headers, json={
        "name": "TLS host", "ip_address": "198.18.5.20", "device_type": "Server",
    }).json()
    captured = {}

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, **kwargs)
        return LabCommandRead(tool=tool, target=kwargs["target"], exit_code=0,
                              output="TLSv1.3 enabled", duration_ms=1)

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)
    response = client.post("/api/security/toolbox/sslscan", headers=headers,
                           json={"device_id": device["id"], "port": 8443})
    assert response.status_code == 200
    assert captured["command"][-1] == "198.18.5.20:8443"
    assert captured["timeout"] == 60
    assert "--no-heartbleed" in captured["command"]
    assert client.post("/api/security/toolbox/sslscan", headers=headers,
                       json={"device_id": device["id"], "port": 65536}).status_code == 422
    assert client.post("/api/security/toolbox/sslscan", headers=headers,
                       json={"device_id": 99999}).status_code == 404


def test_extended_defensive_tools_use_fixed_bounded_arguments(monkeypatch):
    captured = []

    def fake_run(tool, command, **kwargs):
        captured.append((tool, command, kwargs))
        return LabCommandRead(
            tool=tool, target=kwargs.get("target"), exit_code=0, output="ok", duration_ms=1,
        )

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    fping_probe("198.18.5.20")
    whatweb_scan("198.18.5.20", "https", 8443, "/admin")
    nikto_scan("198.18.5.20", "http", 8080, "/")
    openssl_probe("2001:db8::20", 443)
    smbclient_scan("198.18.5.20")
    smb_posture_scan("198.18.5.20")
    host_query("server.lab.example")
    dnsrecon_standard("lab.example")

    by_tool = {tool: (command, kwargs) for tool, command, kwargs in captured}
    assert by_tool["fping"][0] == ["fping", "-c", "3", "-p", "250", "-t", "1000", "198.18.5.20"]
    assert by_tool["fping"][1]["timeout"] == 10
    assert by_tool["whatweb"][0][-1] == "https://198.18.5.20:8443/admin"
    assert "--aggression=1" in by_tool["whatweb"][0]
    assert by_tool["nikto"][1]["timeout"] == 55
    assert by_tool["openssl"][0] == [
        "openssl", "s_client", "-connect", "[2001:db8::20]:443",
        "-brief", "-showcerts", "-no_ign_eof",
    ]
    assert "-N" in by_tool["smbclient"][0]
    assert "--script" in by_tool["smb-audit"][0]
    assert "smb-protocols,smb2-security-mode,smb2-time" in by_tool["smb-audit"][0]
    assert by_tool["host"][0] == ["host", "-W", "3", "server.lab.example"]
    assert by_tool["dnsrecon"][0] == [
        "dnsrecon", "-d", "lab.example", "-t", "std", "--threads", "2", "--lifetime", "3",
    ]


def test_extended_web_tool_endpoint_requires_registered_target(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", headers=headers, json={
        "name": "Web host", "ip_address": "198.18.5.30", "device_type": "Server",
    }).json()
    captured = {}

    def fake_scan(address, scheme, port, path, grep):
        captured.update(address=address, scheme=scheme, port=port, path=path, grep=grep)
        return LabCommandRead(
            tool="whatweb", target=f"{scheme}://{address}:{port}{path}",
            exit_code=0, output="nginx", duration_ms=1,
        )

    monkeypatch.setattr("app.routers.security.whatweb_scan", fake_scan)
    response = client.post("/api/security/toolbox/whatweb", headers=headers, json={
        "device_id": device["id"], "scheme": "https", "port": 8443,
        "path": "/admin", "grep": "nginx",
    })

    assert response.status_code == 200
    assert captured == {
        "address": "198.18.5.30", "scheme": "https", "port": 8443,
        "path": "/admin", "grep": "nginx",
    }
    assert client.post("/api/security/toolbox/whatweb", headers=headers, json={
        "device_id": device["id"], "path": "/bad path",
    }).status_code == 422
    assert client.post("/api/security/toolbox/whatweb", headers=headers, json={
        "device_id": 99999,
    }).status_code == 404


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


def test_lab_grep_is_case_insensitive_and_literal():
    output = "22/tcp open ssh\n80/tcp closed http\n443/tcp OPEN https"

    assert _filter_output(output, "open") == "22/tcp open ssh\n443/tcp OPEN https"
    assert _filter_output(output, "[open]") == ""


def test_missing_tool_is_delegated_to_docker_without_a_shell(monkeypatch):
    captured = {}
    monkeypatch.setenv("AEGIS_NETWORK_TOOLBOX_CONTAINER", "aegis-network-tools")
    monkeypatch.setattr(
        "app.services.security_toolbox_service.shutil.which",
        lambda name: "C:/Docker/docker.exe" if name == "docker" else None,
    )

    def fake_run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        kwargs["stdout"].write(b"22/tcp open ssh\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("app.services.security_toolbox_service.subprocess.run", fake_run)

    result = _run_lab_tool(
        "nmap", ["nmap", "-sT", "-p", "22", "198.18.5.20"],
        target="198.18.5.20", timeout=10,
    )

    assert captured["command"] == [
        "C:/Docker/docker.exe", "exec", "aegis-network-tools",
        "nmap", "-sT", "-p", "22", "198.18.5.20",
    ]
    assert captured["kwargs"]["shell"] is False
    assert result.output == "22/tcp open ssh"


def test_nmap_scan_uses_argument_list_and_normalized_options(monkeypatch):
    captured = {}

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, kwargs=kwargs)
        return LabCommandRead(tool="nmap", target="198.18.5.1", exit_code=0, output="open", duration_ms=1.0)

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    result = nmap_tcp_scan(
        "198.18.5.1", [443, 22], True, "open", show_reason=True
    )

    assert result.exit_code == 0
    assert captured["tool"] == "nmap"
    assert captured["command"] == [
        "nmap", "-Pn", "-sT", "-n", "-T4", "--max-retries", "0",
        "--min-rate", "500",
        "--initial-rtt-timeout", "100ms", "--max-rtt-timeout", "500ms",
        "--host-timeout", "10s", "-p", "443,22", "-sV",
        "--version-intensity", "0", "--reason", "198.18.5.1",
    ]
    assert captured["kwargs"] == {
        "target": "198.18.5.1",
        "grep": "open",
        "timeout": 20,
        "scanned_port_count": 2,
    }


def test_nmap_fast_profile_is_ports_only_and_explains_no_open_top_ports(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "app.services.security_toolbox_service.nmap_command_prefix",
        lambda: ["nmap"],
    )

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, kwargs=kwargs)
        return LabCommandRead(
            tool="nmap",
            target="198.18.5.1",
            exit_code=0,
            output="Nmap done: 1 IP address (1 host up) scanned",
            duration_ms=1.0,
            scanned_port_count=1000,
        )

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    result = nmap_tcp_scan(
        "198.18.5.1", [80], False, scan_mode="TOP_1000", profile="FAST"
    )

    assert "-sV" not in captured["command"]
    assert "--version-intensity" not in captured["command"]
    assert result.output.endswith(
        "No open TCP ports were found among Nmap's top 1,000 ports."
    )


def test_nmap_empty_filtered_output_is_explained(monkeypatch):
    monkeypatch.setattr(
        "app.services.security_toolbox_service._run_lab_tool",
        lambda *_args, **_kwargs: LabCommandRead(
            tool="nmap", target="198.18.5.1", exit_code=0,
            output="", duration_ms=1.0, scanned_port_count=2,
        ),
    )

    result = nmap_tcp_scan("198.18.5.1", [80, 443], False, grep="open")

    assert result.output == "No Nmap output matched 'open'."


def test_nmap_detailed_and_aggressive_profiles_select_version_depth(monkeypatch):
    commands = []

    def fake_run(_tool, command, **kwargs):
        commands.append((command, kwargs))
        return LabCommandRead(tool="nmap", target="198.18.5.1", exit_code=0, output="", duration_ms=1.0)

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    nmap_tcp_scan("198.18.5.1", [80], False, scan_mode="CUSTOM", profile="DETAILED")
    nmap_tcp_scan("198.18.5.1", [80], False, scan_mode="CUSTOM", profile="AGGRESSIVE")

    detailed, aggressive = commands
    assert detailed[0][-3:-1] == ["-sV", "--version-light"]
    assert detailed[1]["timeout"] == 100
    assert aggressive[0][-3:-1] == ["-sV", "--version-all"]
    assert aggressive[1]["timeout"] == 200


def test_nmap_udp_scan_is_bounded_and_uses_profile_specific_version_depth(monkeypatch):
    captured = {}

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, kwargs=kwargs)
        return LabCommandRead(
            tool="nmap-udp", target="198.18.5.1", exit_code=0,
            output="53/udp open domain", duration_ms=1.0, scanned_port_count=3,
        )

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    result = nmap_udp_scan(
        "198.18.5.1",
        [161, 53, 161, 1900],
        profile="DETAILED",
        show_reason=True,
        grep="open",
    )

    assert result.scanned_port_count == 3
    assert captured["tool"] == "nmap-udp"
    assert captured["command"] == [
        "nmap", "-Pn", "-sU", "-n", "-T4", "--max-retries", "1",
        "--host-timeout", "60s", "--open", "-p", "161,53,1900",
        "-sV", "--version-light", "--reason", "198.18.5.1",
    ]
    assert captured["kwargs"] == {
        "target": "198.18.5.1",
        "grep": "open",
        "timeout": 70,
        "scanned_port_count": 3,
    }


def test_test_connection_uses_validated_environment_values(monkeypatch):
    captured = {}

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, kwargs=kwargs)
        return LabCommandRead(
            tool="test-connection", target="198.18.5.1", exit_code=0,
            output="80 True", duration_ms=1.0, scanned_port_count=2,
        )

    monkeypatch.setattr("app.services.security_toolbox_service.shutil.which", lambda name: "C:/Tools/pwsh.exe" if name == "pwsh" else None)
    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    result = run_test_connection_ports("198.18.5.1", [443, 80, 443], 2, "True")

    assert result.scanned_port_count == 2
    assert captured["tool"] == "test-connection"
    assert captured["command"][:4] == ["C:/Tools/pwsh.exe", "-NoProfile", "-NonInteractive", "-Command"]
    assert captured["kwargs"]["environment"] == {
        "AEGIS_TCP_TEST_TARGET": "198.18.5.1",
        "AEGIS_TCP_TEST_PORTS": "443,80",
        "AEGIS_TCP_TEST_TIMEOUT": "2",
    }
    script = captured["command"][4]
    assert "PowerShell 7 Test-Connection -TcpPort" in script
    assert "Scan completed:" in script
    assert "NoResponse" in script
    assert "LatencyMs=$latency" in script


def test_windows_powershell_tcp_fallback_is_parallel_and_deadline_bounded(monkeypatch):
    captured = {}

    def fake_which(name):
        return "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" if name == "powershell.exe" else None

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, kwargs=kwargs)
        return LabCommandRead(
            tool="test-connection", target="198.18.5.1", exit_code=0,
            output="80 False", duration_ms=1.0, scanned_port_count=3,
        )

    monkeypatch.setattr("app.services.security_toolbox_service.shutil.which", fake_which)
    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    run_test_connection_ports("198.18.5.1", [22, 80, 443], 1)

    script = captured["command"][4]
    assert "BeginConnect" in script
    assert "Test-NetConnection" not in script
    assert "Windows PowerShell .NET TcpClient" in script
    assert "$deadline=" in script
    assert "closed/refused" in script
    assert "State=$state" in script
    assert captured["kwargs"]["timeout"] == 13
    assert captured["kwargs"]["scanned_port_count"] == 3


def test_top_1000_scan_uses_ranked_socket_fallback_without_nmap(monkeypatch):
    monkeypatch.setattr(
        "app.services.security_toolbox_service.nmap_command_prefix",
        lambda: None,
    )
    monkeypatch.setattr(
        "app.services.security_toolbox_service.scan_nmap_top_tcp_ports",
        lambda _address: PortScanResult(
            scanned_ports=list(range(1, 1001)),
            open_ports=[OpenPort(port=80, service="HTTP", response_time_ms=1.0)],
            scanner="Nmap-ranked socket scan",
            duration_ms=24.5,
        ),
    )

    result = nmap_tcp_scan(
        "198.18.5.1", [22], False, scan_mode="TOP_1000", show_reason=True
    )

    assert result.scanned_port_count == 1000
    assert "Scanned ports: 1000" in result.output
    assert "80/tcp  open  HTTP" in result.output
    assert "reasons require the Nmap executable" in result.output


def test_nmap_scan_enables_ipv6(monkeypatch):
    captured = {}

    def fake_run(_tool, command, **_kwargs):
        captured["command"] = command
        return LabCommandRead(tool="nmap", target="2001:db8::10", exit_code=0, output="", duration_ms=1.0)

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    nmap_tcp_scan("2001:db8::10", [443], False)

    assert "-6" in captured["command"]
    assert captured["command"][-1] == "2001:db8::10"


def test_windows_arp_scan_uses_bounded_native_fallback(monkeypatch):
    monkeypatch.setattr("app.services.security_toolbox_service.platform.system", lambda: "Windows")
    monkeypatch.setattr("app.services.security_toolbox_service.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "app.services.security_toolbox_service.get_primary_private_network",
        lambda: LocalNetwork("Wi-Fi", "198.18.5.20", "198.18.5.0/24", "198.18.5.1"),
    )
    monkeypatch.setattr(
        "app.services.security_toolbox_service.discover_responsive_hosts",
        lambda _network: [
            ("198.18.5.1", "AA:BB:CC:DD:EE:01"),
            ("198.18.5.10", "AA:BB:CC:DD:EE:10"),
        ],
    )

    result = arp_scan(grep="198.18.5")

    assert result.target == "198.18.5.0/24"
    assert "198.18.5.1" in result.output
    assert "198.18.5.10" in result.output
    assert "198.19.0.1" not in result.output


def test_avahi_browse_uses_a_fixed_nonpublishing_command(monkeypatch):
    captured = {}
    monkeypatch.setattr("app.services.security_toolbox_service.platform.system", lambda: "Linux")

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, kwargs=kwargs)
        return LabCommandRead(
            tool="avahi-browse", target="local mDNS", exit_code=0,
            output="Living Room TV", duration_ms=1.0,
        )

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    result = avahi_browse("Chromecast")

    assert result.exit_code == 0
    assert captured == {
        "tool": "avahi-browse",
        "command": [
            "avahi-browse", "--all", "--resolve", "--terminate",
            "--no-db-lookup", "--ignore-local",
        ],
        "kwargs": {"target": "local mDNS", "grep": "Chromecast", "timeout": 12},
    }


def test_avahi_browse_explains_empty_docker_multicast_results(monkeypatch):
    monkeypatch.setattr("app.services.security_toolbox_service.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "app.services.security_toolbox_service._run_lab_tool",
        lambda *_args, **_kwargs: LabCommandRead(
            tool="avahi-browse", target="local mDNS", exit_code=0,
            output="", duration_ms=1.0,
        ),
    )

    result = avahi_browse()

    assert result.output == (
        "No DNS-SD services were visible inside Docker. "
        "Use Discover network for host-interface mDNS discovery."
    )


def test_windows_avahi_browse_uses_host_interface_mdns(monkeypatch):
    monkeypatch.setattr("app.services.security_toolbox_service.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "app.services.security_toolbox_service.get_primary_private_network",
        lambda: LocalNetwork("WiFi", "198.18.5.20", "198.18.5.0/24", "198.18.5.1"),
    )
    monkeypatch.setattr(
        "app.services.security_toolbox_service.get_settings",
        lambda: SimpleNamespace(discovery_mdns_timeout_seconds=2.0),
    )
    monkeypatch.setattr(
        "app.services.security_toolbox_service.discover_mdns",
        lambda _network, _timeout: {
            "198.18.5.40": {
                "display_name": "Living Room TV",
                "model": "Chromecast Ultra",
                "hostname": "living-room.local",
                "services": ["googlecast", "http"],
            },
            "198.18.6.40": {
                "display_name": "Outside bounded subnet",
                "model": "Should not be returned",
                "hostname": "outside.local",
                "services": ["googlecast"],
            },
        },
    )

    result = avahi_browse("Chromecast")

    assert result.exit_code == 0
    assert result.target == "WiFi 198.18.5.0/24"
    assert result.output == (
        "198.18.5.40\tLiving Room TV\tChromecast Ultra\t"
        "living-room.local\tgooglecast,http"
    )
    assert "198.18.6.40" not in result.output


def test_windows_dig_falls_back_to_nslookup(monkeypatch):
    captured = {}
    monkeypatch.setattr("app.services.security_toolbox_service.platform.system", lambda: "Windows")
    monkeypatch.setattr("app.services.security_toolbox_service.shutil.which", lambda name: None if name == "dig" else name)

    def fake_run(tool, command, **kwargs):
        captured.update(tool=tool, command=command, kwargs=kwargs)
        return LabCommandRead(tool="dig", target="lab.example", exit_code=0, output="record", duration_ms=1.0)

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    dig_query("lab.example", "AAAA", "record")

    assert captured["command"] == ["nslookup", "-type=AAAA", "lab.example"]
    assert captured["kwargs"] == {"target": "lab.example", "grep": "record", "timeout": 10}


def test_curl_request_keeps_url_after_option_terminator(monkeypatch):
    captured = {}

    def fake_run(_tool, command, **_kwargs):
        captured["command"] = command
        return LabCommandRead(tool="curl", target="https://lab.example", exit_code=0, output="", duration_ms=1.0)

    monkeypatch.setattr("app.services.security_toolbox_service._run_lab_tool", fake_run)

    curl_request("https://lab.example", "GET", False)

    assert captured["command"][-2:] == ["--", "https://lab.example"]
    assert captured["command"][captured["command"].index("--proto-redir") + 1] == "=http,https"


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
            return [{"DisplayName": "Allow AEGIS", "Direction": "Inbound", "Action": "Allow", "Profile": "Private"}]
        return [
            {"DestinationPrefix": "0.0.0.0/0", "NextHop": "198.18.1.1", "InterfaceAlias": "Wi-Fi", "RouteMetric": 25},
            {"DestinationPrefix": "198.18.1.0/24", "NextHop": "0.0.0.0", "InterfaceAlias": "Wi-Fi", "RouteMetric": 281},
        ]

    monkeypatch.setattr("app.services.security_toolbox_service._run_powershell_json", powershell_result)

    result = host_network_policy()

    assert result.firewall_profiles[0].default_inbound_action == "Block"
    assert result.firewall_rules[0].name == "Allow AEGIS"
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

    response = client.post(
        "/api/security/toolbox/nmap",
        headers=operator_headers,
        json={"device_id": 1, "ports": [22]},
    )

    assert response.status_code == 403


def test_nmap_endpoint_resolves_registered_device(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post(
        "/api/devices",
        headers=headers,
        json={"name": "Lab host", "ip_address": "198.18.5.20", "device_type": "Server", "is_active": True},
    ).json()
    captured = {}

    def fake_scan(
        address, ports, service_detection, *, grep, scan_mode, profile, show_reason
    ):
        captured.update(
            address=address,
            ports=ports,
            service_detection=service_detection,
            grep=grep,
            scan_mode=scan_mode,
            profile=profile,
            show_reason=show_reason,
        )
        return LabCommandRead(tool="nmap", target=address, exit_code=0, output="22/tcp open ssh", duration_ms=3.5)

    monkeypatch.setattr("app.routers.security.nmap_tcp_scan", fake_scan)

    response = client.post(
        "/api/security/toolbox/nmap",
        headers=headers,
        json={
            "device_id": device["id"],
            "ports": [22, 443, 22],
            "service_detection": True,
            "show_reason": True,
            "grep": "open",
        },
    )

    assert response.status_code == 200
    assert response.json()["output"] == "22/tcp open ssh"
    assert captured == {
        "address": "198.18.5.20", "ports": [22, 443], "service_detection": True,
        "grep": "open", "scan_mode": "CUSTOM", "profile": "FAST",
        "show_reason": True,
    }


def test_nmap_udp_endpoint_resolves_registered_device(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post(
        "/api/devices",
        headers=headers,
        json={"name": "UDP target", "ip_address": "198.18.5.22", "device_type": "Server", "is_active": True},
    ).json()
    captured = {}

    def fake_scan(address, ports, *, profile, show_reason, grep):
        captured.update(
            address=address,
            ports=ports,
            profile=profile,
            show_reason=show_reason,
            grep=grep,
        )
        return LabCommandRead(
            tool="nmap-udp", target=address, exit_code=0,
            output="161/udp open snmp", duration_ms=3.5, scanned_port_count=len(ports),
        )

    monkeypatch.setattr("app.routers.security.nmap_udp_scan", fake_scan)

    response = client.post(
        "/api/security/toolbox/nmap-udp",
        headers=headers,
        json={
            "device_id": device["id"],
            "ports": [161, 53, 161],
            "profile": "DETAILED",
            "show_reason": True,
            "grep": "open",
        },
    )

    assert response.status_code == 200
    assert response.json()["tool"] == "nmap-udp"
    assert response.json()["scanned_port_count"] == 2
    assert captured == {
        "address": "198.18.5.22",
        "ports": [161, 53],
        "profile": "DETAILED",
        "show_reason": True,
        "grep": "open",
    }


def test_test_connection_endpoint_uses_registered_device(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post(
        "/api/devices",
        headers=headers,
        json={"name": "TCP target", "ip_address": "198.18.5.21", "device_type": "Server", "is_active": True},
    ).json()
    captured = {}

    def fake_test(address, ports, timeout_seconds, grep):
        captured.update(address=address, ports=ports, timeout_seconds=timeout_seconds, grep=grep)
        return LabCommandRead(
            tool="test-connection", target=address, exit_code=0,
            output="443 True", duration_ms=2.0, scanned_port_count=len(ports),
        )

    monkeypatch.setattr("app.routers.security.test_connection_ports", fake_test)

    response = client.post(
        "/api/security/toolbox/test-connection",
        headers=headers,
        json={"device_id": device["id"], "ports": [443, 80, 443], "timeout_seconds": 3, "grep": "True"},
    )

    assert response.status_code == 200
    assert response.json()["scanned_port_count"] == 2
    assert captured == {
        "address": "198.18.5.21", "ports": [443, 80],
        "timeout_seconds": 3, "grep": "True",
    }


def test_avahi_browse_endpoint_is_admin_only_and_forwards_literal_filter(client, monkeypatch):
    unauthorized = client.post(
        "/api/security/toolbox/avahi-browse",
        json={"grep": "Chromecast"},
    )
    assert unauthorized.status_code == 403

    headers = admin_headers(client)
    captured = {}

    def fake_browse(grep):
        captured["grep"] = grep
        return LabCommandRead(
            tool="avahi-browse", target="local mDNS", exit_code=0,
            output="Living Room TV", duration_ms=2.0,
        )

    monkeypatch.setattr("app.routers.security.avahi_browse", fake_browse)

    response = client.post(
        "/api/security/toolbox/avahi-browse",
        headers=headers,
        json={"grep": "Chromecast"},
    )

    assert response.status_code == 200
    assert response.json()["tool"] == "avahi-browse"
    assert captured == {"grep": "Chromecast"}
