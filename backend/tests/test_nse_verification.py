from types import SimpleNamespace

import pytest

from app.services.nse_verification_service import (
    parse_nse_verification,
    run_nse_verification,
)
from app.services.port_scan_service import OpenPort


NSE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <script id="ssh2-enum-algos" output="kex_algorithms: diffie-hellman-group1-sha1" />
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <script id="smb2-security-mode" output="Message signing enabled but not required" />
        <script id="unexpected-script" output="must be ignored" />
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Windows 11 Pro 22631; Computer name: LAB-PC" />
      <script id="smb-protocols" output="NT LM 0.12 (SMBv1) [dangerous]" />
    </hostscript>
  </host>
</nmaprun>
"""


def test_nse_parser_keeps_only_requested_script_evidence():
    scripts = ("smb-os-discovery", "smb-protocols", "smb2-security-mode", "ssh2-enum-algos")

    observations = parse_nse_verification(NSE_XML, scripts, [22, 445])

    assert [(item.script_id, item.port) for item in observations] == [
        ("ssh2-enum-algos", 22),
        ("smb-os-discovery", 445),
        ("smb-protocols", 445),
        ("smb2-security-mode", 445),
    ]
    assert all("unexpected" not in item.output for item in observations)


def test_nse_verifier_builds_bounded_argument_list(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "app.services.nse_verification_service.nmap_command_prefix",
        lambda: ["docker", "exec", "aegis-network-tools", "nmap"],
    )

    def fake_run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        return SimpleNamespace(returncode=0, stdout=NSE_XML, stderr="")

    monkeypatch.setattr(
        "app.services.nse_verification_service.subprocess.run",
        fake_run,
    )

    result = run_nse_verification(
        "198.18.1.25",
        [OpenPort(445, "SMB", None), OpenPort(22, "SSH", None), OpenPort(9999, "unknown", None)],
        "FAST",
    )

    command = captured["command"]
    assert command[:4] == ["docker", "exec", "aegis-network-tools", "nmap"]
    assert command[command.index("--script") + 1] == (
        "smb-os-discovery,smb-protocols,smb2-security-mode,ssh2-enum-algos"
    )
    assert command[command.index("-p") + 1] == "22,445"
    assert "--reason" in command
    assert command[-1] == "198.18.1.25"
    assert captured["kwargs"]["timeout"] == 30
    assert captured["kwargs"]["shell"] is False
    assert len(result.observations) == 4


def test_nse_verifier_skips_devices_without_supported_open_services(monkeypatch):
    monkeypatch.setattr(
        "app.services.nse_verification_service.nmap_command_prefix",
        lambda: pytest.fail("Nmap should not be resolved when no checks apply"),
    )

    result = run_nse_verification(
        "198.18.1.25",
        [OpenPort(9999, "unknown", None)],
    )

    assert result.requested_scripts == ()
    assert result.observations == ()
