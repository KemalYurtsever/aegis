import pathlib
import sys
import unittest
from ipaddress import IPv4Address, IPv6Address

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from repository_privacy import artifact_path, inspect

class PrivacyGuardTests(unittest.TestCase):
    def test_documentation_and_benchmark_fixtures_are_allowed(self):
        data = b"198.18.20.10 198.51.100.20 2001:db8::20 127.0.0.1 02:00:00:00:00:01"
        self.assertEqual(inspect("tests/fixture.txt", data, {}), [])

    def test_private_and_unapproved_public_addresses_are_blocked(self):
        for address in (IPv4Address(0x0A000001), IPv4Address(0x01020304)):
            rules = inspect("docs/example.md", str(address).encode(), {})
            self.assertTrue(any("IPv4" in rule for rule in rules))

    def test_non_documentation_ipv6_is_blocked(self):
        address = IPv6Address((0xFD << 120) | 0x20)
        self.assertTrue(any("IPv6" in rule for rule in inspect("fixture.txt", str(address).encode(), {})))

    def test_device_mac_is_blocked_without_echoing_it(self):
        mac = bytes.fromhex("a01234567890").hex(":")
        rules = inspect("fixture.txt", mac.encode(), {})
        self.assertTrue(any("MAC" in rule for rule in rules))
        self.assertNotIn(mac, " ".join(rules))

    def test_runtime_artifacts_remain_blocked_even_if_digest_is_approved(self):
        import hashlib
        for path in ("backend/monitoring.db", "captures/test.pcapng", "reports/export.json", "secrets/password.txt", ".env"):
            self.assertTrue(artifact_path(path))
            self.assertTrue(inspect(path, b"dummy", {path: hashlib.sha256(b"dummy").hexdigest()}))

    def test_only_sanitized_environment_examples_are_versionable(self):
        for path in (".env.docker.example", "backend/.env.example", "secrets/.gitignore", "deploy/kubernetes/secret.example.yaml"):
            self.assertFalse(artifact_path(path))

    def test_unknown_images_are_blocked(self):
        self.assertTrue(inspect("docs/new.png", b"\x89PNG\0", {}))

    def test_changed_approved_images_are_blocked(self):
        import hashlib
        good = b"\x89PNG\0reviewed"
        approved = {"docs/demo.png": hashlib.sha256(good).hexdigest()}
        self.assertEqual(inspect("docs/demo.png", good, approved), [])
        self.assertTrue(inspect("docs/demo.png", good + b"changed", approved))

    def test_personal_hostnames_and_paths_are_blocked(self):
        hostname = "LAP" + "TOP-" + "EXAMPLE01"
        data = ("C:" + "\\" + "Users" + "\\" + "test-user" + "\\" + "private " + hostname).encode()
        self.assertTrue(inspect("docs/example.md", data, {}))

if __name__ == "__main__":
    unittest.main()
