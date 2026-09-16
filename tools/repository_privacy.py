"""Reject runtime data and unreviewed network identifiers before publication.

Examples/fixtures use documentation or benchmarking address ranges. Errors
show paths and rules, never matched identifiers. This is not a semantic proof.
"""
import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import subprocess
import sys

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])[0-9a-fA-F:]*:[0-9a-fA-F:]+(?:\.[0-9.]+)?(?![\w:])")
MAC = re.compile(r"(?i)(?<!\w)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?!\w)")
DOCUMENTATION = tuple(ipaddress.ip_network(net) for net in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    "198.18.0.0/15", "2001:db8::/32",
))
WELL_KNOWN = {"8.8.8.8", "8.8.4.4", "1.1.1.1"}
SYNTHETIC_MAC = re.compile(r"(?i)^(?:aa:bb:cc:dd:ee:[0-9a-f]{2}|00:11:22:33:44:(?:55|66)|02:11:22:33:44:55|02:00:00:00:00:01|ff:ff:ff:ff:ff:ff|00:00:00:00:00:00|01:00:5e:00:00:fb)$")
RUNTIME_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".pcap", ".pcapng", ".cap", ".log", ".bak", ".zip", ".7z", ".tar", ".tgz", ".bundle", ".patch", ".har", ".evtx", ".etl", ".pfx", ".p12", ".pem", ".key", ".keystore"}
RUNTIME_DIRECTORIES = {"logs", "reports", "backups", "attachments", "captures", "privacy-cleanup", "local-validation", "private-data"}
PERSONAL_HOST = re.compile(r"(?i)C:[/\\]Users[/\\](?!Public\b|Default\b|USER\b)[^/\\\s]+|\b(?:DESKTOP|LAPTOP)-[a-z0-9-]{4,}")
KNOWN_SECRET = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b")

def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)

def allowed_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True  # Invalid tokens are exercised by validation tests.
    return (address.is_loopback or address.is_unspecified or address.is_multicast
            or value.startswith("255.") or value in WELL_KNOWN
            or value == "fe80::1"  # Explicit classification-test sentinel.
            or any(address.version == network.version and address in network for network in DOCUMENTATION))

def artifact_path(path):
    item = pathlib.PurePosixPath(path)
    return (item.suffix.lower() in RUNTIME_EXTENSIONS
            or any(part.lower() in RUNTIME_DIRECTORIES for part in item.parts)
            or item.name.lower().endswith(("-wal", "-shm"))
            or (item.name.startswith(".env") and not item.name.endswith(".example"))
            or (path.startswith("secrets/") and path != "secrets/.gitignore")
            or item.name.lower() in {"credentials.json", "secret.yaml", "secret.yml"})

def inspect(path, data, approved):
    failures = []
    if artifact_path(path):
        failures.append("runtime/secret artifact")
    digest = hashlib.sha256(data).hexdigest()
    allowed_digests = approved.get(path, [])
    if digest == allowed_digests or digest in (allowed_digests if isinstance(allowed_digests, list) else []):
        return failures
    if b"\0" in data[:8000] or pathlib.PurePosixPath(path).suffix.lower() in {".png", ".webp", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx"}:
        return failures + ["unreviewed binary/image/document"]
    text = data.decode("utf8", "replace")
    for number, line in enumerate(text.splitlines(), 1):
        if any(not allowed_address(value) for value in IPV4.findall(line)):
            failures.append(f"line {number}: non-synthetic IPv4 literal")
        if any(not allowed_address(value) for value in IPV6.findall(line)):
            failures.append(f"line {number}: non-synthetic IPv6 literal")
        if any(not SYNTHETIC_MAC.fullmatch(value.replace("-", ":")) for value in MAC.findall(line)):
            failures.append(f"line {number}: non-synthetic MAC literal")
        if PERSONAL_HOST.search(line):
            failures.append(f"line {number}: personal hostname/path")
        if KNOWN_SECRET.search(line):
            failures.append(f"line {number}: credential material")
    return failures

def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--index", action="store_true")
    mode.add_argument("--worktree", action="store_true")
    mode.add_argument("--history", nargs="+")
    args = parser.parse_args()
    root = pathlib.Path(git("rev-parse", "--show-toplevel").decode().strip())
    approved = json.loads((root / "tools/privacy-approved-files.json").read_text(encoding="utf8"))
    failures = []
    checked = 0
    if args.worktree:
        paths = set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0"))
        for path in sorted(paths):
            if path and (root / path).is_file():
                checked += 1
                failures.extend((path, rule) for rule in inspect(path, (root / path).read_bytes(), approved))
    else:
        objects = {}
        commits = []
        if args.history:
            commits = git("rev-list", *args.history).decode().splitlines()
            snapshots = [git("ls-tree", "-rz", "--full-tree", commit) for commit in commits]
        elif args.index:
            snapshots = [git("ls-files", "--stage", "-z")]
        else:
            snapshots = [git("ls-tree", "-rz", "--full-tree", "HEAD")]
        for snapshot in snapshots:
            for entry in snapshot.split(b"\0"):
                if not entry:
                    continue
                meta, path = entry.split(b"\t", 1)
                parts = meta.decode().split()
                oid = parts[1] if args.index else parts[2]
                objects.setdefault(oid, set()).add(path.decode())
        for commit in commits:
            objects.setdefault(commit, set()).add("<commit message>")
        batch = subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            for oid, paths in objects.items():
                batch.stdin.write((oid + "\n").encode())
                batch.stdin.flush()
                _, kind, size = batch.stdout.readline().decode().split()
                data = batch.stdout.read(int(size))
                batch.stdout.read(1)
                if kind == "commit":
                    data = data.partition(b"\n\n")[2]
                for path in paths:
                    checked += 1
                    failures.extend((path, rule) for rule in inspect(path, data, approved))
        finally:
            batch.stdin.close()
            batch.wait()
    for path, rule in failures[:80]:
        print(f"BLOCKED {path}: {rule}", file=sys.stderr)
    print(f"Repository privacy: checked {checked} file/message versions; {len(failures)} violations.")
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(main())
