"""Explicit local Windows adapter changes; never modify Docker/remote devices."""
import base64
import ctypes
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from uuid import UUID


class MacManagementError(Exception):
    def __init__(self, message, status_code=409):
        super().__init__(message)
        self.status_code = status_code


_CHANGE_LOCK = threading.Lock()
_PREVIEW_KEY = secrets.token_bytes(32)
_PREVIEW_LOCK = threading.Lock()
_ISSUED_PREVIEWS = {}


def _sign_preview(plan):
    payload = {key: plan[key] for key in ("interface_id", "mode", "previous_mac", "target_mac")}
    payload["expires_at"] = time.time() + 300
    payload["nonce"] = secrets.token_hex(16)
    encoded = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(_PREVIEW_KEY, encoded.encode(), hashlib.sha256).hexdigest()
    token = encoded + "." + signature
    key = hashlib.sha256(token.encode()).hexdigest()
    with _PREVIEW_LOCK:
        now = time.time()
        for stale in [key for key, expiry in _ISSUED_PREVIEWS.items() if expiry <= now]:
            del _ISSUED_PREVIEWS[stale]
        if len(_ISSUED_PREVIEWS) >= 128:
            del _ISSUED_PREVIEWS[next(iter(_ISSUED_PREVIEWS))]
        _ISSUED_PREVIEWS[key] = payload["expires_at"]
    return token


def _check_preview_issued(token, *, consume=False):
    key = hashlib.sha256(token.encode()).hexdigest()
    with _PREVIEW_LOCK:
        expiry = _ISSUED_PREVIEWS.get(key)
        if expiry is None or expiry <= time.time():
            raise MacManagementError("Expired or already used preview. Prepare the exact change again.")
        if consume:
            del _ISSUED_PREVIEWS[key]


def _verify_preview(token, interface_id, mode, mac_address, expected_mac):
    try:
        encoded, signature = token.split(".")
        expected_signature = hmac.new(_PREVIEW_KEY, encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid signature")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if (payload["interface_id"] != str(UUID(str(interface_id))) or payload["mode"] != mode
                or payload["previous_mac"] != normalize_mac(expected_mac)
                or (mode != "restore" and payload["target_mac"] != normalize_mac(mac_address))):
            raise ValueError("Preview mismatch")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise MacManagementError("Invalid or changed preview. Prepare the exact change again.") from exc
    _check_preview_issued(token)
    return payload
_READ_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
$items = @(foreach ($adapter in Get-NetAdapter -Physical -ErrorAction Stop) {
    $name = [WildcardPattern]::Escape($adapter.Name)
    $property = @(Get-NetAdapterAdvancedProperty -Name $name -RegistryKeyword 'NetworkAddress' -AllProperties -ErrorAction SilentlyContinue)
    [pscustomobject]@{
        interface_id = ([Guid]$adapter.InterfaceGuid).ToString()
        name = [string]$adapter.Name
        description = [string]$adapter.InterfaceDescription
        status = [string]$adapter.Status
        current_mac = [string]$adapter.MacAddress
        permanent_mac = [string]$adapter.PermanentAddress
        supports_override = ($property.Count -eq 1)
        override_mac = $(if ($property.Count -eq 1) { [string]($property[0].RegistryValue -join '') } else { '' })
    }
})
ConvertTo-Json -InputObject $items -Depth 3 -Compress
'''


def normalize_mac(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})", value):
        raise ValueError("Enter 12 hexadecimal digits or six pairs separated by ':' or '-'.")
    compact = value.replace(":", "").replace("-", "").upper()
    if compact == "0" * 12 or int(compact[:2], 16) & 1:
        raise ValueError("MAC must be a nonzero unicast address; multicast/broadcast addresses are not allowed.")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def random_local_mac(excluded=()) -> str:
    excluded = {normalize_mac(value) for value in excluded if value}
    for _ in range(32):
        address = bytearray(secrets.token_bytes(6))
        address[0] = (address[0] | 2) & 0xFE
        candidate = normalize_mac(address.hex())
        if candidate not in excluded:
            return candidate
    raise MacManagementError("Could not generate a distinct local address. Try again.")


def host_windows() -> bool:
    return os.name == "nt"


def windows_elevated() -> bool:
    return host_windows() and bool(ctypes.windll.shell32.IsUserAnAdmin())


def _run_script(script, timeout=25):
    executable = Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    try:
        result = subprocess.run(
            [str(executable), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            shell=False, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise MacManagementError("Windows operation timed out; state is unknown. Refresh adapters before retrying.", 504) from exc
    except OSError as exc:
        raise MacManagementError("Windows NetAdapter PowerShell is unavailable.", 503) from exc
    if result.returncode:
        raise MacManagementError("Windows rejected the operation. Check elevation, driver support and refresh the adapter state.")
    return result.stdout.strip()


def adapter_status():
    if not host_windows():
        return {"platform": "unsupported", "can_apply": False, "adapters": [],
                "message": "Host MAC management requires the native Windows backend. A Docker/Linux backend cannot change the Windows host adapter."}
    try:
        rows = json.loads(_run_script(_READ_SCRIPT))
        if not isinstance(rows, list):
            raise ValueError("Adapter query must return an array")
        adapters = []
        for row in rows:
            item = {**row, "interface_id": str(UUID(row["interface_id"]))}
            for key in ("current_mac", "permanent_mac", "override_mac"):
                try:
                    item[key] = normalize_mac(row[key]) if row.get(key) else None
                except ValueError:
                    item[key] = None
            adapters.append(item)
    except (ValueError, KeyError, TypeError) as exc:
        raise MacManagementError("Windows returned an unexpected adapter response.", 503) from exc
    elevated = windows_elevated()
    return {"platform": "windows", "can_apply": elevated, "adapters": adapters,
            "message": "API has local Administrator privileges." if elevated else
                       "To change the MAC directly, run the native Windows API as Administrator, or run the downloaded script in an Administrator PowerShell."}


def _change_script(interface_id, mode, target_mac, previous_mac):
    # Only UUID and validated hexadecimal values enter this fixed script.
    identity = str(UUID(str(interface_id)))
    expected = normalize_mac(previous_mac).replace(":", "")
    operation = "$property | Reset-NetAdapterAdvancedProperty -NoRestart -ErrorAction Stop" if mode == "restore" else (
        "$property | Set-NetAdapterAdvancedProperty -RegistryValue '" + normalize_mac(target_mac).replace(":", "") + "' -NoRestart -ErrorAction Stop")
    expected_result = "([string]$adapter.PermanentAddress -replace '[:-]', '').ToUpperInvariant()" if mode == "restore" else "'" + normalize_mac(target_mac).replace(":", "") + "'"
    return f'''$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{ throw 'Run PowerShell as Administrator.' }}
$adapters = @(Get-NetAdapter -Physical | Where-Object {{ ([Guid]$_.InterfaceGuid).ToString() -eq '{identity}' }})
if ($adapters.Count -ne 1) {{ throw 'Selected physical adapter no longer exists.' }}
$adapter = $adapters[0]
$current = ([string]$adapter.MacAddress -replace '[:-]', '').ToUpperInvariant()
if ($current -ne '{expected}') {{ throw 'Adapter MAC changed after preview. Refresh and prepare again.' }}
$property = @(Get-NetAdapterAdvancedProperty -Name ([WildcardPattern]::Escape($adapter.Name)) -RegistryKeyword 'NetworkAddress' -AllProperties -ErrorAction Stop)
if ($property.Count -ne 1) {{ throw 'Driver does not expose NetworkAddress override.' }}
$wanted = {expected_result}
{operation}
$adapter | Restart-NetAdapter -Confirm:$false -ErrorAction Stop
$deadline = [DateTime]::UtcNow.AddSeconds(8)
do {{
    $updated = Get-NetAdapter -Physical | Where-Object {{ ([Guid]$_.InterfaceGuid).ToString() -eq '{identity}' }}
    $actual = ([string]$updated.MacAddress -replace '[:-]', '').ToUpperInvariant()
    if ($wanted -and $actual -eq $wanted) {{ break }}
    Start-Sleep -Milliseconds 250
}} while ([DateTime]::UtcNow -lt $deadline)
[pscustomobject]@{{ interface_id = '{identity}'; actual_mac = [string]$updated.MacAddress; verified = [bool]($wanted -and $actual -eq $wanted) }} | ConvertTo-Json -Compress
'''


def prepare_change(interface_id, mode, mac_address=None, *, issue_token=True):
    status = adapter_status()
    if status["platform"] != "windows":
        raise MacManagementError(status["message"])
    identity = str(UUID(str(interface_id)))
    adapter = next((item for item in status["adapters"] if item["interface_id"] == identity), None)
    if adapter is None:
        raise MacManagementError("Physical adapter was not found. Refresh the adapter list.", 404)
    if not adapter["supports_override"] or not adapter["current_mac"]:
        raise MacManagementError("This driver does not expose a usable NetworkAddress override.")
    used = [value for item in status["adapters"] for value in (item["current_mac"], item["permanent_mac"], item["override_mac"]) if value]
    if mode == "restore":
        if mac_address is not None:
            raise ValueError("Restore must not include a replacement MAC.")
        target = adapter["permanent_mac"]
        if not target:
            raise MacManagementError("Permanent MAC is unavailable; factory restoration cannot be verified.")
    elif mode in {"manual", "random"}:
        if mode == "manual" and not mac_address:
            raise ValueError("Enter a MAC address for manual mode.")
        target = normalize_mac(mac_address) if mac_address else random_local_mac(used)
        if mode == "random" and not (int(target[:2], 16) & 2):
            raise ValueError("Random-mode addresses must be locally administered.")
        if any(item["interface_id"] != identity and target in (item["current_mac"], item["override_mac"]) for item in status["adapters"]):
            raise ValueError("Another local adapter already uses this MAC. Choose a different address.")
    else:
        raise ValueError("Unknown MAC change mode.")
    script = _change_script(identity, mode, target, adapter["current_mac"])
    rollback_mode = "restore" if not adapter["override_mac"] and adapter["current_mac"] == adapter["permanent_mac"] else "manual"
    rollback = _change_script(identity, rollback_mode, adapter["current_mac"], target)
    plan = {"interface_id": identity, "mode": mode, "previous_mac": adapter["current_mac"], "target_mac": target,
            "can_apply": status["can_apply"], "script": script, "rollback_script": rollback,
            "message": "Only this physical Windows adapter changes; it is restarted and may briefly disconnect. Driver acceptance is verified, not assumed."}
    if issue_token:
        plan["plan_token"] = _sign_preview(plan)
    return plan


def apply_change(interface_id, mode, mac_address, expected_mac, plan_token):
    if not windows_elevated():
        raise MacManagementError("Applying a host MAC change requires the native API to run as Administrator.", 403)
    if not _CHANGE_LOCK.acquire(blocking=False):
        raise MacManagementError("A MAC change is already in progress.")
    try:
        # Random apply must use the address already displayed in its preview.
        if mode != "restore" and mac_address is None:
            raise ValueError("Prepare a replacement MAC before applying.")
        preview = _verify_preview(plan_token, interface_id, mode, mac_address, expected_mac)
        plan = prepare_change(interface_id, mode, mac_address, issue_token=False)
        if preview["target_mac"] != plan["target_mac"]:
            raise MacManagementError("Adapter factory address changed after preview. Refresh and prepare again.")
        if normalize_mac(expected_mac) != plan["previous_mac"]:
            raise MacManagementError("Adapter MAC changed after preview. Refresh and prepare again.")
        _check_preview_issued(plan_token, consume=True)
        try:
            result = json.loads(_run_script(plan["script"]))
            actual = normalize_mac(result["actual_mac"])
        except (ValueError, KeyError, TypeError) as exc:
            raise MacManagementError("Change result could not be verified. Refresh adapters before retrying.") from exc
        return {"status": "APPLIED" if result.get("verified") is True and actual == plan["target_mac"] else "NOT_VERIFIED",
                "actual_mac": actual, "target_mac": plan["target_mac"],
                "message": "Requested MAC is active." if result.get("verified") is True and actual == plan["target_mac"] else
                           "Driver did not activate the requested MAC. Refresh adapters; use the rollback script if needed."}
    finally:
        _CHANGE_LOCK.release()
