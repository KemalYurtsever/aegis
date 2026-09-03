[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [string]$Token,
    [ValidateRange(10, 3600)][int]$IntervalSeconds = 60,
    [switch]$EnableDiagnostics,
    [string]$InstallDirectory = "$env:ProgramData\LIIMS Agent"
)

$ErrorActionPreference = "Stop"
$taskName = "LIIMS Host Agent"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from PowerShell as Administrator."
}
$server = [Uri]$ServerUrl
if ($server.Scheme -notin @("http", "https") -or -not $server.Host) { throw "ServerUrl must be an HTTP or HTTPS URL." }
if (-not $Token) {
    $secureToken = Read-Host "Paste the one-time LIIMS agent token" -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try { $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}
if ($Token.Length -lt 20) { throw "The LIIMS agent token is missing or invalid." }

$healthUrl = "$($ServerUrl.TrimEnd('/'))/api/agent/health"
try {
    $health = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 10
} catch {
    throw "Cannot reach the LIIMS agent ingress at $healthUrl. Check the server address, port 8002, and Windows Firewall. $($_.Exception.Message)"
}
if ($health.status -ne "healthy") { throw "The LIIMS agent ingress did not report a healthy status." }
Write-Host "Preflight passed: LIIMS agent ingress is reachable."

$pythonLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pythonLauncher -and -not $pythonCommand) { throw "Python 3 is required. Install it, then rerun this script." }

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "liims_agent.py") -Destination $InstallDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "requirements.txt") -Destination $InstallDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall-windows.ps1") -Destination $InstallDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "test-agent.ps1") -Destination $InstallDirectory -Force

$venv = Join-Path $InstallDirectory ".venv"
if ($pythonLauncher) { & $pythonLauncher.Source -3 -m venv $venv }
else { & $pythonCommand.Source -m venv $venv }
$venvPython = Join-Path $venv "Scripts\python.exe"
& $venvPython -m pip install --disable-pip-version-check -r (Join-Path $InstallDirectory "requirements.txt")

$configPath = Join-Path $InstallDirectory "agent-config.json"
$logPath = Join-Path $InstallDirectory "logs\agent.log"
@{
    server_url = $ServerUrl.TrimEnd("/")
    token = $Token
    interval_seconds = $IntervalSeconds
    diagnostics_enabled = [bool]$EnableDiagnostics
} |
    ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $configPath /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" "${identity}:R" | Out-Null

& $venvPython (Join-Path $InstallDirectory "liims_agent.py") --once --log-file $logPath
if ($LASTEXITCODE -ne 0) { throw "The verification metric could not be submitted. Review $logPath before retrying." }
Write-Host "Verification passed: the first metric sample was accepted."

$actionArguments = ('"{0}" --log-file "{1}"' -f (Join-Path $InstallDirectory "liims_agent.py"), $logPath)
$action = New-ScheduledTaskAction -Execute $venvPython -Argument $actionArguments -WorkingDirectory $InstallDirectory
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $taskPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "LIIMS agent installed and started."
Write-Host "Server: $($ServerUrl.TrimEnd('/'))"
Write-Host "Task:   $taskName"
Write-Host "Log:    $logPath"
Write-Host "Remote diagnostics: $([bool]$EnableDiagnostics)"
