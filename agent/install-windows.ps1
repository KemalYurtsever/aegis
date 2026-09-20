[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [string]$Token,
    [ValidateRange(10, 3600)][int]$IntervalSeconds = 60,
    [switch]$EnableDiagnostics,
    [string]$InstallDirectory = "$env:ProgramData\AEGIS Agent"
)

$ErrorActionPreference = "Stop"
$taskName = "AEGIS Host Agent"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from PowerShell as Administrator."
}
. (Join-Path $PSScriptRoot 'install-security.ps1')
$server = [Uri]$ServerUrl
if ($server.Scheme -notin @("http", "https") -or -not $server.Host) { throw "ServerUrl must be an HTTP or HTTPS URL." }
if ($server.UserInfo -or $server.Query -or $server.Fragment) { throw "ServerUrl must not contain credentials, a query, or a fragment." }
$loopback = $server.Host -in @('localhost', 'localhost.')
$serverIp = $null
if ([Net.IPAddress]::TryParse($server.Host, [ref]$serverIp)) { $loopback = [Net.IPAddress]::IsLoopback($serverIp) }
if ($server.Scheme -eq 'http' -and -not $loopback) { throw "Remote ServerUrl must use HTTPS." }
if (-not $Token) {
    $secureToken = Read-Host "Paste the one-time AEGIS agent token" -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    try { $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}
if ($Token.Length -lt 20) { throw "The AEGIS agent token is missing or invalid." }

$healthUrl = "$($ServerUrl.TrimEnd('/'))/api/agent/health"
try {
    $health = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 10
} catch {
    throw "Cannot reach the AEGIS agent ingress at $healthUrl. Check the server address, port 8002, and Windows Firewall. $($_.Exception.Message)"
}
if ($health.status -ne "healthy") { throw "The AEGIS agent ingress did not report a healthy status." }
Write-Host "Preflight passed: AEGIS agent ingress is reachable."

$pythonLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
$pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pythonLauncher -and -not $pythonCommand) { throw "Python 3 is required. Install it, then rerun this script." }

$InstallDirectory = Initialize-AegisInstallDirectory -Path $InstallDirectory
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "aegis_agent.py") -Destination $InstallDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "requirements.txt") -Destination $InstallDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall-windows.ps1") -Destination $InstallDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "test-agent.ps1") -Destination $InstallDirectory -Force

$venv = Join-Path $InstallDirectory ".venv"
if ($pythonLauncher) { & $pythonLauncher.Source -3 -m venv $venv }
else { & $pythonCommand.Source -m venv $venv }
if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment creation failed.' }
$venvPython = Join-Path $venv "Scripts\python.exe"
& $venvPython -m pip install --disable-pip-version-check -r (Join-Path $InstallDirectory "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw 'Agent dependency installation failed.' }

$configPath = Join-Path $InstallDirectory "agent-config.json"
$logPath = Join-Path $InstallDirectory "logs\agent.log"
@{
    server_url = $ServerUrl.TrimEnd("/")
    token = $Token
    interval_seconds = $IntervalSeconds
    diagnostics_enabled = [bool]$EnableDiagnostics
} |
    ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
Set-Acl -LiteralPath $configPath -AclObject (Get-AegisProtectedAcl) -ErrorAction Stop
$null = Initialize-AegisInstallDirectory -Path $InstallDirectory

& $venvPython (Join-Path $InstallDirectory "aegis_agent.py") --once --log-file $logPath
if ($LASTEXITCODE -ne 0) { throw "The verification metric could not be submitted. Review $logPath before retrying." }
Write-Host "Verification passed: the first metric sample was accepted."

$actionArguments = ('"{0}" --log-file "{1}"' -f (Join-Path $InstallDirectory "aegis_agent.py"), $logPath)
$action = New-ScheduledTaskAction -Execute $venvPython -Argument $actionArguments -WorkingDirectory $InstallDirectory
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $taskPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "AEGIS agent installed and started."
Write-Host "Server: $($ServerUrl.TrimEnd('/'))"
Write-Host "Task:   $taskName"
Write-Host "Log:    $logPath"
Write-Host "Remote diagnostics: $([bool]$EnableDiagnostics)"
