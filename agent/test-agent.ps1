[CmdletBinding()]
param(
    [string]$InstallDirectory = "$env:ProgramData\LIIMS Agent",
    [switch]$SubmitSample
)

$ErrorActionPreference = "Stop"
$python = Join-Path $InstallDirectory ".venv\Scripts\python.exe"
$agent = Join-Path $InstallDirectory "liims_agent.py"
$log = Join-Path $InstallDirectory "logs\agent.log"
if (-not (Test-Path -LiteralPath $python) -or -not (Test-Path -LiteralPath $agent)) {
    throw "The LIIMS agent is not installed in $InstallDirectory."
}

$mode = if ($SubmitSample) { "--once" } else { "--check" }
$arguments = @($agent, $mode, "--log-file", $log)
& $python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "LIIMS agent diagnostics failed with exit code $LASTEXITCODE. Review $log."
}
if ($SubmitSample) { Write-Host "Connectivity and authenticated metric submission succeeded." }
else { Write-Host "LIIMS agent ingress connectivity succeeded. Use -SubmitSample to test the token and metric submission." }
