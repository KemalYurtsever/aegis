$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $projectRoot "backend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
$tokenFile = Join-Path $projectRoot "secrets\prometheus_token.txt"

$pids = netstat -ano -p tcp |
    Select-String '^\s*TCP\s+127\.0\.0\.1:8000\s+\S+\s+LISTENING\s+(\d+)\s*$' |
    ForEach-Object { [int]$_.Matches[0].Groups[1].Value } |
    Sort-Object -Unique
foreach ($processId in $pids) {
    Stop-Process -Id $processId -Force -ErrorAction Stop
}

$deadline = (Get-Date).AddSeconds(10)
while ((Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 200
}
if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) {
    throw "Port 8000 is still occupied after stopping the previous backend."
}

$env:LIIMS_PROMETHEUS_TOKEN_FILE = $tokenFile
$env:LIIMS_ALLOW_PUBLIC_LAN_DISCOVERY = "true"
Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000") -WorkingDirectory $backend -WindowStyle Hidden

$deadline = (Get-Date).AddSeconds(15)
while (-not (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 250
}
if (-not (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue)) {
    throw "The replacement backend did not start on port 8000."
}
