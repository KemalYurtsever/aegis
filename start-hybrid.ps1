$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$dockerBin = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin"
if (Test-Path $dockerBin) { $env:Path = "$dockerBin;$env:Path" }

$tokenFile = Join-Path $projectRoot "secrets\prometheus_token.txt"
if (-not (Test-Path $tokenFile)) { throw "Missing secrets\prometheus_token.txt" }
if (-not (Get-Content -Raw -LiteralPath $tokenFile).Trim()) { throw "secrets\prometheus_token.txt is empty" }

$logDirectory = Join-Path $projectRoot "logs"
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

function Wait-HttpEndpoint {
    param([string]$Name, [string]$Url, [int]$TimeoutSeconds = 45)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 4
            if ($response.StatusCode -eq 200) { return }
        } catch { }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "$Name did not become ready at $Url. Review the logs in $logDirectory."
}

function Remove-StaleComposeContainers {
    param([string]$WorkingDirectory)

    $containerIds = @(docker ps -aq --filter "label=com.docker.compose.project.working_dir=$WorkingDirectory")
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect existing Docker containers." }
    if ($containerIds.Count -eq 0) { return }

    Write-Host "Removing $($containerIds.Count) stale container(s) created from this Aegis directory. Docker volumes will be preserved."
    docker rm -f $containerIds | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to remove stale Aegis containers." }
}

function Assert-PortAvailable {
    param([int]$Port, [string]$Service)

    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) { return }

    $containerNames = @(docker ps --filter "publish=$Port" --format "{{.Names}}")
    $owner = if ($containerNames.Count -gt 0) {
        "Docker container(s): $($containerNames -join ', ')"
    } else {
        $processIds = $listeners | Select-Object -ExpandProperty OwningProcess -Unique
        "process ID(s): $($processIds -join ', ')"
    }
    throw "$Service cannot start because 127.0.0.1:$Port is already in use by $owner. Stop that workload or change its published port, then run start-hybrid.ps1 again."
}

$dockerAvailable = $false
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $previousErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    docker info 2>&1 | Out-Null
    $dockerAvailable = $LASTEXITCODE -eq 0
    $ErrorActionPreference = $previousErrorPreference
}
if ($dockerAvailable) {
    docker compose -f (Join-Path $projectRoot "docker-compose.yml") down
    if ($LASTEXITCODE -ne 0) { throw "Unable to stop the fully containerized stack." }
    Remove-StaleComposeContainers -WorkingDirectory $projectRoot
    Assert-PortAvailable -Port 9090 -Service "Prometheus"
    Assert-PortAvailable -Port 3000 -Service "Grafana"
    docker compose -f (Join-Path $projectRoot "docker-compose.observability.yml") up -d --build
    if ($LASTEXITCODE -ne 0) { throw "Unable to start the network toolbox, Prometheus, and Grafana." }
} else {
    Write-Warning "Docker Desktop is not running. Starting core AEGIS without the network toolbox, Prometheus, or Grafana."
}

$backend = Join-Path $projectRoot "backend"
$frontend = Join-Path $projectRoot "frontend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) { throw "Backend virtual environment is missing: $python" }
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) { throw "npm.cmd was not found. Install Node.js before starting AEGIS." }
$backendPort = 8001
$agentPort = 8002
$env:AEGIS_PROMETHEUS_TOKEN_FILE = $tokenFile
$networkToolbox = "aegis-network-tools"
if ($dockerAvailable) {
    $env:AEGIS_NETWORK_TOOLBOX_CONTAINER = $networkToolbox
} else {
    Remove-Item Env:AEGIS_NETWORK_TOOLBOX_CONTAINER -ErrorAction SilentlyContinue
}
# Permit discovery on the directly connected physical /24 when DHCP uses an
# address outside the private ranges.
$env:AEGIS_ALLOW_PUBLIC_LAN_DISCOVERY = "true"
$env:VITE_API_BASE_URL = "http://127.0.0.1:$backendPort"

if (-not (Get-NetTCPConnection -LocalPort $backendPort -State Listen -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$backendPort") -WorkingDirectory $backend -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDirectory "backend.out.log") -RedirectStandardError (Join-Path $logDirectory "backend.err.log")
}
if (-not (Get-NetTCPConnection -LocalPort $agentPort -State Listen -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "app.agent_main:app", "--host", "0.0.0.0", "--port", "$agentPort") -WorkingDirectory $backend -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDirectory "agent-ingress.out.log") -RedirectStandardError (Join-Path $logDirectory "agent-ingress.err.log")
}
if (-not (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath "npm.cmd" -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1") -WorkingDirectory $frontend -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDirectory "frontend.out.log") -RedirectStandardError (Join-Path $logDirectory "frontend.err.log")
}

Wait-HttpEndpoint -Name "AEGIS frontend" -Url "http://127.0.0.1:5173/"
Wait-HttpEndpoint -Name "AEGIS API" -Url "http://127.0.0.1:$backendPort/api/health"
Wait-HttpEndpoint -Name "AEGIS agent ingress" -Url "http://127.0.0.1:$agentPort/api/agent/health"
if ($dockerAvailable) {
    $toolboxRunning = docker inspect -f "{{.State.Running}}" $networkToolbox 2>$null
    if ($LASTEXITCODE -ne 0 -or $toolboxRunning -ne "true") { throw "The AEGIS network toolbox container is not running." }
    Wait-HttpEndpoint -Name "Grafana" -Url "http://127.0.0.1:3000/api/health"
    Wait-HttpEndpoint -Name "Prometheus" -Url "http://127.0.0.1:9090/-/ready"
}

Write-Host "Hybrid AEGIS started:"
Write-Host "  AEGIS:      http://127.0.0.1:5173"
Write-Host "  API:        http://127.0.0.1:$backendPort/docs"
Write-Host "  Agents:     http://<this-PC-LAN-IP>:$agentPort/api/agent/health"
if ($dockerAvailable) {
    Write-Host "  Net tools:  Docker container $networkToolbox"
    Write-Host "  Grafana:    http://127.0.0.1:3000"
    Write-Host "  Prometheus: http://127.0.0.1:9090"
} else {
    Write-Host "  Net tools:  local Windows fallbacks only"
    Write-Host "  Grafana:    skipped (Docker Desktop is not running)"
    Write-Host "  Prometheus: skipped (Docker Desktop is not running)"
}
Write-Host "  Logs:       $logDirectory"
Write-Host "All AEGIS services passed readiness checks."
if (-not (Get-NetFirewallRule -DisplayName "AEGIS Agent Ingress" -ErrorAction SilentlyContinue)) {
    Write-Warning "Agent firewall access is not configured. Run .\configure-agent-access.ps1 once as Administrator."
}
