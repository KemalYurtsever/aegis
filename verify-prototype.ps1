param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $projectRoot "backend"
$frontend = Join-Path $projectRoot "frontend"
$python = Join-Path $backend ".venv\Scripts\python.exe"
$tokenFile = Join-Path $projectRoot "secrets\prometheus_token.txt"
$dockerBin = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin"
if (Test-Path $dockerBin) { $env:Path = "$dockerBin;$env:Path" }

function Invoke-PrototypeCheck {
    param([string]$Name, [scriptblock]$Action)

    Write-Host "[RUN]  $Name"
    $started = Get-Date
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE."
    }
    $elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    Write-Host "[PASS] $Name ($elapsed s)" -ForegroundColor Green
}

if (-not (Test-Path -LiteralPath $python)) {
    throw "Backend virtual environment is missing. Follow README.md > Installation."
}
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    throw "npm.cmd was not found. Install Node.js 20.19 or newer."
}
if (-not (Test-Path -LiteralPath $tokenFile) -or -not (Get-Content -Raw -LiteralPath $tokenFile).Trim()) {
    throw "secrets\prometheus_token.txt is missing or empty. Follow README.md > Installation."
}

Push-Location $backend
try {
    Invoke-PrototypeCheck "Python dependency integrity" { & $python -m pip check }
    Invoke-PrototypeCheck "Python source compilation" { & $python -m compileall -q app (Join-Path $projectRoot "agent\aegis_agent.py") }
    if (Test-Path -LiteralPath (Join-Path $backend "monitoring.db")) {
        Invoke-PrototypeCheck "SQLite integrity" { & $python tools\verify_sqlite_backup.py monitoring.db }
    } else {
        Write-Host "[SKIP] SQLite integrity (the database will be created on first launch)" -ForegroundColor Yellow
    }
    if (-not $SkipTests) {
        Invoke-PrototypeCheck "Backend test suite" { & $python -m pytest }
    }
} finally {
    Pop-Location
}

Push-Location $frontend
try {
    Invoke-PrototypeCheck "Frontend dependency tree" { & npm.cmd ls --depth=0 }
    Invoke-PrototypeCheck "Frontend tests and production build" { & npm.cmd run check }
} finally {
    Pop-Location
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI was not found. Install or repair Docker Desktop."
}
Invoke-PrototypeCheck "Full-stack Compose configuration" { & docker compose -f (Join-Path $projectRoot "docker-compose.yml") config --quiet }
Invoke-PrototypeCheck "Hybrid Compose configuration" { & docker compose -f (Join-Path $projectRoot "docker-compose.observability.yml") config --quiet }
if (Test-Path -LiteralPath (Join-Path $projectRoot "secrets\wireshark_password.txt")) {
    Invoke-PrototypeCheck "Optional Wireshark Compose configuration" { & docker compose -f (Join-Path $projectRoot "docker-compose.wireshark.yml") config --quiet }
}

$previousErrorPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& docker info *> $null
$dockerAvailable = $LASTEXITCODE -eq 0
$ErrorActionPreference = $previousErrorPreference
if (-not $dockerAvailable) {
    throw "Docker Desktop is installed but its daemon is not running."
}
Write-Host "[PASS] Docker daemon" -ForegroundColor Green
Write-Host "Prototype readiness checks passed." -ForegroundColor Cyan
