$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$dockerBin = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin"
if (Test-Path $dockerBin) { $env:Path = "$dockerBin;$env:Path" }

foreach ($port in 8001, 8002, 5173) {
    $deadline = (Get-Date).AddSeconds(10)
    do {
        $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
        if ($listeners.Count -eq 0) { break }
        $listeners | Select-Object -ExpandProperty OwningProcess -Unique |
            ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        Write-Warning "Port $port is still occupied after 10 seconds."
    }
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
    docker compose -f (Join-Path $projectRoot "docker-compose.observability.yml") down
    if ($LASTEXITCODE -ne 0) { throw "Unable to stop Prometheus and Grafana cleanly." }
} else {
    Write-Warning "Docker Desktop is not running. Prometheus and Grafana were already unavailable."
}
Write-Host "Hybrid AEGIS stopped. Persistent data was preserved."
