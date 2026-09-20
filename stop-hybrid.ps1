$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$dockerBin = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin"
if (Test-Path $dockerBin) { $env:Path = "$dockerBin;$env:Path" }

function Remove-StaleComposeContainers {
    param([string]$WorkingDirectory)

    $containerIds = @(docker ps -aq --filter "label=com.docker.compose.project.working_dir=$WorkingDirectory")
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect existing Docker containers." }
    if ($containerIds.Count -eq 0) { return }

    Write-Host "Removing $($containerIds.Count) stale container(s) created from this Aegis directory. Docker volumes will be preserved."
    docker rm -f $containerIds | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to remove stale Aegis containers." }
}

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
    # Release the optional GUI's shared namespace/proxy network attachment
    # before bringing down its toolbox. No named volumes are deleted.
    $wiresharkIds = @(docker ps -aq --filter "label=aegis.wireshark.managed=true" --filter "label=com.docker.compose.project.working_dir=$projectRoot")
    if ($LASTEXITCODE -ne 0) { throw "Unable to inspect optional Wireshark containers." }
    if ($wiresharkIds.Count -gt 0) {
        docker rm -f $wiresharkIds | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to stop optional Wireshark containers." }
        Write-Host "Wireshark stopped. Saved PCAP files and settings were preserved in its Docker volume."
    }
    docker compose -f (Join-Path $projectRoot "docker-compose.observability.yml") down
    if ($LASTEXITCODE -ne 0) { throw "Unable to stop the network toolbox, Prometheus, and Grafana cleanly." }
    Remove-StaleComposeContainers -WorkingDirectory $projectRoot
} else {
    Write-Warning "Docker Desktop is not running. The network toolbox, Prometheus, and Grafana were already unavailable."
}
Write-Host "Hybrid AEGIS stopped. Persistent data was preserved."
