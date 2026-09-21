param(
    [ValidateRange(1024, 65535)][int]$Port = 8444
)

$ErrorActionPreference = "Stop"
$wiresharkProject = Split-Path -Parent $MyInvocation.MyCommand.Path
$wiresharkCompose = Join-Path $wiresharkProject "docker-compose.wireshark.yml"
$wiresharkSecret = Join-Path $wiresharkProject "secrets\wireshark_password.txt"
$wiresharkShortPasswordOptIn = Join-Path $wiresharkProject "secrets\wireshark_allow_short_password.txt"
$wiresharkContainer = "aegis-network-tools"
$wiresharkDockerBin = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin"
if (Test-Path -LiteralPath $wiresharkDockerBin) { $env:Path = "$wiresharkDockerBin;$env:Path" }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker CLI was not found." }
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { throw "curl.exe is required for the local HTTPS readiness check." }

$wiresharkPreviousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$wiresharkInspection = docker inspect $wiresharkContainer 2>$null
$wiresharkInspectExit = $LASTEXITCODE
$ErrorActionPreference = $wiresharkPreviousPreference
if ($wiresharkInspectExit -ne 0) { throw "Start the Aegis Docker toolbox before Wireshark. Run start-hybrid.ps1 or docker compose -f docker-compose.observability.yml up -d network-toolbox." }
$wiresharkToolbox = ($wiresharkInspection | ConvertFrom-Json)[0]
if (-not $wiresharkToolbox.State.Running) { throw "The Aegis toolbox is not running. Start it before Wireshark." }
$wiresharkNetworks = @($wiresharkToolbox.NetworkSettings.Networks.PSObject.Properties.Name)
if ($wiresharkNetworks.Count -ne 1 -or $wiresharkNetworks[0] -in "host", "none") { throw "The toolbox must have one Docker bridge network for the loopback TLS proxy." }

# Create a strong local credential once. Existing user credentials are never
# overwritten and no password is printed, embedded in URLs, or sent to logs.
if (-not (Test-Path -LiteralPath $wiresharkSecret)) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $wiresharkSecret) -Force | Out-Null
    $wiresharkRandomBytes = New-Object byte[] 24
    $wiresharkRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $wiresharkRng.GetBytes($wiresharkRandomBytes) } finally { $wiresharkRng.Dispose() }
    [System.IO.File]::WriteAllText($wiresharkSecret, [Convert]::ToBase64String($wiresharkRandomBytes), [System.Text.UTF8Encoding]::new($false))
}
$wiresharkPasswordLength = (Get-Content -Raw -LiteralPath $wiresharkSecret).Trim().Length
if ($wiresharkPasswordLength -eq 0) { throw "Wireshark's local password file is empty." }
if ($wiresharkPasswordLength -lt 20 -and -not (Test-Path -LiteralPath $wiresharkShortPasswordOptIn)) {
    throw "Wireshark's existing local password is too short. Set a password of at least 20 characters or create the ignored secrets/wireshark_allow_short_password.txt opt-in file."
}

$env:AEGIS_NETWORK_TOOLBOX_CONTAINER = $wiresharkContainer
$env:AEGIS_WIRESHARK_NETWORK = $wiresharkNetworks[0]
$env:AEGIS_WIRESHARK_PORT = "$Port"
docker compose -f $wiresharkCompose config --quiet
if ($LASTEXITCODE -ne 0) { throw "Wireshark Compose configuration is invalid." }

$ErrorActionPreference = "Continue"
$wiresharkExistingJson = docker inspect aegis-wireshark 2>$null
$wiresharkExistingExit = $LASTEXITCODE
$ErrorActionPreference = $wiresharkPreviousPreference
$wiresharkRecreate = $false
if ($wiresharkExistingExit -eq 0) {
    $wiresharkExisting = ($wiresharkExistingJson | ConvertFrom-Json)[0]
    $wiresharkRecreate = $wiresharkExisting.HostConfig.NetworkMode -ne "container:$($wiresharkToolbox.Id)"
    if ($wiresharkRecreate) { Write-Host "Reattaching Wireshark to the current toolbox. Saved PCAP files/settings are preserved; an unsaved GUI session may restart." }
}
$wiresharkArguments = @("compose", "-f", $wiresharkCompose, "up", "-d")
if ($wiresharkRecreate) { $wiresharkArguments += "--force-recreate" }
$wiresharkArguments += @("wireshark", "wireshark-proxy")
& docker @wiresharkArguments
if ($LASTEXITCODE -ne 0) { throw "Wireshark startup failed. Inspect docker compose -f docker-compose.wireshark.yml logs." }

$wiresharkDeadline = (Get-Date).AddSeconds(90)
$wiresharkReady = $false
do {
    # This is only a readiness probe of the explicitly local, self-signed GUI;
    # it sends no credentials and does not alter browser or Windows trust.
    $wiresharkCode = & curl.exe --insecure --silent --output NUL --write-out "%{http_code}" --max-time 3 "https://127.0.0.1:$Port/" 2>$null
    if ($wiresharkCode -eq "401") { $wiresharkReady = $true; break }
    if ($wiresharkCode -eq "200") { throw "Wireshark is responding without authentication. Check FILE__PASSWORD before use." }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $wiresharkDeadline)
if (-not $wiresharkReady) { throw "Wireshark HTTPS/authentication did not become ready. Inspect its Docker logs." }

docker exec --user abc aegis-wireshark sh -c 'mkdir -p /config/captures'
if ($LASTEXITCODE -ne 0) { throw "Wireshark's capture directory could not be initialized." }
Write-Host "Wireshark ready: https://127.0.0.1:$Port/"
Write-Host "  User: aegis"
Write-Host "  Password file (local only): $wiresharkSecret"
Write-Host "  Capture interface: eth0 (Aegis toolbox traffic, not Windows physical adapters)"
Write-Host "  Save PCAP/PCAPNG files under /config/captures"
