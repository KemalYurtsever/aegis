param(
    [ValidateRange(1024, 65535)][int]$Port = 8444
)

$ErrorActionPreference = "Stop"
$wiresharkProject = Split-Path -Parent $MyInvocation.MyCommand.Path
$wiresharkSecret = Join-Path $wiresharkProject "secrets\wireshark_password.txt"
$wiresharkDockerBin = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin"
if (Test-Path -LiteralPath $wiresharkDockerBin) { $env:Path = "$wiresharkDockerBin;$env:Path" }
if (-not (Test-Path -LiteralPath $wiresharkSecret)) { throw "Run start-wireshark.ps1 first." }

$wiresharkToolbox = (docker inspect aegis-network-tools | ConvertFrom-Json)[0]
if ($LASTEXITCODE -ne 0) { throw "Toolbox inspection failed." }
$wiresharkGui = (docker inspect aegis-wireshark | ConvertFrom-Json)[0]
if ($LASTEXITCODE -ne 0) { throw "Wireshark inspection failed." }
$wiresharkProxy = (docker inspect aegis-wireshark-proxy | ConvertFrom-Json)[0]
if ($LASTEXITCODE -ne 0) { throw "Proxy inspection failed." }
if ($wiresharkGui.HostConfig.NetworkMode -ne "container:$($wiresharkToolbox.Id)") { throw "Wireshark is attached to an outdated toolbox. Rerun start-wireshark.ps1." }
if ($wiresharkGui.State.Health.Status -ne "healthy") { throw "Wireshark is not healthy." }
$wiresharkBindings = @($wiresharkProxy.HostConfig.PortBindings.'8444/tcp')
if ($wiresharkBindings.Count -ne 1 -or $wiresharkBindings[0].HostIp -ne "127.0.0.1" -or $wiresharkBindings[0].HostPort -ne "$Port") { throw "The Wireshark proxy must publish only the configured loopback port." }
Write-Host "[PASS] Current toolbox namespace, GUI health and loopback publishing"

function Test-WiresharkStatus {
    param([string]$Credential, [string]$Expected)

    # Supply Basic authentication through stdin, never the URL or process
    # arguments. No redirects are followed, and only loopback is contacted.
    $wiresharkCurlConfiguration = if ($Credential) {
        'user = "' + $Credential.Replace('\', '\\').Replace('"', '\"') + '"'
    } else { '# no authentication' }
    $wiresharkStatus = $wiresharkCurlConfiguration | & curl.exe --config - --insecure --silent --output NUL --write-out "%{http_code}" --max-time 5 "https://127.0.0.1:$Port/"
    if ($LASTEXITCODE -ne 0 -or $wiresharkStatus -ne $Expected) { throw "Wireshark HTTPS returned $wiresharkStatus; expected $Expected." }
}

$wiresharkPassword = (Get-Content -Raw -LiteralPath $wiresharkSecret).Trim()
if ($wiresharkPassword -match '[\r\n]') { throw "The local Wireshark password must be one line." }
try {
    Test-WiresharkStatus -Expected "401"
    Test-WiresharkStatus -Credential "aegis:$wiresharkPassword" -Expected "200"
    Write-Host "[PASS] HTTPS denies anonymous access and accepts the local credential"
} finally {
    $wiresharkPassword = $null
}
docker exec aegis-wireshark-proxy nginx -t
if ($LASTEXITCODE -ne 0) { throw "Proxy configuration is invalid." }
docker exec --user abc aegis-wireshark dumpcap -D
if ($LASTEXITCODE -ne 0) { throw "The Wireshark capture user cannot list interfaces." }
Write-Host "Wireshark checks passed. This check starts no packet capture and changes no browser/Windows certificate trust."
