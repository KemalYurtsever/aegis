[CmdletBinding()]
param(
    [string]$AuthorizedSubnet,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$ruleName = "AEGIS Agent Ingress"
$agentPort = 8002
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from PowerShell as Administrator."
}

Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) {
    Write-Host "Removed the $ruleName firewall rule."
    return
}

if (-not $AuthorizedSubnet) {
    $candidate = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
        Sort-Object RouteMetric, InterfaceMetric |
        ForEach-Object {
            $route = $_
            $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
            $address = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike "169.254.*" } |
                Select-Object -First 1
            if ($adapter -and $address -and $adapter.Status -eq "Up" -and
                "$($adapter.Name) $($adapter.InterfaceDescription)" -notmatch "VPN|Tunnel|Mullvad|WireGuard|Hyper-V|VirtualBox|VMware|Loopback|vEthernet") {
                [PSCustomObject]@{ Address = $address.IPAddress; PrefixLength = $address.PrefixLength }
            }
        } | Select-Object -First 1
    if (-not $candidate) { throw "Unable to identify an active physical IPv4 adapter." }

    $bytes = [Net.IPAddress]::Parse($candidate.Address).GetAddressBytes()
    $prefix = [int]$candidate.PrefixLength
    for ($index = 0; $index -lt 4; $index++) {
        $remaining = $prefix - ($index * 8)
        $mask = if ($remaining -ge 8) { 255 } elseif ($remaining -le 0) { 0 } else { (256 - [math]::Pow(2, 8 - $remaining)) }
        $bytes[$index] = $bytes[$index] -band [int]$mask
    }
    $AuthorizedSubnet = "$([Net.IPAddress]::new($bytes).ToString())/$prefix"
}

New-NetFirewallRule `
    -DisplayName $ruleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort $agentPort `
    -RemoteAddress $AuthorizedSubnet `
    -Profile Any | Out-Null

Write-Host "AEGIS agent ingress is allowed from $AuthorizedSubnet on TCP $agentPort only."
