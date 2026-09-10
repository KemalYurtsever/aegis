[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ruleName = "AEGIS Agent Ingress"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from PowerShell as Administrator."
}

$rules = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) {
    Write-Host "No legacy $ruleName firewall rule exists."
    return
}
$rules | Remove-NetFirewallRule
Write-Host "Removed the legacy $ruleName firewall rule."
