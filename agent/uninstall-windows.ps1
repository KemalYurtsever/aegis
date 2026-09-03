[CmdletBinding()]
param([string]$InstallDirectory = "$env:ProgramData\AEGIS Agent")

$ErrorActionPreference = "Stop"
$taskName = "AEGIS Host Agent"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from PowerShell as Administrator."
}

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
if (Test-Path -LiteralPath $InstallDirectory) {
    $resolved = [IO.Path]::GetFullPath($InstallDirectory)
    $programData = [IO.Path]::GetFullPath($env:ProgramData)
    if (-not $resolved.StartsWith($programData, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove an install directory outside ProgramData: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Host "AEGIS agent was removed."
