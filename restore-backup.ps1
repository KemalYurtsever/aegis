param(
    [Parameter(Mandatory = $true)]
    [string]$BackupFile
)

$ErrorActionPreference = "Stop"
$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$backendRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "backend"))
$databasePath = [System.IO.Path]::GetFullPath((Join-Path $backendRoot "monitoring.db"))
$backupDirectory = [System.IO.Path]::GetFullPath((Join-Path $backendRoot "backups"))
$pythonPath = [System.IO.Path]::GetFullPath((Join-Path $backendRoot ".venv\Scripts\python.exe"))
$verifierPath = [System.IO.Path]::GetFullPath((Join-Path $backendRoot "tools\verify_sqlite_backup.py"))

$listener = Get-NetTCPConnection -LocalPort 8001 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    throw "AEGIS is still running on port 8001. Run .\stop-hybrid.ps1 before restoring a backup."
}
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw "Backend Python was not found at $pythonPath"
}
$resolvedBackup = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $BackupFile -ErrorAction Stop).Path)
if ([System.IO.Path]::GetExtension($resolvedBackup) -ne ".db") {
    throw "The selected backup must have a .db extension."
}
if ($resolvedBackup -eq $databasePath) {
    throw "Select a backup file, not the active monitoring database."
}

& $pythonPath $verifierPath $resolvedBackup
if ($LASTEXITCODE -ne 0) {
    throw "Backup verification failed. The active database was not changed."
}

New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$rollbackPath = Join-Path $backupDirectory "pre-restore-$timestamp.db"
$temporaryPath = Join-Path $backendRoot "monitoring.restore.pending"

try {
    if (Test-Path -LiteralPath $databasePath -PathType Leaf) {
        Copy-Item -LiteralPath $databasePath -Destination $rollbackPath -ErrorAction Stop
    }
    Copy-Item -LiteralPath $resolvedBackup -Destination $temporaryPath -ErrorAction Stop
    Move-Item -LiteralPath $temporaryPath -Destination $databasePath -Force -ErrorAction Stop
}
finally {
    if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

Write-Host "AEGIS database restored successfully."
Write-Host "Restored from: $resolvedBackup"
if (Test-Path -LiteralPath $rollbackPath -PathType Leaf) {
    Write-Host "Previous database preserved at: $rollbackPath"
}
Write-Host "Run .\start-hybrid.ps1 to start AEGIS."
