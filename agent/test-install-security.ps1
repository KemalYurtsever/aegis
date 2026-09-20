[CmdletBinding()]
param([switch]$Privileged)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'install-security.ps1')
$checks = 0
function Assert-Rejected {
    param([scriptblock]$Action)
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe installation fixture was accepted.' }
    $script:checks++
}
function Descriptor {
    param([string]$Sddl)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    return $acl
}
$safe = Descriptor 'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FRFX;;;BU)'
Assert-AegisAcl -Acl $safe -Path 'synthetic-protected-tree'
$checks++
$nullDacl = Descriptor 'O:SYG:SY'
Assert-Rejected { Assert-AegisAcl -Acl $nullDacl -Path 'synthetic-null-dacl' }
foreach ($mask in @('0x1f01ff','0x120116','0x2','0x4','0x40','0x10000','0x40000','0x80000','0x10000000','0x40000000')) {
    $unsafe = Descriptor "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;$mask;;;BU)"
    Assert-Rejected { Assert-AegisAcl -Acl $unsafe -Path 'synthetic-writable-tree' }
}
$untrustedOwner = Descriptor 'O:BUG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
Assert-Rejected { Assert-AegisAcl -Acl $untrustedOwner -Path 'synthetic-untrusted-owner' }
$replaceable = Descriptor 'O:SYG:SYD:P(A;;0x40;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
Assert-Rejected { Assert-AegisAcl -Acl $replaceable -Path 'synthetic-replaceable-parent' -Ancestor }
# Standard parent create-child rights are permitted; the new child is created
# atomically protected or an existing attacker-owned child is rejected.
Assert-AegisPath -Path $env:ProgramData -Ancestor
Assert-AegisPath -Path $env:ProgramFiles -Ancestor
$checks += 2
Assert-Rejected { Initialize-AegisInstallDirectory -Path 'relative-install' }
Assert-Rejected { Initialize-AegisInstallDirectory -Path 'C:\' }
Assert-Rejected { Initialize-AegisInstallDirectory -Path '\\localhost\share\agent' }

if ($Privileged) {
    if (-not $installPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Privileged filesystem checks require PowerShell as Administrator.'
    }
    $fixtureRoot = Join-Path $env:ProgramData ('AEGIS-install-test-' + [Guid]::NewGuid().ToString('N'))
    $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
    $expectedPrefix = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\AEGIS-install-test-'
    if (-not $resolvedFixture.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture path.' }
    try {
        $null = Initialize-AegisInstallDirectory -Path $resolvedFixture
        $code = Join-Path $resolvedFixture 'synthetic-code.txt'
        'Non-executable fixture' | Set-Content -LiteralPath $code
        $null = Initialize-AegisInstallDirectory -Path $resolvedFixture
        Assert-AegisPath -Path $code
        $checks += 2
        $acl = Get-Acl -LiteralPath $code
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Modify', 'Allow'))
        Set-Acl -LiteralPath $code -AclObject $acl
        Assert-Rejected { Initialize-AegisInstallDirectory -Path $resolvedFixture }
        Set-Acl -LiteralPath $code -AclObject (Get-AegisProtectedAcl)
        $target = Join-Path $resolvedFixture 'target'
        New-Item -ItemType Directory -Path $target | Out-Null
        $link = Join-Path $resolvedFixture 'link'
        New-Item -ItemType Junction -Path $link -Target $target | Out-Null
        Assert-Rejected { Initialize-AegisInstallDirectory -Path $resolvedFixture }
        [IO.Directory]::Delete($link) # Remove only the junction, not its target.
    } finally {
        if (Test-Path -LiteralPath $resolvedFixture) { Remove-Item -LiteralPath $resolvedFixture -Recurse -Force }
    }
}
Write-Output "PASS: $checks installer security checks; privileged filesystem checks=$([bool]$Privileged). No agent/task installed."
