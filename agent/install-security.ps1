# Shared with the standalone ACL verifier; never execute retained writable code.
$script:AegisTrustedOwners = @(
    'S-1-5-18', 'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)
$installIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$installPrincipal = [Security.Principal.WindowsPrincipal]::new($installIdentity)
if ($installPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $script:AegisTrustedOwners += $installIdentity.User.Value
}

function Assert-AegisAcl {
    param([Security.AccessControl.FileSystemSecurity]$Acl, [string]$Path, [switch]$Ancestor)
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $script:AegisTrustedOwners) { throw "Untrusted installation owner: $Path" }
    $rights = [Security.AccessControl.FileSystemRights]
    $unsafe = [int64]($rights::Delete -bor $rights::DeleteSubdirectoriesAndFiles -bor $rights::ChangePermissions -bor $rights::TakeOwnership)
    if (-not $Ancestor) {
        $unsafe = $unsafe -bor [int64]($rights::WriteData -bor $rights::AppendData -bor $rights::WriteAttributes -bor $rights::WriteExtendedAttributes)
    }
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        # Generic write/all are possible on raw security descriptors too.
        $mask = [int64]$rule.FileSystemRights
        $genericUnsafe = ($mask -band 0x10000000) -or (-not $Ancestor -and ($mask -band 0x40000000))
        if ($rule.IdentityReference.Value -notin $script:AegisTrustedOwners -and (($mask -band $unsafe) -or $genericUnsafe)) {
            throw "Unprivileged write or replacement access on installation path: $Path"
        }
    }
}

function Assert-AegisPath {
    param([string]$Path, [switch]$Ancestor)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Installation reparse points are not allowed: $Path" }
    Assert-AegisAcl -Acl (Get-Acl -LiteralPath $Path -ErrorAction Stop) -Path $Path -Ancestor:$Ancestor
}

function Get-AegisProtectedAcl {
    param([switch]$Directory)
    if ($Directory) { $acl = [Security.AccessControl.DirectorySecurity]::new() }
    else { $acl = [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        if ($Directory) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow')
        } else {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow')
        }
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Initialize-AegisInstallDirectory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'InstallDirectory must be an absolute local path.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':') -or $full.Length -le 3) {
        throw 'InstallDirectory must be a non-root local drive directory, not UNC or an alternate stream.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne 'Fixed' -or $drive.DriveFormat -ne 'NTFS') { throw 'Installation requires a local fixed NTFS drive.' }
    $parent = [IO.Directory]::GetParent($full)
    if (-not $parent.Exists) { throw 'Create the parent directory securely before installing the agent.' }
    for ($ancestor = $parent; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
        Assert-AegisPath -Path $ancestor.FullName -Ancestor
    }
    if (-not (Test-Path -LiteralPath $full)) {
        # Supply the protected descriptor at creation, not after an insecure
        # mkdir. If another principal won creation, the verification rejects it.
        $directory = [IO.DirectoryInfo]::new($full)
        $acl = Get-AegisProtectedAcl -Directory
        if ($PSVersionTable.PSEdition -eq 'Core') { [IO.FileSystemAclExtensions]::Create($directory, $acl) }
        else { $directory.Create($acl) }
    }
    if (-not (Get-Item -LiteralPath $full -Force).PSIsContainer) { throw 'InstallDirectory is not a directory.' }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($full)
    $verified = [Collections.Generic.List[string]]::new()
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        Assert-AegisPath -Path $current
        $verified.Add($current)
        if ((Get-Item -LiteralPath $current -Force).PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop) { $pending.Push($child.FullName) }
        }
    }
    # Do not repair and execute an untrusted tree: all entries passed above.
    foreach ($current in $verified) {
        $directory = (Get-Item -LiteralPath $current -Force).PSIsContainer
        Set-Acl -LiteralPath $current -AclObject (Get-AegisProtectedAcl -Directory:$directory) -ErrorAction Stop
        Assert-AegisPath -Path $current
    }
    return $full
}
