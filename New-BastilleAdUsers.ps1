# Version: 2.0
# Requires: Run as Administrator on a domain controller (ActiveDirectory + ADFS modules)
# Purpose: Create the Bastille OU/group/user structure and bind ADFS Web API
#          applications to the appropriate access-control groups.
# Notes:   Idempotent - re-running skips objects that already exist. ADFS access
#          control policies are applied using resolved group SIDs (the value the
#          "Permit specific group" policy expects), not bare group names.
# Examples:
#   .\New-BastilleAdUsers.ps1
#   .\New-BastilleAdUsers.ps1 -UserPassword (Read-Host "Sample user password" -AsSecureString)
#   .\New-BastilleAdUsers.ps1 -SkipAdfs        (AD objects only, no app binding)

[CmdletBinding()]
param(
    # Password for the sample BN Viewer / BN Ops accounts. Defaults to the
    # historical lab password if not supplied. Prefer passing a SecureString.
    [object]$UserPassword = "bastille#123",

    # Skip binding the ADFS Web API access control policies.
    [switch]$SkipAdfs,

    # Skip creating the sample BN Viewer / BN Ops users (still creates OUs/groups).
    [switch]$SkipUsers
)

$ErrorActionPreference = 'Stop'

# --- Helpers ---

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Ou {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    # -Identity throws a terminating ADIdentityNotFoundException when the OU is
    # absent, which -ErrorAction SilentlyContinue does not suppress; catch it.
    $existing = $null
    try { $existing = Get-ADOrganizationalUnit -Identity $dn -ErrorAction Stop } catch { $existing = $null }
    if ($existing) {
        Write-Host "  [=] OU exists: $dn" -ForegroundColor DarkGray
    }
    else {
        New-ADOrganizationalUnit -Name $Name -Path $Path | Out-Null
        Write-Host "  [+] OU created: $dn" -ForegroundColor Green
    }
    return $dn
}

function Ensure-Group {
    param([string]$Name, [string]$Path)
    $existing = Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [=] Group exists: $Name" -ForegroundColor DarkGray
        return $existing
    }
    $g = New-ADGroup -GroupScope Global -Name $Name -Path $Path -PassThru
    Write-Host "  [+] Group created: $Name" -ForegroundColor Green
    return $g
}

function Ensure-User {
    param(
        [string]$Name,
        [string]$GivenName,
        [string]$Surname,
        [string]$SamAccountName,
        [string]$Upn,
        [securestring]$Password,
        [string]$Path
    )
    $existing = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [=] User exists: $Name ($SamAccountName)" -ForegroundColor DarkGray
        return $existing
    }
    $u = New-ADUser -Name $Name -GivenName $GivenName -Surname $Surname `
        -SamAccountName $SamAccountName -UserPrincipalName $Upn `
        -AccountPassword $Password -PasswordNeverExpires $true -Enabled $true `
        -Path $Path -PassThru
    Write-Host "  [+] User created: $Name ($SamAccountName)" -ForegroundColor Green
    return $u
}

function Resolve-User {
    param([string]$Member)
    # Accept a SamAccountName, display Name, or DN/SID/GUID. -Identity does not
    # resolve display names, so fall back to a filtered lookup on either field.
    try { return Get-ADUser -Identity $Member -ErrorAction Stop } catch {}
    $u = Get-ADUser -Filter "SamAccountName -eq '$Member' -or Name -eq '$Member'" -ErrorAction SilentlyContinue
    return $u
}

function Ensure-UserInOu {
    param([string]$Member, [string]$TargetOu)
    # Move a user into $TargetOu for organizational tidiness. OU placement does
    # not affect ADFS access (group membership does) - this is cosmetic. Skips
    # if the account is missing or already in the target OU.
    $u = Resolve-User -Member $Member
    if (-not $u) {
        Write-Warning "  '$Member' not found - cannot move to '$TargetOu'. Skipped."
        return
    }
    $currentParent = ($u.DistinguishedName -split ',', 2)[1]
    if ($currentParent -eq $TargetOu) {
        Write-Host "  [=] $($u.SamAccountName) already in $TargetOu" -ForegroundColor DarkGray
    }
    else {
        Move-ADObject -Identity $u.DistinguishedName -TargetPath $TargetOu
        Write-Host "  [+] $($u.SamAccountName) moved to $TargetOu" -ForegroundColor Green
    }
}

function Ensure-Member {
    param([string]$GroupName, [string]$Member)
    $resolved = Resolve-User -Member $Member
    if (-not $resolved) {
        Write-Warning "  Member '$Member' not found - cannot add to '$GroupName'. Skipped."
        return
    }
    $current = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $resolved.SID }
    if ($current) {
        Write-Host "  [=] $($resolved.SamAccountName) already in $GroupName" -ForegroundColor DarkGray
    }
    else {
        Add-ADGroupMember -Identity $GroupName -Members $resolved
        Write-Host "  [+] $($resolved.SamAccountName) added to $GroupName" -ForegroundColor Green
    }
}

function Resolve-GroupSid {
    param([string]$GroupName)
    $g = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if ($g) { return $g.SID.Value }
    Write-Warning "  Could not resolve SID for group '$GroupName'."
    return $null
}

function ConvertTo-Secure {
    param([object]$Value)
    if ($Value -is [securestring]) { return $Value }
    return (ConvertTo-SecureString ([string]$Value) -AsPlainText -Force)
}

# --- Main ---

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory module (RSAT-AD-PowerShell) is required."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$DomainDN     = (Get-ADDomain).DistinguishedName
$DomainForest = (Get-ADDomain).Forest

Write-Host ""
Write-Host "Domain : $DomainDN" -ForegroundColor Cyan
Write-Host "Forest : $DomainForest" -ForegroundColor Cyan

# 1. OU tree -----------------------------------------------------------------
Write-Host ""
Write-Host "Creating OU structure..." -ForegroundColor Cyan
$ouBastille  = Ensure-Ou -Name "Bastille"  -Path $DomainDN
$ouGroups    = Ensure-Ou -Name "Groups"    -Path $ouBastille
$ouUsers     = Ensure-Ou -Name "Users"     -Path $ouBastille
$ouAdmins    = Ensure-Ou -Name "Admins"    -Path $ouUsers
$ouOperators = Ensure-Ou -Name "Operators" -Path $ouUsers
$ouViewers   = Ensure-Ou -Name "Viewers"   -Path $ouUsers

# 2. Security groups ---------------------------------------------------------
Write-Host ""
Write-Host "Creating security groups..." -ForegroundColor Cyan
$groupNames = @('BNAdmin', 'DVROps', 'DVRViewer', 'ADAMOps', 'ADAMViewer')
foreach ($name in $groupNames) { Ensure-Group -Name $name -Path $ouGroups | Out-Null }

# 3. Pre-existing admin account membership -----------------------------------
Write-Host ""
Write-Host "Assigning administrator membership..." -ForegroundColor Cyan
# The 'BN Test' account is created elsewhere (Install-ADFS-pfx-From_Scratch.ps1
# -CreateTestUsers, or by hand), not here. Its SamAccountName varies by
# environment ('bntest' from the installer, 'BN Test' when created via the GUI),
# so match on the display Name, which is consistent. Resolve-User falls back to a
# Name filter; warn (don't fail) if the account is missing.
Ensure-Member -GroupName "BNAdmin" -Member "BN Test"
# Keep the admin account organized under the Admins OU (cosmetic; does not
# affect ADFS access, which is governed by BNAdmin membership above).
Ensure-UserInOu -Member "BN Test" -TargetOu $ouAdmins

# 4. Sample users ------------------------------------------------------------
if (-not $SkipUsers) {
    Write-Host ""
    Write-Host "Creating sample users..." -ForegroundColor Cyan
    $securePassword = ConvertTo-Secure -Value $UserPassword

    Ensure-User -Name "BN Viewer" -GivenName "BN" -Surname "Viewer" `
        -SamAccountName "bn-viewer" -Upn "bn-viewer@$DomainForest" `
        -Password $securePassword -Path $ouViewers | Out-Null

    Ensure-User -Name "BN Ops" -GivenName "BN" -Surname "Ops" `
        -SamAccountName "bn-ops" -Upn "bn-ops@$DomainForest" `
        -Password $securePassword -Path $ouOperators | Out-Null

    Write-Host ""
    Write-Host "Assigning sample-user memberships..." -ForegroundColor Cyan
    Ensure-Member -GroupName "DVRViewer"  -Member "bn-viewer"
    Ensure-Member -GroupName "ADAMViewer" -Member "bn-viewer"
    Ensure-Member -GroupName "DVROps"     -Member "bn-ops"
    Ensure-Member -GroupName "ADAMOps"    -Member "bn-ops"
}
else {
    Write-Host ""
    Write-Host "Skipping sample users (-SkipUsers)." -ForegroundColor Yellow
}

# 5. ADFS Web API access control policies ------------------------------------
if (-not $SkipAdfs) {
    Write-Host ""
    Write-Host "Binding ADFS Web API access control policies..." -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ADFS)) {
        Write-Warning "ADFS module not available - skipping Web API policy binding. Re-run on an ADFS node, or use -SkipAdfs to silence this."
    }
    else {
        Import-Module ADFS -ErrorAction Stop

        $appPolicies = @(
            [PSCustomObject]@{ TargetName = 'Bastille Admin - Web application';          Groups = @('BNAdmin') },
            [PSCustomObject]@{ TargetName = 'Bastille DVR and Device - Web application'; Groups = @('BNAdmin', 'DVROps', 'DVRViewer') },
            [PSCustomObject]@{ TargetName = 'Bastille Lighthouse - Web application';     Groups = @('BNAdmin', 'ADAMOps', 'ADAMViewer') }
        )

        foreach ($app in $appPolicies) {
            $target = Get-AdfsWebApiApplication -Name $app.TargetName -ErrorAction SilentlyContinue
            if (-not $target) {
                Write-Warning "  Web API application not found: '$($app.TargetName)' - skipped. (Register it in ADFS first.)"
                continue
            }

            $sids = @()
            foreach ($g in $app.Groups) {
                $sid = Resolve-GroupSid -GroupName $g
                if ($sid) { $sids += $sid }
            }
            if ($sids.Count -eq 0) {
                Write-Warning "  No group SIDs resolved for '$($app.TargetName)' - skipped."
                continue
            }

            Set-AdfsWebApiApplication -TargetName $app.TargetName `
                -AccessControlPolicyName "Permit specific group" `
                -AccessControlPolicyParameters @{ GroupParameter = $sids }
            Write-Host "  [+] $($app.TargetName) -> $($app.Groups -join ', ')" -ForegroundColor Green
        }
    }
}
else {
    Write-Host ""
    Write-Host "Skipping ADFS Web API policy binding (-SkipAdfs)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
