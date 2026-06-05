# Version: 4.0
# Requires: Run as Administrator on a domain controller (ActiveDirectory + ADFS modules)
# Purpose: Create the Bastille OU/group/user structure and bind ADFS Web API
#          applications to the appropriate access-control groups.
# Notes:   Interactive by default - it prints the current state, then asks what
#          to create with the standard behavior shown as the [default]. Press
#          Enter to accept a default, or type a new value to change it. Use
#          -NonInteractive to accept all defaults with no prompts (automation),
#          or -ReportOnly to print the current state and exit.
#          Idempotent - re-running skips objects that already exist. ADFS access
#          control policies are applied using resolved group SIDs (the value the
#          "Permit specific group" policy expects), not bare group names.
# Examples:
#   .\New-BastilleAdUsers.ps1                  (interactive interview)
#   .\New-BastilleAdUsers.ps1 -ReportOnly      (show current state only, change nothing)
#   .\New-BastilleAdUsers.ps1 -NonInteractive  (accept all defaults, no prompts)
#   .\New-BastilleAdUsers.ps1 -SkipAdfs        (default the ADFS step to "no")

[CmdletBinding()]
param(
    # Password for the sample users. Accepts a SecureString (recommended) or a
    # plain string. Seeds the default when prompted; used as-is in -NonInteractive.
    [object]$UserPassword = "bastille#123",

    # Seed the "create sample users?" default to No.
    [switch]$SkipUsers,

    # Seed the "apply ADFS policies?" default to No.
    [switch]$SkipAdfs,

    # Accept all defaults without prompting (automation / scripted runs).
    [switch]$NonInteractive,

    # Print the current Bastille AD/ADFS state and exit without making changes.
    [switch]$ReportOnly
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Sample user and ADFS application definitions (the "what the script creates"
# baseline). Edit these to change the per-user details or app->group mappings.
# ---------------------------------------------------------------------------

$SampleUsers = @(
    [PSCustomObject]@{ Name = 'BN Viewer'; Sam = 'bn-viewer'; Given = 'BN'; Surname = 'Viewer'; Ou = 'Viewers';   Groups = @('DVRViewer', 'ADAMViewer') },
    [PSCustomObject]@{ Name = 'BN Ops';    Sam = 'bn-ops';    Given = 'BN'; Surname = 'Ops';    Ou = 'Operators'; Groups = @('DVROps', 'ADAMOps') }
)

$AppPolicies = @(
    [PSCustomObject]@{ TargetName = 'Bastille Admin - Web application';          Groups = @('BNAdmin') },
    [PSCustomObject]@{ TargetName = 'Bastille DVR and Device - Web application'; Groups = @('BNAdmin', 'DVROps', 'DVRViewer') },
    [PSCustomObject]@{ TargetName = 'Bastille Lighthouse - Web application';     Groups = @('BNAdmin', 'ADAMOps', 'ADAMViewer') }
)

# --- Input helpers ----------------------------------------------------------

function Read-WithDefault {
    param([string]$Prompt, [string]$Default)
    $resp = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
    return $resp.Trim()
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default)
    $hint = "y/N"
    if ($Default) { $hint = "Y/n" }
    $resp = Read-Host "$Prompt [$hint]"
    if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
    return ($resp.Trim() -match '^(y|yes)$')
}

function Read-ListWithDefault {
    param([string]$Prompt, [string[]]$Default)
    $resp = Read-Host ("$Prompt [{0}]" -f ($Default -join ', '))
    if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
    return @($resp -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# --- AD/ADFS helpers --------------------------------------------------------

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

function Show-BastilleState {
    # Print a read-only snapshot of the Bastille OU tree, groups (with members),
    # users (with their OU and group memberships), and the ADFS Web API policies.
    param([string]$Label, [string]$BastilleOu)

    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host "  $Label" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan

    $root = $null
    try { $root = Get-ADOrganizationalUnit -Identity $BastilleOu -ErrorAction Stop } catch { $root = $null }

    if (-not $root) {
        Write-Host "  No '$BastilleOu' OU structure exists yet." -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-Host "  Organizational Units" -ForegroundColor White
        foreach ($ou in @(Get-ADOrganizationalUnit -SearchBase $BastilleOu -Filter * | Sort-Object DistinguishedName)) {
            Write-Host "    $($ou.DistinguishedName)"
        }

        Write-Host ""
        Write-Host "  Groups (members)" -ForegroundColor White
        $groups = @(Get-ADGroup -SearchBase $BastilleOu -Filter * | Sort-Object Name)
        if ($groups.Count -eq 0) { Write-Host "    (none)" -ForegroundColor DarkGray }
        foreach ($g in $groups) {
            $members = @(Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty SamAccountName)
            $memberText = "(empty)"
            if ($members.Count -gt 0) { $memberText = ($members -join ', ') }
            Write-Host ("    {0,-12} {1}" -f $g.Name, $memberText)
        }

        Write-Host ""
        Write-Host "  Users (OU / groups)" -ForegroundColor White
        $users = @(Get-ADUser -SearchBase $BastilleOu -Filter * -Properties MemberOf | Sort-Object Name)
        if ($users.Count -eq 0) { Write-Host "    (none)" -ForegroundColor DarkGray }
        foreach ($u in $users) {
            $ouName  = (($u.DistinguishedName -split ',', 2)[1] -split ',')[0] -replace '^OU=', ''
            $grpList = @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' } | Sort-Object)
            $grpText = "(no groups)"
            if ($grpList.Count -gt 0) { $grpText = ($grpList -join ', ') }
            $state = "enabled"
            if (-not $u.Enabled) { $state = "DISABLED" }
            Write-Host ("    {0,-16} [{1,-8}] OU={2,-10} groups: {3}" -f $u.SamAccountName, $state, $ouName, $grpText)
        }
    }

    if (Get-Module -ListAvailable -Name ADFS) {
        Import-Module ADFS -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "  ADFS Web API access control policies" -ForegroundColor White
        foreach ($app in $AppPolicies) {
            $found = Get-AdfsWebApiApplication -Name $app.TargetName -ErrorAction SilentlyContinue
            if ($found) {
                Write-Host ("    {0,-45} {1}" -f $app.TargetName, $found.AccessControlPolicyName)
            }
            else {
                Write-Host ("    {0,-45} (not registered)" -f $app.TargetName) -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ""
}

# --- Main -------------------------------------------------------------------

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

# Show what already exists before deciding anything.
$baseOuName = 'Bastille'
Show-BastilleState -Label "Current state (before changes)" -BastilleOu "OU=$baseOuName,$DomainDN"

if ($ReportOnly) {
    Write-Host "Report-only mode (-ReportOnly): no changes made." -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# Gather configuration. Defaults reflect the standard behavior; -SkipUsers /
# -SkipAdfs seed the relevant defaults to "no". Interactive unless requested.
# ---------------------------------------------------------------------------

$adfsAvailable = [bool](Get-Module -ListAvailable -Name ADFS)

$cfg = [ordered]@{
    BaseOuName  = $baseOuName
    Groups      = @('BNAdmin', 'DVROps', 'DVRViewer', 'ADAMOps', 'ADAMViewer')
    AdminMember = 'BN Test'
    CreateUsers = (-not $SkipUsers)
    ApplyAdfs   = ((-not $SkipAdfs) -and $adfsAvailable)
    Password    = $UserPassword
}

if (-not $NonInteractive) {
    Write-Host ""
    Write-Host "Configure what to create. Press Enter to accept each [default]." -ForegroundColor Cyan
    $cfg.BaseOuName  = Read-WithDefault    "  Base OU name" $cfg.BaseOuName
    $cfg.Groups      = Read-ListWithDefault "  Security groups (comma-separated)" $cfg.Groups
    $cfg.AdminMember = Read-WithDefault    "  Admin account to add to BNAdmin (blank = skip)" $cfg.AdminMember
    $cfg.CreateUsers = Read-YesNo          ("  Create sample users ({0})?" -f (($SampleUsers | ForEach-Object { $_.Name }) -join ', ')) $cfg.CreateUsers
    if ($cfg.CreateUsers) {
        if (Read-YesNo "    Set a custom sample-user password (else use the default)?" $false) {
            $cfg.Password = Read-Host "    Sample-user password" -AsSecureString
        }
    }
    if ($adfsAvailable) {
        $cfg.ApplyAdfs = Read-YesNo "  Apply ADFS Web API access control policies?" $cfg.ApplyAdfs
    }
    else {
        $cfg.ApplyAdfs = $false
        Write-Host "  (ADFS module not present - the ADFS policy step will be skipped)" -ForegroundColor DarkGray
    }
}

# Plan summary --------------------------------------------------------------
$adminText = $cfg.AdminMember
if ([string]::IsNullOrWhiteSpace($adminText)) { $adminText = '(skip)' }
$usersText = 'no'
if ($cfg.CreateUsers) { $usersText = (($SampleUsers | ForEach-Object { $_.Sam }) -join ', ') }
$adfsText = 'no'
if ($cfg.ApplyAdfs) { $adfsText = 'yes' }

Write-Host ""
Write-Host "Plan:" -ForegroundColor Cyan
Write-Host "  OU tree         : OU=$($cfg.BaseOuName),$DomainDN  (+ Groups, Users\{Admins,Operators,Viewers})"
Write-Host "  Groups          : $($cfg.Groups -join ', ')"
Write-Host "  Admin -> BNAdmin: $adminText"
Write-Host "  Sample users    : $usersText"
Write-Host "  ADFS policies   : $adfsText"

if (-not $NonInteractive) {
    if (-not (Read-YesNo "Proceed with these settings?" $true)) {
        Write-Host "Aborted - no changes made." -ForegroundColor Yellow
        return
    }
}

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------

# 1. OU tree -----------------------------------------------------------------
Write-Host ""
Write-Host "Creating OU structure..." -ForegroundColor Cyan
$ouBastille  = Ensure-Ou -Name $cfg.BaseOuName -Path $DomainDN
$ouGroups    = Ensure-Ou -Name "Groups"    -Path $ouBastille
$ouUsers     = Ensure-Ou -Name "Users"     -Path $ouBastille
$ouAdmins    = Ensure-Ou -Name "Admins"    -Path $ouUsers
$ouOperators = Ensure-Ou -Name "Operators" -Path $ouUsers
$ouViewers   = Ensure-Ou -Name "Viewers"   -Path $ouUsers
$ouByName = @{ 'Admins' = $ouAdmins; 'Operators' = $ouOperators; 'Viewers' = $ouViewers }

# 2. Security groups ---------------------------------------------------------
Write-Host ""
Write-Host "Creating security groups..." -ForegroundColor Cyan
foreach ($name in $cfg.Groups) { Ensure-Group -Name $name -Path $ouGroups | Out-Null }

# 3. Pre-existing admin account membership -----------------------------------
if (-not [string]::IsNullOrWhiteSpace($cfg.AdminMember)) {
    Write-Host ""
    Write-Host "Assigning administrator membership..." -ForegroundColor Cyan
    # The admin account is created elsewhere, not here. Its SamAccountName varies
    # by environment ('bntest' from the installer, 'BN Test' from the GUI), so
    # Resolve-User matches on display Name too. Warn (don't fail) if missing.
    Ensure-Member -GroupName "BNAdmin" -Member $cfg.AdminMember
    # Keep the admin account organized under the Admins OU (cosmetic; ADFS access
    # is governed by BNAdmin membership above, not OU placement).
    Ensure-UserInOu -Member $cfg.AdminMember -TargetOu $ouAdmins
}

# 4. Sample users ------------------------------------------------------------
if ($cfg.CreateUsers) {
    Write-Host ""
    Write-Host "Creating sample users..." -ForegroundColor Cyan
    $securePassword = ConvertTo-Secure -Value $cfg.Password

    foreach ($su in $SampleUsers) {
        $targetOu = $ouByName[$su.Ou]
        if (-not $targetOu) { $targetOu = $ouUsers }
        Ensure-User -Name $su.Name -GivenName $su.Given -Surname $su.Surname `
            -SamAccountName $su.Sam -Upn "$($su.Sam)@$DomainForest" `
            -Password $securePassword -Path $targetOu | Out-Null
    }

    Write-Host ""
    Write-Host "Assigning sample-user memberships..." -ForegroundColor Cyan
    foreach ($su in $SampleUsers) {
        foreach ($grp in $su.Groups) { Ensure-Member -GroupName $grp -Member $su.Sam }
    }
}
else {
    Write-Host ""
    Write-Host "Skipping sample users." -ForegroundColor Yellow
}

# 5. ADFS Web API access control policies ------------------------------------
if ($cfg.ApplyAdfs) {
    Write-Host ""
    Write-Host "Binding ADFS Web API access control policies..." -ForegroundColor Cyan
    Import-Module ADFS -ErrorAction Stop

    foreach ($app in $AppPolicies) {
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
else {
    Write-Host ""
    Write-Host "Skipping ADFS Web API policy binding." -ForegroundColor Yellow
}

# Report the resulting state so the changes are easy to verify at a glance.
Show-BastilleState -Label "Final state (after changes)" -BastilleOu "OU=$($cfg.BaseOuName),$DomainDN"

Write-Host "Done." -ForegroundColor Cyan
