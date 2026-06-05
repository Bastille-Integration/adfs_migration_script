<#
.SYNOPSIS
    Provision the Bastille AD RBAC structure (OUs, groups, users) and ADFS Web
    API access control policies, or add a single user to an existing structure.

.DESCRIPTION
    Interactive by default: prints the current state, asks which operation to
    run, prompts for each setting with the standard behavior shown as the
    [default] (Enter accepts, typed input overrides), shows a plan, and confirms
    before making any change.

    Two operation modes:
      Restructure  Create/verify the OU tree, security groups, sample users, and
                   ADFS Web API access control policies.
      AddUser      Add one user to an already-built structure, by role
                   (Admin / Operator / Viewer).

    The script is idempotent (existing objects are skipped) and additive - it
    never removes a user from a group or deletes a renamed/removed group, so it
    will not reconcile drift. Each change is attempted independently; failures
    are collected and reported in a summary at the end rather than aborting the
    run. Supports -WhatIf / -Confirm, and writes a transcript log.

.PARAMETER Help
    Show concise usage help and exit.

.PARAMETER BaseOuName
    Name of the base OU under the domain root. Default: Bastille.

.PARAMETER UserPassword
    Password for created users. Accepts a SecureString (recommended) or a plain
    string. Seeds the default when prompted; applied as-is under -NonInteractive.

.PARAMETER PasswordNeverExpires
    Whether created accounts have non-expiring passwords. Default: $true (lab
    convenience). Pass -PasswordNeverExpires:$false to honor the domain policy.

.PARAMETER SkipUsers
    Seed the "create sample users?" choice to No (Restructure mode).

.PARAMETER SkipAdfs
    Seed the "apply ADFS policies?" choice to No (Restructure mode).

.PARAMETER NonInteractive
    Accept all defaults with no prompts (automation / scripted runs).

.PARAMETER ReportOnly
    Print the current Bastille AD/ADFS state and exit without making changes.

.PARAMETER Mode
    Restructure or AddUser. Prompted at startup if omitted (defaults to
    Restructure under -NonInteractive).

.PARAMETER NewUserName
    (AddUser) Full display name, e.g. "Jane Smith". Required under -NonInteractive.

.PARAMETER NewUserGivenName
    (AddUser) First name. Derived from the name if omitted.

.PARAMETER NewUserSurname
    (AddUser) Last name. Derived from the name if omitted.

.PARAMETER NewUserSam
    (AddUser) SAM account name. Derived (spaces -> hyphens, lowercased) if omitted.

.PARAMETER NewUserUpn
    (AddUser) UPN. Defaults to <sam>@<forest> if omitted.

.PARAMETER NewUserRole
    (AddUser) Admin, Operator, or Viewer. Required under -NonInteractive.

.PARAMETER NewUserGroups
    (AddUser) Override the role's default group list.

.PARAMETER LogPath
    Transcript log file path. Defaults to a timestamped file beside the script.

.EXAMPLE
    .\New-BastilleAdUsers.ps1
    Interactive interview (choose Restructure or AddUser).

.EXAMPLE
    .\New-BastilleAdUsers.ps1 -ReportOnly
    Show the current state and exit without changing anything.

.EXAMPLE
    .\New-BastilleAdUsers.ps1 -Mode AddUser -NonInteractive -NewUserName "Jane Smith" -NewUserRole Operator
    Add a user non-interactively.

.EXAMPLE
    .\New-BastilleAdUsers.ps1 -NonInteractive -WhatIf
    Preview the full restructuring without making changes.

.NOTES
    Version : 5.0
    Requires: Run as Administrator on a domain controller. ActiveDirectory
              module required; ADFS module required only for the ADFS step.
              ASCII-only on purpose (Windows PowerShell 5.1 misreads non-ASCII
              in BOM-less files).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    # Show usage help and exit.
    [switch]$Help,

    # Name of the base OU under the domain root.
    [string]$BaseOuName = "Bastille",

    # Password for created users (SecureString recommended, or a plain string).
    [object]$UserPassword = "bastille#123",

    # Non-expiring passwords on created accounts (default on for lab use).
    [bool]$PasswordNeverExpires = $true,

    # Seed the "create sample users?" default to No.
    [switch]$SkipUsers,

    # Seed the "apply ADFS policies?" default to No.
    [switch]$SkipAdfs,

    # Accept all defaults without prompting (automation / scripted runs).
    [switch]$NonInteractive,

    # Print the current Bastille AD/ADFS state and exit without making changes.
    [switch]$ReportOnly,

    # Operation mode. Prompted at startup if omitted (Restructure under -NonInteractive).
    [ValidateSet('Restructure', 'AddUser')]
    [string]$Mode,

    # --- For -Mode AddUser (gathered interactively if omitted) ---
    [string]$NewUserName,
    [string]$NewUserGivenName,
    [string]$NewUserSurname,
    [string]$NewUserSam,
    [string]$NewUserUpn,
    [ValidateSet('Admin', 'Operator', 'Viewer')]
    [string]$NewUserRole,
    [string[]]$NewUserGroups,

    # Transcript log path. Defaults to a timestamped file beside the script.
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

# Collected non-fatal problems, reported in the end-of-run summary.
$script:Issues = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Sample user, ADFS application, and role definitions (the "what the script
# creates" baseline). Edit these to change details or app->group mappings.
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

# Role -> OU + default group memberships, used by the "add a user" mode.
$Roles = @(
    [PSCustomObject]@{ Name = 'Admin';    Ou = 'Admins';    Groups = @('BNAdmin') },
    [PSCustomObject]@{ Name = 'Operator'; Ou = 'Operators'; Groups = @('DVROps', 'ADAMOps') },
    [PSCustomObject]@{ Name = 'Viewer';   Ou = 'Viewers';   Groups = @('DVRViewer', 'ADAMViewer') }
)

# --- Help -------------------------------------------------------------------

function Show-Help {
    $help = @'
New-BastilleAdUsers.ps1
  Provision the Bastille AD RBAC structure (OUs, groups, users) and ADFS Web API
  access control policies, or add a single user to an existing structure.

USAGE
  .\New-BastilleAdUsers.ps1 [-Mode <Restructure|AddUser>] [options]

  Interactive by default: prints the current state, asks which operation to run,
  prompts for each setting with the standard value shown as [default] (Enter to
  accept, type to change), shows a plan, and confirms before any change.

MODES
  Restructure (default)  Create/verify the OU tree, security groups, sample
                         users, and ADFS Web API access control policies.
  AddUser                Add one user to an already-built structure, by role
                         (Admin/Operator/Viewer).

COMMON OPTIONS
  -Help                  Show this help and exit.
  -ReportOnly            Print the current Bastille AD/ADFS state and exit.
  -NonInteractive        Accept all defaults with no prompts (automation).
  -WhatIf / -Confirm     Preview changes / confirm each change (standard).
  -Mode <name>           Restructure | AddUser. Prompted at startup if omitted.
  -BaseOuName <name>     Base OU under the domain root (default: Bastille).
  -LogPath <path>        Transcript log path (default: timestamped, beside script).

RESTRUCTURE OPTIONS
  -UserPassword <value>  Sample-user password (string or SecureString).
  -PasswordNeverExpires <bool>  Default $true; use :$false to honor domain policy.
  -SkipUsers             Default the "create sample users?" choice to No.
  -SkipAdfs              Default the "apply ADFS policies?" choice to No.

ADDUSER OPTIONS
  -NewUserName <text>    Full display name, e.g. "Jane Smith".  (required with -NonInteractive)
  -NewUserRole <name>    Admin | Operator | Viewer.             (required with -NonInteractive)
  -NewUserGivenName <s>  First name   (derived from the name if omitted).
  -NewUserSurname <s>    Last name    (derived from the name if omitted).
  -NewUserSam <s>        SAM account  (derived: spaces -> hyphens, lowercased).
  -NewUserUpn <s>        UPN          (defaults to <sam>@<forest>).
  -NewUserGroups <list>  Override the role's default group list.

NOTES
  Idempotent and additive: existing objects are skipped; the script never removes
  group memberships or deletes objects, so it will not reconcile drift. Failures
  are collected and reported at the end rather than aborting the run.

EXAMPLES
  .\New-BastilleAdUsers.ps1
  .\New-BastilleAdUsers.ps1 -ReportOnly
  .\New-BastilleAdUsers.ps1 -NonInteractive -WhatIf
  .\New-BastilleAdUsers.ps1 -Mode AddUser
  .\New-BastilleAdUsers.ps1 -Mode AddUser -NonInteractive -NewUserName "Jane Smith" -NewUserRole Operator

REQUIRES
  Run as Administrator on a domain controller. ActiveDirectory module required;
  ADFS module required only for the ADFS policy step.
'@
    Write-Host $help
}

# --- Small helpers ----------------------------------------------------------

function Add-Issue {
    # Record a non-fatal problem and surface it now; summarized at the end.
    param([string]$Message)
    [void]$script:Issues.Add($Message)
    Write-Warning $Message
}

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

function ConvertTo-Secure {
    param([object]$Value)
    if ($Value -is [securestring]) { return $Value }
    return (ConvertTo-SecureString ([string]$Value) -AsPlainText -Force)
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
        return $dn
    }
    if ($PSCmdlet.ShouldProcess($dn, "Create OU")) {
        try {
            New-ADOrganizationalUnit -Name $Name -Path $Path -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host "  [+] OU created: $dn" -ForegroundColor Green
        }
        catch { Add-Issue "Failed to create OU '$dn': $($_.Exception.Message)" }
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
    if ($PSCmdlet.ShouldProcess($Name, "Create group")) {
        try {
            $g = New-ADGroup -GroupScope Global -Name $Name -Path $Path -PassThru -Confirm:$false -ErrorAction Stop
            Write-Host "  [+] Group created: $Name" -ForegroundColor Green
            return $g
        }
        catch { Add-Issue "Failed to create group '$Name': $($_.Exception.Message)" }
    }
    return $null
}

function Ensure-User {
    param(
        [string]$Name,
        [string]$GivenName,
        [string]$Surname,
        [string]$SamAccountName,
        [string]$Upn,
        [securestring]$Password,
        [string]$Path,
        [bool]$NeverExpires = $true
    )
    $existing = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [=] User exists: $Name ($SamAccountName)" -ForegroundColor DarkGray
        return $existing
    }
    if ($PSCmdlet.ShouldProcess("$Name ($SamAccountName)", "Create user")) {
        try {
            $u = New-ADUser -Name $Name -GivenName $GivenName -Surname $Surname `
                -SamAccountName $SamAccountName -UserPrincipalName $Upn `
                -AccountPassword $Password -PasswordNeverExpires $NeverExpires -Enabled $true `
                -Path $Path -PassThru -Confirm:$false -ErrorAction Stop
            Write-Host "  [+] User created: $Name ($SamAccountName)" -ForegroundColor Green
            return $u
        }
        catch { Add-Issue "Failed to create user '$Name' ($SamAccountName): $($_.Exception.Message)" }
    }
    return $null
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
    # not affect ADFS access (group membership does) - this is cosmetic.
    $u = Resolve-User -Member $Member
    if (-not $u) { Add-Issue "'$Member' not found - cannot move to '$TargetOu'."; return }
    $currentParent = ($u.DistinguishedName -split ',', 2)[1]
    if ($currentParent -eq $TargetOu) {
        Write-Host "  [=] $($u.SamAccountName) already in $TargetOu" -ForegroundColor DarkGray
        return
    }
    if ($PSCmdlet.ShouldProcess($u.SamAccountName, "Move to $TargetOu")) {
        try {
            Move-ADObject -Identity $u.DistinguishedName -TargetPath $TargetOu -Confirm:$false -ErrorAction Stop
            Write-Host "  [+] $($u.SamAccountName) moved to $TargetOu" -ForegroundColor Green
        }
        catch { Add-Issue "Failed to move '$($u.SamAccountName)' to '$TargetOu': $($_.Exception.Message)" }
    }
}

function Ensure-Member {
    param([string]$GroupName, [string]$Member)
    # Resolve the group via -Filter first: Get-ADGroupMember -Identity on a
    # missing group throws a terminating error that -EA SilentlyContinue would
    # not suppress. Warn and skip instead of crashing the run.
    $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if (-not $group) { Add-Issue "Group '$GroupName' not found - cannot add '$Member'."; return }
    $resolved = Resolve-User -Member $Member
    if (-not $resolved) { Add-Issue "Member '$Member' not found - cannot add to '$GroupName'."; return }
    $already = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $resolved.SID }
    if ($already) {
        Write-Host "  [=] $($resolved.SamAccountName) already in $GroupName" -ForegroundColor DarkGray
        return
    }
    if ($PSCmdlet.ShouldProcess("$($resolved.SamAccountName) -> $GroupName", "Add group member")) {
        try {
            Add-ADGroupMember -Identity $group -Members $resolved -Confirm:$false -ErrorAction Stop
            Write-Host "  [+] $($resolved.SamAccountName) added to $GroupName" -ForegroundColor Green
        }
        catch { Add-Issue "Failed to add '$($resolved.SamAccountName)' to '$GroupName': $($_.Exception.Message)" }
    }
}

function Resolve-GroupSid {
    param([string]$GroupName)
    $g = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if ($g) { return $g.SID.Value }
    Add-Issue "Could not resolve SID for group '$GroupName'."
    return $null
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

function Show-Summary {
    Write-Host ""
    if ($script:Issues.Count -gt 0) {
        Write-Host ("Completed with {0} warning(s):" -f $script:Issues.Count) -ForegroundColor Yellow
        foreach ($i in $script:Issues) { Write-Host "  - $i" -ForegroundColor Yellow }
    }
    else {
        Write-Host "Done - no warnings." -ForegroundColor Cyan
    }
    if ($script:TranscriptStarted) { Write-Host "Log: $script:LogFile" -ForegroundColor DarkGray }
}

# --- Main -------------------------------------------------------------------

if ($Help) {
    Show-Help
    return
}

if (-not (Test-IsAdmin)) {
    throw "This script must be run as Administrator."
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module (RSAT-AD-PowerShell) is required."
}
Import-Module ActiveDirectory -ErrorAction Stop

$DomainDN     = (Get-ADDomain).DistinguishedName
$DomainForest = (Get-ADDomain).Forest

Write-Host ""
Write-Host "Domain : $DomainDN" -ForegroundColor Cyan
Write-Host "Forest : $DomainForest" -ForegroundColor Cyan

# Show what already exists before deciding anything.
Show-BastilleState -Label "Current state (before changes)" -BastilleOu "OU=$BaseOuName,$DomainDN"

if ($ReportOnly) {
    Write-Host "Report-only mode (-ReportOnly): no changes made." -ForegroundColor Yellow
    return
}

# Start a transcript for audit (skip under -WhatIf - nothing is changed).
$script:TranscriptStarted = $false
$script:LogFile = $LogPath
if (-not $WhatIfPreference) {
    if (-not $script:LogFile) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $dir = $PSScriptRoot
        if (-not $dir) { $dir = $env:TEMP }
        $script:LogFile = Join-Path $dir "New-BastilleAdUsers-$stamp.log"
    }
    try {
        Start-Transcript -Path $script:LogFile -ErrorAction Stop | Out-Null
        $script:TranscriptStarted = $true
    }
    catch { Write-Warning "Could not start transcript at '$script:LogFile': $($_.Exception.Message)" }
}

$script:EffectiveBaseOu = $BaseOuName

try {
    # -----------------------------------------------------------------------
    # Choose operation mode
    # -----------------------------------------------------------------------
    $opMode = $Mode
    if (-not $opMode) {
        if ($NonInteractive) {
            $opMode = 'Restructure'
        }
        else {
            Write-Host ""
            Write-Host "What would you like to do?" -ForegroundColor Cyan
            Write-Host "  1) RBAC restructuring - create/verify the full OU/group/user structure and ADFS policies"
            Write-Host "  2) Add a user         - add one user to the existing structure"
            $choice = Read-WithDefault "  Choose" "1"
            if ($choice -eq '2') { $opMode = 'AddUser' } else { $opMode = 'Restructure' }
        }
    }

    if ($opMode -eq 'AddUser') {
        # -------------------------------------------------------------------
        # Mode: Add a single user to an existing structure
        # -------------------------------------------------------------------
        Write-Host ""
        Write-Host "Add a user to the existing structure" -ForegroundColor Cyan

        $effBase = $BaseOuName
        if (-not $NonInteractive -and -not $PSBoundParameters.ContainsKey('BaseOuName')) {
            $effBase = Read-WithDefault "  Base OU name" $effBase
        }
        $script:EffectiveBaseOu = $effBase

        # --- Identity ---
        $name = $NewUserName
        if (-not $name) {
            if ($NonInteractive) { throw "AddUser mode requires -NewUserName under -NonInteractive." }
            $name = (Read-Host "  Full name (e.g. Jane Smith)").Trim()
        }
        if ([string]::IsNullOrWhiteSpace($name)) { Write-Host "No name given - aborting." -ForegroundColor Yellow; return }

        $nameParts    = $name -split '\s+', 2
        $givenDefault = $nameParts[0]
        $surDefault   = ''
        if ($nameParts.Count -gt 1) { $surDefault = $nameParts[1] }
        $samDefault   = ($name -replace '\s+', '-').ToLower()

        $given   = $NewUserGivenName
        $surname = $NewUserSurname
        $sam     = $NewUserSam
        $upn     = $NewUserUpn
        if ($NonInteractive) {
            if (-not $given)   { $given = $givenDefault }
            if (-not $surname) { $surname = $surDefault }
            if (-not $sam)     { $sam = $samDefault }
            if (-not $upn)     { $upn = "$sam@$DomainForest" }
        }
        else {
            if (-not $given)   { $given = Read-WithDefault "  Given name" $givenDefault }
            if (-not $surname) { $surname = Read-WithDefault "  Surname" $surDefault }
            if (-not $sam)     { $sam = Read-WithDefault "  SAM account name" $samDefault }
            if (-not $upn)     { $upn = Read-WithDefault "  UPN" "$sam@$DomainForest" }
        }

        # --- Role (OU + default groups) ---
        $role = $null
        if ($NewUserRole) { $role = $Roles | Where-Object { $_.Name -eq $NewUserRole } | Select-Object -First 1 }
        if (-not $role) {
            if ($NonInteractive) { throw "AddUser mode requires a valid -NewUserRole under -NonInteractive." }
            Write-Host "  Roles:"
            for ($i = 0; $i -lt $Roles.Count; $i++) {
                Write-Host ("    {0}) {1,-9} OU={2,-10} groups: {3}" -f ($i + 1), $Roles[$i].Name, $Roles[$i].Ou, ($Roles[$i].Groups -join ', '))
            }
            $roleChoice = Read-WithDefault "  Choose role" "3"
            $idx = 2
            if ($roleChoice -match '^\d+$' -and [int]$roleChoice -ge 1 -and [int]$roleChoice -le $Roles.Count) { $idx = [int]$roleChoice - 1 }
            $role = $Roles[$idx]
        }

        # --- Groups (default from role, editable) ---
        $groups = $NewUserGroups
        if (-not $groups -or $groups.Count -eq 0) {
            if ($NonInteractive) { $groups = $role.Groups }
            else { $groups = Read-ListWithDefault "  Groups" $role.Groups }
        }

        # --- Target OU must already exist ---
        $targetOuDn = "OU=$($role.Ou),OU=Users,OU=$effBase,$DomainDN"
        $ouExists = $null
        try { $ouExists = Get-ADOrganizationalUnit -Identity $targetOuDn -ErrorAction Stop } catch { $ouExists = $null }
        if (-not $ouExists) {
            throw "Target OU '$targetOuDn' does not exist. Run RBAC restructuring first (Mode Restructure), or check -BaseOuName."
        }

        # --- Password ---
        $pw = $UserPassword
        if (-not $NonInteractive) {
            if (Read-YesNo "  Set a custom password (else use the default)?" $false) {
                $pw = Read-Host "  Password" -AsSecureString
            }
        }
        $securePassword = ConvertTo-Secure -Value $pw

        # --- Plan + confirm ---
        Write-Host ""
        Write-Host "Plan:" -ForegroundColor Cyan
        Write-Host "  User    : $name ($sam)"
        Write-Host "  UPN     : $upn"
        Write-Host "  OU      : $targetOuDn"
        Write-Host "  Groups  : $($groups -join ', ')"
        if (-not $NonInteractive -and -not $WhatIfPreference) {
            if (-not (Read-YesNo "Proceed?" $true)) {
                Write-Host "Aborted - no changes made." -ForegroundColor Yellow
                return
            }
        }

        # --- Execute ---
        Write-Host ""
        Write-Host "Adding user..." -ForegroundColor Cyan
        Ensure-User -Name $name -GivenName $given -Surname $surname `
            -SamAccountName $sam -Upn $upn -Password $securePassword -Path $targetOuDn `
            -NeverExpires $PasswordNeverExpires | Out-Null
        foreach ($g in $groups) { Ensure-Member -GroupName $g -Member $sam }
    }
    else {
        # -------------------------------------------------------------------
        # Mode: RBAC restructuring
        # Defaults reflect standard behavior; -SkipUsers / -SkipAdfs seed the
        # relevant defaults to "no". Interactive unless requested.
        # -------------------------------------------------------------------
        $adfsAvailable = [bool](Get-Module -ListAvailable -Name ADFS)

        $cfg = [ordered]@{
            BaseOuName  = $BaseOuName
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

        $script:EffectiveBaseOu = $cfg.BaseOuName

        # Plan summary
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

        if (-not $NonInteractive -and -not $WhatIfPreference) {
            if (-not (Read-YesNo "Proceed with these settings?" $true)) {
                Write-Host "Aborted - no changes made." -ForegroundColor Yellow
                return
            }
        }

        # 1. OU tree
        Write-Host ""
        Write-Host "Creating OU structure..." -ForegroundColor Cyan
        $ouBastille  = Ensure-Ou -Name $cfg.BaseOuName -Path $DomainDN
        $ouGroups    = Ensure-Ou -Name "Groups"    -Path $ouBastille
        $ouUsers     = Ensure-Ou -Name "Users"     -Path $ouBastille
        $ouAdmins    = Ensure-Ou -Name "Admins"    -Path $ouUsers
        $ouOperators = Ensure-Ou -Name "Operators" -Path $ouUsers
        $ouViewers   = Ensure-Ou -Name "Viewers"   -Path $ouUsers
        $ouByName = @{ 'Admins' = $ouAdmins; 'Operators' = $ouOperators; 'Viewers' = $ouViewers }

        # 2. Security groups
        Write-Host ""
        Write-Host "Creating security groups..." -ForegroundColor Cyan
        foreach ($gname in $cfg.Groups) { Ensure-Group -Name $gname -Path $ouGroups | Out-Null }

        # 3. Pre-existing admin account membership
        if (-not [string]::IsNullOrWhiteSpace($cfg.AdminMember)) {
            Write-Host ""
            Write-Host "Assigning administrator membership..." -ForegroundColor Cyan
            # The admin account is created elsewhere, not here. Its SamAccountName
            # varies by environment ('bntest' from the installer, 'BN Test' from
            # the GUI), so Resolve-User matches on display Name too.
            Ensure-Member -GroupName "BNAdmin" -Member $cfg.AdminMember
            Ensure-UserInOu -Member $cfg.AdminMember -TargetOu $ouAdmins
        }

        # 4. Sample users
        if ($cfg.CreateUsers) {
            Write-Host ""
            Write-Host "Creating sample users..." -ForegroundColor Cyan
            $securePassword = ConvertTo-Secure -Value $cfg.Password
            foreach ($su in $SampleUsers) {
                $targetOu = $ouByName[$su.Ou]
                if (-not $targetOu) { $targetOu = $ouUsers }
                Ensure-User -Name $su.Name -GivenName $su.Given -Surname $su.Surname `
                    -SamAccountName $su.Sam -Upn "$($su.Sam)@$DomainForest" `
                    -Password $securePassword -Path $targetOu -NeverExpires $PasswordNeverExpires | Out-Null
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

        # 5. ADFS Web API access control policies
        if ($cfg.ApplyAdfs) {
            Write-Host ""
            Write-Host "Binding ADFS Web API access control policies..." -ForegroundColor Cyan
            Import-Module ADFS -ErrorAction Stop
            foreach ($app in $AppPolicies) {
                $target = Get-AdfsWebApiApplication -Name $app.TargetName -ErrorAction SilentlyContinue
                if (-not $target) {
                    Add-Issue "Web API application not found: '$($app.TargetName)' - skipped. (Register it in ADFS first.)"
                    continue
                }
                $sids = @()
                foreach ($g in $app.Groups) {
                    $sid = Resolve-GroupSid -GroupName $g
                    if ($sid) { $sids += $sid }
                }
                if ($sids.Count -eq 0) {
                    Add-Issue "No group SIDs resolved for '$($app.TargetName)' - skipped."
                    continue
                }
                if ($PSCmdlet.ShouldProcess($app.TargetName, "Set access control policy")) {
                    try {
                        Set-AdfsWebApiApplication -TargetName $app.TargetName `
                            -AccessControlPolicyName "Permit specific group" `
                            -AccessControlPolicyParameters @{ GroupParameter = $sids } -ErrorAction Stop
                        Write-Host "  [+] $($app.TargetName) -> $($app.Groups -join ', ')" -ForegroundColor Green
                    }
                    catch { Add-Issue "Failed to set policy on '$($app.TargetName)': $($_.Exception.Message)" }
                }
            }
        }
        else {
            Write-Host ""
            Write-Host "Skipping ADFS Web API policy binding." -ForegroundColor Yellow
        }
    }

    # Report the resulting state, then summarize.
    Show-BastilleState -Label "Final state (after changes)" -BastilleOu "OU=$($script:EffectiveBaseOu),$DomainDN"
    Show-Summary
}
finally {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}
