# Version: 1.0
# Requires: Run as Administrator on an ADFS node
# Examples:
#   .\Invoke-AdfsTroubleshoot.ps1
#   .\Invoke-AdfsTroubleshoot.ps1 -Username jsmith
#   .\Invoke-AdfsTroubleshoot.ps1 -Username jsmith -Unlock
#   .\Invoke-AdfsTroubleshoot.ps1 -Username jsmith -Unlock -NonInteractive
#   .\Invoke-AdfsTroubleshoot.ps1 -SkipAdfs       (AD lockout check only)

[CmdletBinding()]
param(
    [string]$Username,

    [switch]$Unlock,

    [int]$EventCount = 30,

    [int]$CertWarnDays = 30,

    [switch]$SkipAdfs,

    [switch]$SkipAd,

    [switch]$NonInteractive
)

# --- Helpers ---

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
    Write-Host ("  " + $Title) -ForegroundColor Cyan
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Import-AdfsSafe {
    try   { Import-Module ADFS -ErrorAction Stop | Out-Null; return $true }
    catch { Write-Warning "ADFS module not available: $($_.Exception.Message)"; return $false }
}

function Import-AdSafe {
    try   { Import-Module ActiveDirectory -ErrorAction Stop | Out-Null; return $true }
    catch {
        Write-Warning "ActiveDirectory module not available. Install RSAT-AD-PowerShell to enable AD operations."
        return $false
    }
}

function Confirm-Action {
    param([string]$Prompt)
    if ($NonInteractive) { return $true }
    return ((Read-Host $Prompt) -match '^(y|yes)$')
}

# --- ADFS Health ---

function Show-AdfsServiceStatus {
    try {
        $svc = Get-Service -Name adfssrv -ErrorAction Stop
        $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
        Write-Host ("  Service (adfssrv) : {0}" -f $svc.Status) -ForegroundColor $color
    }
    catch {
        Write-Host "  Service (adfssrv) : Cannot query — $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-CertRow {
    param([string]$Label, $Cert, [int]$WarnDays)

    if ($null -eq $Cert) {
        Write-Host ("  {0,-38}: <not found>" -f $Label) -ForegroundColor Yellow
        return
    }

    $days  = [int](($Cert.NotAfter - (Get-Date)).TotalDays)
    $color = if ($days -lt 0)        { 'Red'    }
             elseif ($days -le $WarnDays) { 'Yellow' }
             else                        { 'Green'  }
    $note  = if ($days -lt 0)        { " [EXPIRED {0}d ago]"    -f (-$days) }
             elseif ($days -le $WarnDays) { " [EXPIRES IN {0}d]"    -f $days  }
             else                        { " ({0}d remaining)"       -f $days  }

    Write-Host ("  {0,-38}: {1}{2}" -f $Label, $Cert.NotAfter.ToString("yyyy-MM-dd"), $note) -ForegroundColor $color
}

function Show-AdfsCertificates {
    param([int]$WarnDays)

    foreach ($type in @('Token-Signing', 'Token-Decrypting', 'Service-Communications')) {
        try {
            foreach ($c in @(Get-AdfsCertificate -CertificateType $type -ErrorAction Stop)) {
                $isPrimary = if ($c.PSObject.Properties.Name -contains 'IsPrimary') { $c.IsPrimary } else { $true }
                $label = "$type" + $(if ($isPrimary) { " (Primary)" } else { " (Secondary)" })
                Show-CertRow -Label $label -Cert $c.Certificate -WarnDays $WarnDays
            }
        }
        catch {
            Write-Host ("  {0,-38}: Cannot query" -f $type) -ForegroundColor Yellow
        }
    }

    try {
        $seen = @{}
        foreach ($b in @(Get-AdfsSslCertificate -ErrorAction Stop)) {
            if ($seen.ContainsKey($b.CertificateHash)) { continue }
            $seen[$b.CertificateHash] = $true
            $certObj = Get-ChildItem Cert:\LocalMachine\My |
                Where-Object { $_.Thumbprint -ieq $b.CertificateHash } |
                Select-Object -First 1
            Show-CertRow -Label ("SSL ({0})" -f $b.HostName) -Cert $certObj -WarnDays $WarnDays
        }
    }
    catch {
        Write-Host ("  {0,-38}: Cannot query" -f 'SSL') -ForegroundColor Yellow
    }
}

function Show-AdfsConfig {
    try {
        $p = Get-AdfsProperties -ErrorAction Stop

        Write-Host ("  Federation Host    : {0}" -f $p.HostName)
        Write-Host ("  Display Name       : {0}" -f $p.DisplayName)
        Write-Host ("  Audit Level        : {0}" -f $p.AuditLevel)

        $lockoutEnabled = $p.EnableExtranetLockout
        $lockColor = if ($lockoutEnabled) { 'Green' } else { 'Yellow' }
        Write-Host ("  Extranet Lockout   : {0}" -f $lockoutEnabled) -ForegroundColor $lockColor

        if ($lockoutEnabled) {
            Write-Host ("  Lockout Threshold  : {0} bad attempts" -f $p.ExtranetLockoutThreshold)
            Write-Host ("  Observation Window : {0}"               -f $p.ExtranetObservationWindow)
        }

        if ($p.AuditLevel -eq 'None') {
            Write-Host ""
            Write-Host "  NOTE: Audit level is None — auth failures will not appear in the Security log." -ForegroundColor Yellow
            Write-Host "        To enable:" -ForegroundColor DarkYellow
            Write-Host "          Set-AdfsProperties -AuditLevel Basic" -ForegroundColor DarkYellow
            Write-Host "          auditpol /set /subcategory:`"Application Generated`" /success:enable /failure:enable" -ForegroundColor DarkYellow
        }
    }
    catch {
        Write-Host "  Cannot read ADFS properties: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Event Log ---

function Show-AdfsRecentEvents {
    param([int]$Count)

    $collected = [System.Collections.Generic.List[PSCustomObject]]::new()

    # AD FS/Admin — errors and warnings
    try {
        $adminEvents = Get-WinEvent -LogName 'AD FS/Admin' -MaxEvents ($Count * 3) -ErrorAction Stop |
            Where-Object { $_.Level -le 3 }

        foreach ($e in $adminEvents) {
            [void]$collected.Add([PSCustomObject]@{
                Time    = $e.TimeCreated
                Source  = 'ADFS/Admin'
                Level   = $e.LevelDisplayName
                Id      = $e.Id
                Message = (($e.Message -split "`n")[0]).Trim() -replace '\s+', ' '
            })
        }
    }
    catch {
        Write-Host "  AD FS/Admin log not accessible: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Security log — ADFS Auditing source (requires auditing to be configured)
    try {
        $secEvents = Get-WinEvent -FilterHashtable @{
            LogName      = 'Security'
            ProviderName = 'AD FS Auditing'
        } -MaxEvents $Count -ErrorAction Stop

        foreach ($e in $secEvents) {
            [void]$collected.Add([PSCustomObject]@{
                Time    = $e.TimeCreated
                Source  = 'Security'
                Level   = $e.LevelDisplayName
                Id      = $e.Id
                Message = (($e.Message -split "`n")[0]).Trim() -replace '\s+', ' '
            })
        }
    }
    catch {
        # Silently skip — auditing may not be configured
    }

    if ($collected.Count -eq 0) {
        Write-Host "  No errors or warnings found in AD FS/Admin event log." -ForegroundColor Green
        return
    }

    $collected |
        Sort-Object Time -Descending |
        Select-Object -First $Count |
        ForEach-Object {
            $color = switch ($_.Level) {
                'Critical' { 'Red'    }
                'Error'    { 'Red'    }
                'Warning'  { 'Yellow' }
                default    { 'Gray'   }
            }
            $msg = if ($_.Message.Length -gt 90) { $_.Message.Substring(0, 87) + '...' } else { $_.Message }
            Write-Host ("  {0}  {1,-8}  {2,5}  {3}" -f `
                $_.Time.ToString("yyyy-MM-dd HH:mm:ss"), $_.Level, $_.Id, $msg) -ForegroundColor $color
        }
}

# --- AD Account Lockout ---

function Get-AdUserFull {
    param([string]$Identity)

    try {
        return Get-ADUser -Identity $Identity -Properties `
            LockedOut, AccountLockoutTime, BadLogonCount, LastBadPasswordAttempt, `
            LastLogonDate, Enabled, PasswordNeverExpires, PasswordExpired, `
            PasswordLastSet, PasswordExpirationDate, DisplayName, UserPrincipalName `
            -ErrorAction Stop
    }
    catch {
        Write-Host "  Cannot find AD account '$Identity': $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Show-AdUserStatus {
    param($User)

    $lockedColor  = if ($User.LockedOut) { 'Red'    } else { 'Green' }
    $enabledColor = if ($User.Enabled)   { 'Green'  } else { 'Red'   }
    $pwdExpColor  = if ($User.PasswordExpired) { 'Red' } else { 'Green' }

    Write-Host ("  Account           : {0}  ({1})" -f $User.SamAccountName, $User.DisplayName)
    Write-Host ("  UPN               : {0}" -f $User.UserPrincipalName)
    Write-Host ("  Enabled           : {0}" -f $User.Enabled) -ForegroundColor $enabledColor
    Write-Host ("  AD Locked Out     : {0}" -f $User.LockedOut) -ForegroundColor $lockedColor

    if ($User.LockedOut -and $null -ne $User.AccountLockoutTime) {
        Write-Host ("  Locked At         : {0}" -f $User.AccountLockoutTime)
    }

    Write-Host ("  Bad Logon Count   : {0}" -f $User.BadLogonCount)

    if ($null -ne $User.LastBadPasswordAttempt) {
        Write-Host ("  Last Bad Password : {0}" -f $User.LastBadPasswordAttempt)
    }

    Write-Host ("  Password Expired  : {0}" -f $User.PasswordExpired) -ForegroundColor $pwdExpColor
    Write-Host ("  Password Last Set : {0}" -f $(if ($User.PasswordLastSet) { $User.PasswordLastSet } else { "<never>" }))

    $pwdExpiry = if ($User.PasswordNeverExpires) {
        "Never"
    } elseif ($User.PasswordExpirationDate) {
        $User.PasswordExpirationDate.ToString("yyyy-MM-dd")
    } else {
        "Unknown"
    }
    Write-Host ("  Password Expires  : {0}" -f $pwdExpiry)
    Write-Host ("  Last Logon        : {0}" -f $(if ($User.LastLogonDate) { $User.LastLogonDate } else { "<never>" }))
}

function Show-AdfsExtranetStatus {
    param([string]$Upn)

    try {
        $activity = Get-AdfsAccountActivity -Identifier $Upn -ErrorAction Stop

        if ($null -eq $activity) {
            Write-Host "  ADFS Extranet     : No activity record for '$Upn'" -ForegroundColor Gray
            return
        }

        Write-Host "  ADFS Extranet Lockout Activity:" -ForegroundColor Gray
        $activity |
            Get-Member -MemberType Property |
            Where-Object { $_.Name -ne 'Identifier' } |
            ForEach-Object {
                $val = $activity.($_.Name)
                Write-Host ("    {0,-35}: {1}" -f $_.Name, $val)
            }
    }
    catch {
        Write-Host ("  ADFS Extranet     : Not available — {0}" -f $_.Exception.Message) -ForegroundColor Gray
    }
}

function Invoke-UnlockAccount {
    param(
        [string]$SamAccountName,
        [string]$Upn,
        [bool]$AdAvailable,
        [bool]$AdfsAvailable
    )

    # ---- AD Unlock ----
    if ($AdAvailable) {
        try {
            $user = Get-AdUserFull -Identity $SamAccountName
            if ($null -ne $user) {
                if ($user.LockedOut) {
                    if (Confirm-Action "  Unlock AD account '$SamAccountName'? (y/n)") {
                        Unlock-ADAccount -Identity $SamAccountName -ErrorAction Stop
                        Write-Host "  AD account unlocked." -ForegroundColor Green
                    }
                    else {
                        Write-Host "  Skipped AD unlock." -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "  AD account is not locked — no AD unlock needed." -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host ("  AD unlock failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    }
    else {
        Write-Host "  AD module not available — cannot unlock AD account from this session." -ForegroundColor Yellow
        Write-Host "  Unlock manually via ADUC or a machine with RSAT-AD-PowerShell installed." -ForegroundColor Yellow
    }

    # ---- ADFS Extranet Lockout Reset ----
    if ($AdfsAvailable -and -not [string]::IsNullOrWhiteSpace($Upn)) {
        try {
            $props = Get-AdfsProperties -ErrorAction Stop
            if (-not $props.EnableExtranetLockout) {
                Write-Host "  ADFS Extranet Lockout is not enabled — no ADFS lockout to reset." -ForegroundColor Gray
                return
            }

            if (Confirm-Action "  Reset ADFS extranet lockout for '$Upn'? (y/n)") {
                try {
                    Reset-AdfsAccountLockout -Identity $Upn -ErrorAction Stop
                    Write-Host "  ADFS extranet lockout reset." -ForegroundColor Green
                }
                catch {
                    # Fallback for ADFS versions that don't have Reset-AdfsAccountLockout
                    $activity = Get-AdfsAccountActivity -Identifier $Upn -ErrorAction Stop
                    if ($null -ne $activity) {
                        Set-AdfsAccountActivity -Identifier $Upn `
                            -BadPwdCountFamiliar 0 -BadPwdCountUnfamiliar 0 -ErrorAction Stop
                        Write-Host "  ADFS extranet lockout counters reset." -ForegroundColor Green
                    }
                    else {
                        Write-Host "  No ADFS extranet activity found for '$Upn'." -ForegroundColor Gray
                    }
                }
            }
            else {
                Write-Host "  Skipped ADFS extranet lockout reset." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host ("  ADFS extranet lockout reset failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }
    elseif ($AdfsAvailable -and [string]::IsNullOrWhiteSpace($Upn)) {
        Write-Host "  UPN not available — skipping ADFS extranet lockout reset." -ForegroundColor Yellow
        Write-Host "  Re-run with a UPN (e.g. -Username user@domain.com) to reset ADFS lockout." -ForegroundColor Yellow
    }
}

# =============================================================================
# Main
# =============================================================================

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$adfsAvailable = if ($SkipAdfs) { $false } else { Import-AdfsSafe }
$adAvailable   = if ($SkipAd)   { $false } else { Import-AdSafe   }

# ---- ADFS Health ----
if (-not $SkipAdfs -and $adfsAvailable) {
    Write-SectionHeader "ADFS Service"
    Show-AdfsServiceStatus

    Write-SectionHeader "Certificate Expiry (warn at $CertWarnDays days)"
    Show-AdfsCertificates -WarnDays $CertWarnDays

    Write-SectionHeader "ADFS Configuration"
    Show-AdfsConfig

    Write-SectionHeader "Recent ADFS Errors and Warnings"
    Show-AdfsRecentEvents -Count $EventCount
}

# ---- Account section ----
if (-not $SkipAd) {

    if (-not [string]::IsNullOrWhiteSpace($Username)) {

        # ---- Specific user ----
        Write-SectionHeader "Account Status: $Username"

        $adUser = $null
        $upn    = $null

        if ($adAvailable) {
            $adUser = Get-AdUserFull -Identity $Username
            if ($null -ne $adUser) {
                Show-AdUserStatus -User $adUser
                $upn = $adUser.UserPrincipalName
            }
        }
        else {
            Write-Host "  AD module not available — cannot check AD account status." -ForegroundColor Yellow
            # Username might already be a UPN
            if ($Username -match '@') { $upn = $Username }
        }

        if ($adfsAvailable -and -not [string]::IsNullOrWhiteSpace($upn)) {
            Write-Host ""
            Show-AdfsExtranetStatus -Upn $upn
        }

        $isLocked    = $null -ne $adUser -and $adUser.LockedOut
        $shouldUnlock = $Unlock -or (
            -not $NonInteractive -and $isLocked -and
            (Confirm-Action "`n  Account is locked. Unlock now? (y/n)")
        )

        if ($shouldUnlock) {
            Write-SectionHeader "Unlocking: $Username"
            Invoke-UnlockAccount `
                -SamAccountName ($adUser ? $adUser.SamAccountName : $Username) `
                -Upn            $upn `
                -AdAvailable    $adAvailable `
                -AdfsAvailable  $adfsAvailable
        }
        elseif ($Unlock -and -not $isLocked) {
            Write-Host ""
            Write-Host "  -Unlock was specified but the account does not appear to be locked in AD." -ForegroundColor Yellow
            Write-Host "  ADFS extranet lockout reset will still be attempted if applicable." -ForegroundColor Yellow

            Write-SectionHeader "Unlocking: $Username"
            Invoke-UnlockAccount `
                -SamAccountName ($adUser ? $adUser.SamAccountName : $Username) `
                -Upn            $upn `
                -AdAvailable    $adAvailable `
                -AdfsAvailable  $adfsAvailable
        }

    }
    else {

        # ---- List all locked accounts ----
        Write-SectionHeader "Locked AD Accounts"

        if ($adAvailable) {
            try {
                $locked = @(Search-ADAccount -LockedOut -ErrorAction Stop)

                if ($locked.Count -eq 0) {
                    Write-Host "  No locked AD accounts found." -ForegroundColor Green
                }
                else {
                    Write-Host ("  {0} locked account(s):" -f $locked.Count) -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host ("  {0,-20}  {1,-30}  {2,-22}  {3}" -f "Username", "Display Name", "Locked At", "Bad Logons") -ForegroundColor Gray

                    foreach ($acct in ($locked | Sort-Object SamAccountName)) {
                        try {
                            $d = Get-ADUser -Identity $acct.SamAccountName `
                                -Properties LockedOut, AccountLockoutTime, BadLogonCount, DisplayName `
                                -ErrorAction Stop

                            $lockedAt = if ($d.AccountLockoutTime) {
                                $d.AccountLockoutTime.ToString("yyyy-MM-dd HH:mm:ss")
                            } else { "unknown time" }

                            Write-Host ("  {0,-20}  {1,-30}  {2,-22}  {3}" -f `
                                $d.SamAccountName, $d.DisplayName, $lockedAt, $d.BadLogonCount) `
                                -ForegroundColor Yellow
                        }
                        catch {
                            Write-Host ("  {0,-20}  (unable to read details)" -f $acct.SamAccountName) -ForegroundColor Yellow
                        }
                    }

                    Write-Host ""
                    Write-Host "  To inspect or unlock a specific account:" -ForegroundColor Cyan
                    Write-Host "    .\Invoke-AdfsTroubleshoot.ps1 -Username <samaccountname> -Unlock" -ForegroundColor DarkCyan
                }
            }
            catch {
                Write-Host ("  Search failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
            }
        }
        else {
            Write-Host "  ActiveDirectory module not available." -ForegroundColor Yellow
            Write-Host "  Install it on this machine to list locked accounts:" -ForegroundColor Yellow
            Write-Host "    Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor DarkYellow
        }
    }
}

Write-Host ""
Write-Host ("=" * 64) -ForegroundColor DarkCyan
Write-Host "  Done." -ForegroundColor Cyan
Write-Host ("=" * 64) -ForegroundColor DarkCyan
Write-Host ""
