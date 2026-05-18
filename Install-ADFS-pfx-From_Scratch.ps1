# Version: 2.0
# Requires: Run as Administrator on the target node
# Deploys a fresh ADFS configuration using a PFX certificate.
# Examples:
#   .\Install-ADFS-pfx-From_Scratch.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -ServiceAccountCredential (Get-Credential)
#   .\Install-ADFS-pfx-From_Scratch.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -GroupServiceAccountIdentifier "DOMAIN\adfssvc$"
#   .\Install-ADFS-pfx-From_Scratch.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -ServiceAccountCredential (Get-Credential) -OverrideServiceAccount

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PfxPath,

    [SecureString]$PfxPassword,

    # Resolved from the cert SAN (looks for a SAN segment containing 'adfs') if omitted
    [string]$FederationServiceName,

    [string]$FederationServiceDisplayName = "ADFS Federation Service",

    # Supply one of the three service account options:
    [PSCredential]$ServiceAccountCredential,
    [string]$GroupServiceAccountIdentifier,
    [switch]$UseNetworkService,

    # Required when ServiceAccountCredential is a local or non-domain account
    [switch]$OverrideServiceAccount,

    [switch]$NoExportable,

    [switch]$SkipWindowsFeature,

    [switch]$SkipAdGroups,

    # Creates BN Test / BN User accounts and assigns them to their groups
    [switch]$CreateTestUsers,

    # Optional OU paths for AD object creation; default container if omitted
    [string]$AdGroupsOu,
    [string]$AdUsersOu,

    [switch]$SkipAppRegistration,

    # Skip applying per-group access control policies on Web API applications
    [switch]$SkipAccessControlPolicies,

    [switch]$SkipCors,

    [switch]$NonInteractive
)

# ---------------------------------------------------------------------------
# Claim rules applied to every Web API — maps AD attributes to OIDC claims
# ---------------------------------------------------------------------------

$IssuanceTransformRules = @'
@RuleName = "UPN"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"), query = ";userPrincipalName,tokenGroups;{0}", param = c.Value);

@RuleName = "Groups-Roles"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"), query = ";tokenGroups;{0}", param = c.Value);
'@

# ---------------------------------------------------------------------------
# Application definitions
#
# ServiceLabels: one or more cert SAN service labels whose hostnames feed
#                redirect URIs for this group (DVR and Device share one group)
# ClientId:      used as both the native client Identifier and the Web API
#                Identifier — matches the "paste the client identifier" step
#                in the ADFS wizard
# AccessGroups:  AD security groups that are permitted access to the Web API
#                (applied via "Permit specific group" access control policy)
# ---------------------------------------------------------------------------

$AppDefinitions = @(
    [PSCustomObject]@{
        GroupName     = 'Bastille Admin'
        ClientId      = 'bastille-admin'
        ServiceLabels = @('admin')
        RedirectPaths = @('/authenticated', '/signin-callback', '/signout-callback')
        AccessGroups  = @('Bastille Admins')
    },
    [PSCustomObject]@{
        GroupName     = 'Bastille DVR and Device'
        ClientId      = 'bastille-dvr-device'
        ServiceLabels = @('dvr', 'device')
        RedirectPaths = @('/authenticated', '/signin-callback', '/signout-callback')
        AccessGroups  = @('Bastille Admins', 'Bastille Users')
    },
    [PSCustomObject]@{
        GroupName     = 'Bastille ADAM'
        ClientId      = 'bastille-adam'
        ServiceLabels = @('explorer')
        RedirectPaths = @('/auth-callback', '/authenticated', '/signin-callback', '/signout-callback')
        AccessGroups  = @('Bastille Admins')
    },
    [PSCustomObject]@{
        GroupName     = 'Bastille ADAM API'
        ClientId      = 'bastille-adam-api'
        ServiceLabels = @('wtiapi')
        RedirectPaths = @('/authenticated', '/signin-callback', '/signout-callback')
        AccessGroups  = @('Bastille Admins')
    }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Stop-Script {
    param([string]$Message)
    Write-Error $Message
    exit 1
}

function Confirm-Action {
    param([string]$Prompt)
    if ($NonInteractive) { return $true }
    $answer = Read-Host $Prompt
    return ($answer -match '^(y|yes)$')
}

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SecureStringIsEmpty {
    param([SecureString]$Value)
    if ($null -eq $Value) { return $true }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [string]::IsNullOrEmpty([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
}

function Import-PfxToLocalMachineMy {
    param(
        [string]$FilePath,
        [SecureString]$Password,
        [bool]$Exportable,
        [bool]$NonInteractive = $false
    )

    if (-not (Test-Path -LiteralPath $FilePath)) { Stop-Script "PFX file not found: $FilePath" }

    $beforeThumbprints = @(Get-ChildItem Cert:\LocalMachine\My | ForEach-Object { $_.Thumbprint })
    $params = @{ FilePath = $FilePath; CertStoreLocation = 'Cert:\LocalMachine\My'; ErrorAction = 'Stop' }
    if ($Exportable) { $params['Exportable'] = $true }

    $passwordIsEmpty = Get-SecureStringIsEmpty -Value $Password

    try {
        if (-not $passwordIsEmpty) { $params['Password'] = $Password }
        $imported = Import-PfxCertificate @params
    }
    catch {
        if (-not $passwordIsEmpty) { throw }
        if ($NonInteractive) { Stop-Script "PFX import failed and no password was provided. Use -PfxPassword to supply one." }

        Write-Host "PFX import failed without a password. The file may be password-protected." -ForegroundColor Yellow
        $prompted = Read-Host "Enter PFX password" -AsSecureString
        if (Get-SecureStringIsEmpty -Value $prompted) { Stop-Script "No password entered. Cannot import PFX." }

        $params['Password'] = $prompted
        $imported = Import-PfxCertificate @params
    }

    $after = @(Get-ChildItem Cert:\LocalMachine\My)
    $newCerts = @($after | Where-Object { $beforeThumbprints -notcontains $_.Thumbprint })
    if (-not $newCerts -or $newCerts.Count -eq 0) { $newCerts = @($imported) }
    return ,$newCerts
}

function Get-BestLeafCertificate {
    param([array]$Certificates)

    $candidates = @(
        $Certificates |
        Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'HasPrivateKey' -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending
    )
    if (-not $candidates -or $candidates.Count -eq 0) { return $null }

    foreach ($cert in $candidates) {
        try {
            $bc = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Basic Constraints' }
            if (-not $bc -or $bc.Format($true) -notmatch 'Subject Type=CA') { return $cert }
        }
        catch { return $cert }
    }
    return $candidates[0]
}

function Get-CertificateDnsNames {
    param($Cert)
    $names = @()
    try { if ($null -ne $Cert.DnsNameList) { $names += @($Cert.DnsNameList | ForEach-Object { $_.Unicode }) } } catch {}
    return @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object -Unique)
}

function Get-NewHostSuffixFromSans {
    param([string[]]$DnsNames)

    $splitNames = [System.Collections.Generic.List[string[]]]::new()
    foreach ($name in $DnsNames) { $splitNames.Add(@($name -split '\.')) }

    foreach ($labels in $splitNames) {
        if ($labels[0] -eq '*') {
            $suffix = ($labels | Select-Object -Skip 1) -join '.'
            if (-not [string]::IsNullOrWhiteSpace($suffix)) { return $suffix }
        }
    }

    $minLabels = ($splitNames | ForEach-Object { $_.Count } | Measure-Object -Minimum).Minimum
    if ($minLabels -lt 3) { return $null }

    $firstLabels = $splitNames[0]
    for ($len = $minLabels - 1; $len -ge 2; $len--) {
        $candidate = ($firstLabels | Select-Object -Last $len) -join '.'
        $allMatch = $true
        foreach ($labels in $splitNames) {
            if (($labels | Select-Object -Last $len) -join '.' -ne $candidate) { $allMatch = $false; break }
        }
        if ($allMatch) { return $candidate }
    }
    return $null
}

function Resolve-HostnameFromSans {
    param([string]$ServiceLabel, [string[]]$SanNames)

    $label = $ServiceLabel.Trim().ToLowerInvariant()
    $bestMatch = $null
    $bestScore = -1

    foreach ($san in $SanNames) {
        $firstLabel = ($san -split '\.')[0].ToLowerInvariant()
        $segments   = @($firstLabel -split '-')
        if ($segments -contains $label) {
            $score = 1000 - $firstLabel.Length
            if ($score -gt $bestScore) { $bestScore = $score; $bestMatch = $san }
        }
    }
    return $bestMatch
}

function Find-AdfsSanHostname {
    param([string[]]$SanNames)

    $best = $null
    $bestScore = -1

    foreach ($san in $SanNames) {
        $firstLabel = ($san -split '\.')[0].ToLowerInvariant()
        $segments   = @($firstLabel -split '-')
        if ($segments -contains 'adfs') {
            $score = if ($segments -contains 'auth') { 2 } else { 1 }
            if ($score -gt $bestScore) { $bestScore = $score; $best = $san }
        }
    }
    return $best
}

function Grant-CertPrivateKeyReadAccess {
    param($Cert, [string]$Account)
    try {
        $pk = $Cert.PrivateKey
        if ($null -eq $pk) { Write-Warning "No accessible private key — skipping ACL update for '$Account'."; return }
        $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $pk.CspKeyContainerInfo.UniqueKeyContainerName
        if (-not (Test-Path -LiteralPath $keyPath)) { Write-Warning "Private key file not found at '$keyPath'."; return }
        $acl  = Get-Acl -Path $keyPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Account,
            [System.Security.AccessControl.FileSystemRights]::Read,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $keyPath -AclObject $acl
        Write-Host "Granted private key read access to: $Account" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to grant private key access to '$Account': $($_.Exception.Message)"
    }
}

function Get-HttpSysSslBindings {
    $output = @(& netsh http show sslcert 2>&1)
    $bindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $current = $null

    foreach ($line in $output) {
        if ($line -match '^\s+IP:port\s*:\s*(.+)$') {
            if ($null -ne $current) { [void]$bindings.Add($current) }
            $current = [PSCustomObject]@{ Type = 'ipport'; Binding = $Matches[1].Trim(); CertHash = $null; AppId = $null; Store = 'MY' }
        }
        elseif ($line -match '^\s+Hostname:port\s*:\s*(.+)$') {
            if ($null -ne $current) { [void]$bindings.Add($current) }
            $current = [PSCustomObject]@{ Type = 'hostnameport'; Binding = $Matches[1].Trim(); CertHash = $null; AppId = $null; Store = 'MY' }
        }
        elseif ($null -ne $current) {
            if      ($line -match '^\s+Certificate Hash\s*:\s*(.+)$')       { $current.CertHash = $Matches[1].Trim() }
            elseif  ($line -match '^\s+Application ID\s*:\s*(.+)$')         { $current.AppId    = $Matches[1].Trim() }
            elseif  ($line -match '^\s+Certificate Store Name\s*:\s*(.+)$') {
                $s = $Matches[1].Trim(); if ($s -ne '(null)') { $current.Store = $s }
            }
        }
    }
    if ($null -ne $current) { [void]$bindings.Add($current) }
    return ,$bindings.ToArray()
}

function Set-HttpSysSslBinding {
    param([string]$IpPort, [string]$Thumbprint, [string]$AppId, [string]$Store = 'MY')

    $typeArg = "ipport=$IpPort"
    & netsh http delete sslcert $typeArg 2>&1 | Out-Null
    $result = @(& netsh http add sslcert $typeArg certhash=$Thumbprint appid=$AppId certstorename=$Store 2>&1)

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Bound $IpPort to new certificate" -ForegroundColor Green
    }
    else {
        Write-Host "  Failed to bind $IpPort`: $($result -join ' ')" -ForegroundColor Red
    }
}

function Test-AdfsServiceExists {
    try { $null = Get-Service -Name adfssrv -ErrorAction Stop; return $true }
    catch { return $false }
}

function Wait-AdfsService {
    param([int]$TimeoutSeconds = 120)

    $elapsed = 0
    $svc = Get-Service -Name adfssrv -ErrorAction SilentlyContinue

    while (($null -eq $svc -or $svc.Status -ne 'Running') -and $elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 3
        $elapsed += 3
        $svc = Get-Service -Name adfssrv -ErrorAction SilentlyContinue
        if ($null -ne $svc) { $svc.Refresh() }
    }

    return ($null -ne $svc -and $svc.Status -eq 'Running')
}

function Resolve-AdGroupSid {
    param([string]$GroupName)
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($GroupName)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        return $sid.Value
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Test-IsAdmin)) { Stop-Script "This script must be run as Administrator." }

$serviceAccountCount = 0
if ($null -ne $ServiceAccountCredential)                               { $serviceAccountCount++ }
if (-not [string]::IsNullOrWhiteSpace($GroupServiceAccountIdentifier)) { $serviceAccountCount++ }
if ($UseNetworkService)                                                { $serviceAccountCount++ }

if ($serviceAccountCount -eq 0) {
    Stop-Script "Specify a service account: -ServiceAccountCredential, -GroupServiceAccountIdentifier, or -UseNetworkService."
}
if ($serviceAccountCount -gt 1) {
    Stop-Script "Specify only one of -ServiceAccountCredential, -GroupServiceAccountIdentifier, or -UseNetworkService."
}

# ---------------------------------------------------------------------------
# Step 1: Install Windows Feature
# ---------------------------------------------------------------------------

if (-not $SkipWindowsFeature) {
    Write-Host ""
    Write-Host "Checking required Windows features..." -ForegroundColor Cyan

    # ADFS requires IIS (Web-Server) to host its endpoints
    $requiredFeatures = @('ADFS-Federation', 'Web-Server')
    $toInstall        = [System.Collections.Generic.List[string]]::new()

    foreach ($featureName in $requiredFeatures) {
        $feature = Get-WindowsFeature -Name $featureName -ErrorAction SilentlyContinue
        if ($null -eq $feature) {
            Stop-Script "Get-WindowsFeature returned nothing for '$featureName'. Ensure this is Windows Server with Server Manager available."
        }
        if ($feature.InstallState -eq 'Installed') {
            Write-Host "  $featureName — already installed." -ForegroundColor Green
        }
        else {
            [void]$toInstall.Add($featureName)
            Write-Host "  $featureName — will be installed." -ForegroundColor Yellow
        }
    }

    if ($toInstall.Count -gt 0) {
        Write-Host "Installing: $($toInstall -join ', ') ..." -ForegroundColor Cyan
        try {
            $result = Install-WindowsFeature -Name $toInstall.ToArray() -IncludeManagementTools -ErrorAction Stop
            if (-not $result.Success) { Stop-Script "Windows feature installation failed." }
            Write-Host "Features installed successfully." -ForegroundColor Green
            if ($result.RestartNeeded -ne 'No') {
                Write-Host "WARNING: A restart may be required before proceeding." -ForegroundColor Yellow
                if (-not (Confirm-Action "Continue without restarting? (y/n)")) {
                    Stop-Script "Cancelled. Restart the server and re-run the script."
                }
            }
        }
        catch { Stop-Script "Failed to install Windows features: $($_.Exception.Message)" }
    }
}
else {
    Write-Host ""
    Write-Host "Skipping Windows feature check (-SkipWindowsFeature specified)." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 2: Import PFX
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Importing PFX into Cert:\LocalMachine\My ..." -ForegroundColor Cyan

try {
    $importedCerts = Import-PfxToLocalMachineMy -FilePath $PfxPath -Password $PfxPassword -Exportable:(-not $NoExportable) -NonInteractive:$NonInteractive
}
catch { Stop-Script "PFX import failed: $($_.Exception.Message)" }

$leafCert = Get-BestLeafCertificate -Certificates $importedCerts
if ($null -eq $leafCert) { Stop-Script "No usable leaf certificate with a private key was found after PFX import." }

$thumbprint = $leafCert.Thumbprint
$certSans   = @(Get-CertificateDnsNames -Cert $leafCert)
$newSuffix  = Get-NewHostSuffixFromSans -DnsNames $certSans

Write-Host "Certificate imported:" -ForegroundColor Green
Write-Host ("  Subject    : {0}" -f $leafCert.Subject)
Write-Host ("  Thumbprint : {0}" -f $thumbprint)
Write-Host ("  NotAfter   : {0}" -f $leafCert.NotAfter)
if ($certSans.Count -gt 0) {
    Write-Host ("  SANs       : {0}" -f ($certSans -join ', '))
}

# ---------------------------------------------------------------------------
# Step 3: Grant private key access
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Granting private key access to ADFS service account..." -ForegroundColor Cyan
Grant-CertPrivateKeyReadAccess -Cert $leafCert -Account "NT SERVICE\adfssrv"
if ($null -ne $ServiceAccountCredential) {
    Grant-CertPrivateKeyReadAccess -Cert $leafCert -Account $ServiceAccountCredential.UserName
}

# ---------------------------------------------------------------------------
# Step 4: Resolve Federation Service Name
# ---------------------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($FederationServiceName)) {
    Write-Host ""
    Write-Host "Auto-detecting federation service name from certificate SANs..." -ForegroundColor Cyan
    $FederationServiceName = Find-AdfsSanHostname -SanNames $certSans
    if ([string]::IsNullOrWhiteSpace($FederationServiceName)) {
        Stop-Script "Could not determine the federation service name from the certificate SANs. Provide -FederationServiceName explicitly."
    }
    Write-Host "Auto-detected federation service name: $FederationServiceName" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "Using provided federation service name: $FederationServiceName" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Step 5: Guard against re-configuration
# ---------------------------------------------------------------------------

if (Test-AdfsServiceExists) {
    Write-Host ""
    Write-Host "WARNING: The ADFS service (adfssrv) already exists on this machine." -ForegroundColor Yellow
    Write-Host "Running Install-AdfsFarm on an already-configured node will overwrite the existing configuration." -ForegroundColor Yellow
    if (-not (Confirm-Action "Proceed and overwrite existing ADFS configuration? (y/n)")) {
        Stop-Script "Cancelled by user."
    }
}

# ---------------------------------------------------------------------------
# Step 6: Install ADFS Farm
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Installing ADFS farm..." -ForegroundColor Cyan
Write-Host "  Federation Service Name    : $FederationServiceName"
Write-Host "  Federation Service Display : $FederationServiceDisplayName"
Write-Host "  Certificate Thumbprint     : $thumbprint"

$farmParams = @{
    CertificateThumbprint        = $thumbprint
    FederationServiceName        = $FederationServiceName
    FederationServiceDisplayName = $FederationServiceDisplayName
    ErrorAction                  = 'Stop'
}

if ($null -ne $ServiceAccountCredential) {
    $farmParams['ServiceAccountCredential'] = $ServiceAccountCredential
    if ($OverrideServiceAccount) { $farmParams['OverrideServiceAccount'] = $true }
    Write-Host "  Service Account            : $($ServiceAccountCredential.UserName)"
}
elseif (-not [string]::IsNullOrWhiteSpace($GroupServiceAccountIdentifier)) {
    $farmParams['GroupServiceAccountIdentifier'] = $GroupServiceAccountIdentifier
    Write-Host "  gMSA                       : $GroupServiceAccountIdentifier"
}
elseif ($UseNetworkService) {
    $nsPassword = New-Object System.Security.SecureString
    $farmParams['ServiceAccountCredential'] = New-Object PSCredential("NT AUTHORITY\Network Service", $nsPassword)
    $farmParams['OverrideServiceAccount']   = $true
    Write-Host "  Service Account            : NT AUTHORITY\Network Service"
}

if (-not (Confirm-Action "Proceed with ADFS farm installation? (y/n)")) {
    Stop-Script "Cancelled by user."
}

try {
    Install-AdfsFarm @farmParams | Out-Null
    Write-Host "ADFS farm installation completed." -ForegroundColor Green
}
catch { Stop-Script "Install-AdfsFarm failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# Step 7: Wait for ADFS service
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Waiting for ADFS service to start..." -ForegroundColor Cyan

if (Wait-AdfsService -TimeoutSeconds 120) {
    Write-Host "ADFS service is running." -ForegroundColor Green
}
else {
    Write-Host "WARNING: ADFS service did not reach Running state within 120 seconds. Some steps may fail." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 8: SSL certificate binding
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Binding SSL certificate..." -ForegroundColor Cyan

try {
    Set-AdfsSslCertificate -Thumbprint $thumbprint -ErrorAction Stop
    Write-Host "Set-AdfsSslCertificate completed." -ForegroundColor Green
}
catch {
    Write-Host "Set-AdfsSslCertificate failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Falling back to direct netsh binding." -ForegroundColor Yellow
}

Write-Host "Verifying HTTP.SYS SSL bindings..." -ForegroundColor Cyan

try {
    $httpSysBindings = @(Get-HttpSysSslBindings)
    $stale           = @($httpSysBindings | Where-Object { $_.CertHash -and $_.CertHash -ine $thumbprint })
    $missing443      = -not ($httpSysBindings | Where-Object { $_.Binding -match ':443$' -and $_.CertHash -ieq $thumbprint })

    foreach ($b in $stale) {
        $typeArg = "$($b.Type)=$($b.Binding)"
        & netsh http delete sslcert $typeArg 2>&1 | Out-Null
        $r = @(& netsh http add sslcert $typeArg certhash=$thumbprint appid=$($b.AppId) certstorename=$($b.Store) 2>&1)
        $color = if ($LASTEXITCODE -eq 0) { "Green" } else { "Red" }
        Write-Host ("  {0} {1}" -f $(if ($LASTEXITCODE -eq 0) { "Updated" } else { "FAILED" }), $b.Binding) -ForegroundColor $color
    }

    if ($missing443) {
        Set-HttpSysSslBinding -IpPort "0.0.0.0:443" -Thumbprint $thumbprint -AppId '{5d89a20c-beab-4389-8f50-3dba3ec5af60}'
    }
    elseif ($stale.Count -eq 0) {
        Write-Host "HTTP.SYS bindings are correct." -ForegroundColor Green
    }
}
catch { Write-Host "netsh verification failed: $($_.Exception.Message)" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Step 9: Service Communications certificate
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Setting Service Communications certificate..." -ForegroundColor Cyan

try {
    Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $thumbprint -ErrorAction Stop
    Write-Host "Service Communications certificate set." -ForegroundColor Green
}
catch { Write-Host "Service Communications update failed: $($_.Exception.Message)" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Step 10: CORS trusted origins
# ---------------------------------------------------------------------------

if (-not $SkipCors) {
    Write-Host ""
    Write-Host "Configuring CORS trusted origins from certificate SANs..." -ForegroundColor Cyan

    $corsLabels  = @('admin', 'dvr', 'device', 'explorer', 'wtiapi')
    $corsOrigins = [System.Collections.Generic.List[string]]::new()

    foreach ($label in $corsLabels) {
        $san = Resolve-HostnameFromSans -ServiceLabel $label -SanNames $certSans
        if (-not [string]::IsNullOrWhiteSpace($san)) {
            [void]$corsOrigins.Add("https://$san")
        }
        else {
            Write-Warning "No SAN found for CORS label '$label' — skipped."
        }
    }

    if ($corsOrigins.Count -gt 0) {
        $corsOrigins | ForEach-Object { Write-Host "  $_" }
        try {
            Set-AdfsResponseHeaders -EnableCORS $true -ErrorAction Stop
            Set-AdfsResponseHeaders -CORSTrustedOrigins $corsOrigins.ToArray() -ErrorAction Stop
            Write-Host "CORS enabled and trusted origins configured." -ForegroundColor Green
        }
        catch { Write-Host "CORS configuration failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
    else {
        Write-Host "No CORS origins could be resolved from the certificate SANs." -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "Skipping CORS configuration (-SkipCors specified)." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 11: AD Security Groups (4.2.2)
# ---------------------------------------------------------------------------

if (-not $SkipAdGroups) {
    Write-Host ""
    Write-Host "Creating AD security groups..." -ForegroundColor Cyan

    $adSecurityGroups = @('Bastille Admins', 'Bastille Users')

    foreach ($groupName in $adSecurityGroups) {
        $existing = $null
        try { $existing = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction Stop } catch {}

        if ($null -eq $existing) {
            $adGroupParams = @{
                Name          = $groupName
                GroupScope    = 'Global'
                GroupCategory = 'Security'
                ErrorAction   = 'Stop'
            }
            if (-not [string]::IsNullOrWhiteSpace($AdGroupsOu)) { $adGroupParams['Path'] = $AdGroupsOu }
            try {
                New-ADGroup @adGroupParams | Out-Null
                Write-Host "  [+] Group created: $groupName" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Failed to create group '$groupName': $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  [=] Group already exists: $groupName" -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host ""
    Write-Host "Skipping AD security group creation (-SkipAdGroups specified)." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 12: Test Users and Group Membership (4.2.3 / 4.2.4)
# ---------------------------------------------------------------------------

if ($CreateTestUsers) {
    Write-Host ""
    Write-Host "Creating test AD users..." -ForegroundColor Cyan

    $testUsers = @(
        [PSCustomObject]@{ Name = 'BN Test'; SamAccountName = 'bntest'; Group = 'Bastille Admins' },
        [PSCustomObject]@{ Name = 'BN User'; SamAccountName = 'bnuser'; Group = 'Bastille Users'  }
    )

    foreach ($userDef in $testUsers) {
        $existing = $null
        try { $existing = Get-ADUser -Filter { SamAccountName -eq $userDef.SamAccountName } -ErrorAction Stop } catch {}

        if ($null -eq $existing) {
            $adUserParams = @{
                Name                  = $userDef.Name
                SamAccountName        = $userDef.SamAccountName
                AccountPassword       = (ConvertTo-SecureString 'ChangeMe1!' -AsPlainText -Force)
                Enabled               = $true
                ChangePasswordAtLogon = $false
                ErrorAction           = 'Stop'
            }
            if (-not [string]::IsNullOrWhiteSpace($AdUsersOu)) { $adUserParams['Path'] = $AdUsersOu }
            try {
                New-ADUser @adUserParams | Out-Null
                Write-Host "  [+] User created: $($userDef.Name) ($($userDef.SamAccountName))" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Failed to create user '$($userDef.Name)': $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  [=] User already exists: $($userDef.SamAccountName)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Assigning test users to groups..." -ForegroundColor Cyan

    foreach ($userDef in $testUsers) {
        try {
            Add-ADGroupMember -Identity $userDef.Group -Members $userDef.SamAccountName -ErrorAction Stop
            Write-Host "  [+] $($userDef.SamAccountName) -> $($userDef.Group)" -ForegroundColor Green
        }
        catch {
            Write-Host "  [!] Failed to add '$($userDef.SamAccountName)' to '$($userDef.Group)': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ---------------------------------------------------------------------------
# Step 13: Application groups, native clients, Web APIs, permissions, claims
#
# Each group follows the ADFS wizard pattern:
#   1. Application Group
#   2. Native Client Application  (ClientId = the client identifier)
#   3. Web API Application        (Identifier = same ClientId, per wizard step 8)
#   4. Application Permission     (openid + profile scopes)
#   5. Issuance Transform Rules   (UPN rule + Groups-Roles rule on the Web API)
#   6. Access Control Policy      ("Permit specific group" per AccessGroups)
# ---------------------------------------------------------------------------

if (-not $SkipAppRegistration) {
    Write-Host ""
    Write-Host "Registering Bastille application groups..." -ForegroundColor Cyan

    foreach ($def in $AppDefinitions) {

        # Collect redirect URIs across all service labels for this group
        $redirectUris   = [System.Collections.Generic.List[string]]::new()
        $resolvedLabels = [System.Collections.Generic.List[string]]::new()

        foreach ($label in $def.ServiceLabels) {
            $san = Resolve-HostnameFromSans -ServiceLabel $label -SanNames $certSans
            if ([string]::IsNullOrWhiteSpace($san)) {
                Write-Warning "  No matching SAN for label '$label' in '$($def.GroupName)' — skipped."
                continue
            }
            [void]$resolvedLabels.Add($san)
            foreach ($path in $def.RedirectPaths) {
                [void]$redirectUris.Add("https://$san$path")
            }
        }

        if ($redirectUris.Count -eq 0) {
            Write-Host ""
            Write-Host "  [$($def.GroupName)] No SANs resolved — skipping group." -ForegroundColor Yellow
            continue
        }

        Write-Host ""
        Write-Host "  $($def.GroupName)" -ForegroundColor Cyan
        Write-Host "    Client ID     : $($def.ClientId)"
        Write-Host "    Hostnames     : $($resolvedLabels -join ', ')"
        Write-Host "    Redirect URIs :"
        $redirectUris | ForEach-Object { Write-Host "      $_" }

        # Resolve access control policy for this group
        $accessPolicyName   = "Permit everyone"
        $accessPolicyParams = $null

        if (-not $SkipAccessControlPolicies -and $def.AccessGroups -and $def.AccessGroups.Count -gt 0) {
            $groupSids = [System.Collections.Generic.List[string]]::new()
            foreach ($groupName in $def.AccessGroups) {
                $sid = Resolve-AdGroupSid -GroupName $groupName
                if ($sid) {
                    [void]$groupSids.Add($sid)
                }
                else {
                    Write-Warning "    Could not resolve SID for '$groupName' — using group name as fallback."
                    [void]$groupSids.Add($groupName)
                }
            }
            if ($groupSids.Count -gt 0) {
                $accessPolicyName   = "Permit specific group"
                $accessPolicyParams = @{ GroupParameter = $groupSids.ToArray() }
            }
        }

        # 1. Application Group
        $existingGroup = Get-AdfsApplicationGroup -ApplicationGroupIdentifier $def.ClientId -ErrorAction SilentlyContinue
        if ($null -eq $existingGroup) {
            try {
                Add-AdfsApplicationGroup `
                    -Name $def.GroupName `
                    -ApplicationGroupIdentifier $def.ClientId `
                    -ErrorAction Stop | Out-Null
                Write-Host "    [+] Application group created." -ForegroundColor Green
            }
            catch {
                Write-Host "    [!] Failed to create application group: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }
        }
        else {
            Write-Host "    [=] Application group already exists." -ForegroundColor Yellow
        }

        # 2. Native Client Application
        $existingNative = Get-AdfsNativeClientApplication -ApplicationGroupIdentifier $def.ClientId -ErrorAction SilentlyContinue |
            Where-Object { $_.Identifier -eq $def.ClientId }

        if ($null -eq $existingNative) {
            try {
                Add-AdfsNativeClientApplication `
                    -ApplicationGroupIdentifier $def.ClientId `
                    -Name "$($def.GroupName) - Native" `
                    -Identifier $def.ClientId `
                    -RedirectUri $redirectUris.ToArray() `
                    -ErrorAction Stop | Out-Null
                Write-Host "    [+] Native client application registered." -ForegroundColor Green
            }
            catch {
                Write-Host "    [!] Failed to register native client application: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            try {
                Set-AdfsNativeClientApplication `
                    -TargetApplication $existingNative `
                    -RedirectUri $redirectUris.ToArray() `
                    -ErrorAction Stop | Out-Null
                Write-Host "    [=] Native client application updated." -ForegroundColor Yellow
            }
            catch {
                Write-Host "    [!] Failed to update native client application: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # 3. Web API Application (identifier = same ClientId, matching the wizard's paste-client-id step)
        $webApiName = "$($def.GroupName) - Web API"
        $existingWebApi = Get-AdfsWebApiApplication -ApplicationGroupIdentifier $def.ClientId -ErrorAction SilentlyContinue |
            Where-Object { $_.Identifier -contains $def.ClientId }

        if ($null -eq $existingWebApi) {
            try {
                $addWebApiParams = @{
                    ApplicationGroupIdentifier = $def.ClientId
                    Name                       = $webApiName
                    Identifier                 = $def.ClientId
                    AccessControlPolicyName    = $accessPolicyName
                    ErrorAction                = 'Stop'
                }
                if ($null -ne $accessPolicyParams) {
                    $addWebApiParams['AccessControlPolicyParameters'] = $accessPolicyParams
                }
                Add-AdfsWebApiApplication @addWebApiParams | Out-Null
                Write-Host "    [+] Web API application registered (policy: $accessPolicyName)." -ForegroundColor Green
            }
            catch {
                Write-Host "    [!] Failed to register Web API application: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            # Update access control policy on the existing Web API
            try {
                $updateParams = @{
                    TargetApplication       = $existingWebApi
                    AccessControlPolicyName = $accessPolicyName
                    ErrorAction             = 'Stop'
                }
                if ($null -ne $accessPolicyParams) {
                    $updateParams['AccessControlPolicyParameters'] = $accessPolicyParams
                }
                Set-AdfsWebApiApplication @updateParams | Out-Null
                Write-Host "    [=] Web API application access control policy updated ($accessPolicyName)." -ForegroundColor Yellow
            }
            catch {
                Write-Host "    [!] Failed to update Web API access control policy: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # 4. Application Permission (openid + profile)
        $existingPermission = Get-AdfsApplicationPermission -ErrorAction SilentlyContinue |
            Where-Object { $_.ClientRoleIdentifier -eq $def.ClientId -and $_.ServerRoleIdentifier -eq $def.ClientId }

        if ($null -eq $existingPermission) {
            try {
                Grant-AdfsApplicationPermission `
                    -ClientRoleIdentifier $def.ClientId `
                    -ServerRoleIdentifier $def.ClientId `
                    -ScopeNames @("openid", "profile") `
                    -ErrorAction Stop | Out-Null
                Write-Host "    [+] Application permission granted (openid, profile)." -ForegroundColor Green
            }
            catch {
                Write-Host "    [!] Failed to grant application permission: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "    [=] Application permission already exists." -ForegroundColor Yellow
        }

        # 5. Issuance Transform Rules (UPN + Groups-Roles claim rules on the Web API)
        try {
            Set-AdfsWebApiApplication `
                -TargetIdentifier $def.ClientId `
                -IssuanceTransformRules $IssuanceTransformRules `
                -ErrorAction Stop | Out-Null
            Write-Host "    [+] Claim rules set (UPN, Groups-Roles)." -ForegroundColor Green
        }
        catch {
            Write-Host "    [!] Failed to set claim rules: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
else {
    Write-Host ""
    Write-Host "Skipping application registration (-SkipAppRegistration specified)." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 14: Restart ADFS service
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Restarting ADFS service to apply all changes..." -ForegroundColor Cyan

try {
    Restart-Service -Name adfssrv -Force -ErrorAction Stop
    if (Wait-AdfsService -TimeoutSeconds 60) {
        Write-Host "ADFS service restarted successfully." -ForegroundColor Green
    }
    else {
        Write-Host "ADFS service restart timed out." -ForegroundColor Red
    }
}
catch { Write-Host "ADFS service restart failed: $($_.Exception.Message)" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
Write-Host ("  Federation Service Name : {0}" -f $FederationServiceName) -ForegroundColor DarkGray
Write-Host ("  Certificate Thumbprint  : {0}" -f $thumbprint)             -ForegroundColor DarkGray
if (-not [string]::IsNullOrWhiteSpace($newSuffix)) {
    Write-Host ("  Domain Suffix           : {0}" -f $newSuffix)           -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "Application Groups:" -ForegroundColor DarkGray
foreach ($def in $AppDefinitions) {
    $accessNote = if ($def.AccessGroups -and $def.AccessGroups.Count -gt 0) { " [" + ($def.AccessGroups -join ", ") + "]" } else { "" }
    Write-Host ("  {0}  [{1}]{2}" -f $def.GroupName, $def.ClientId, $accessNote) -ForegroundColor DarkGray
}
