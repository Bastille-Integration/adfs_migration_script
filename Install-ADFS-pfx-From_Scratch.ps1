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

    [switch]$SkipAppRegistration,

    [switch]$SkipCors,

    [switch]$NonInteractive
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

    if (-not (Test-Path -LiteralPath $FilePath)) {
        Stop-Script "PFX file not found: $FilePath"
    }

    $beforeThumbprints = @(Get-ChildItem Cert:\LocalMachine\My | ForEach-Object { $_.Thumbprint })

    $params = @{
        FilePath          = $FilePath
        CertStoreLocation = 'Cert:\LocalMachine\My'
        ErrorAction       = 'Stop'
    }
    if ($Exportable) { $params['Exportable'] = $true }

    $passwordIsEmpty = Get-SecureStringIsEmpty -Value $Password

    try {
        if (-not $passwordIsEmpty) { $params['Password'] = $Password }
        $imported = Import-PfxCertificate @params
    }
    catch {
        if (-not $passwordIsEmpty) { throw }

        if ($NonInteractive) {
            Stop-Script "PFX import failed and no password was provided. Use -PfxPassword to supply one."
        }

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

    # Try wildcard first
    foreach ($labels in $splitNames) {
        if ($labels[0] -eq '*') {
            $suffix = ($labels | Select-Object -Skip 1) -join '.'
            if (-not [string]::IsNullOrWhiteSpace($suffix)) { return $suffix }
        }
    }

    # Fall back to longest common suffix
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
            # Prefer SANs that also contain 'auth' — more specific ADFS endpoint
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
        $svc.Refresh()
    }

    return ($null -ne $svc -and $svc.Status -eq 'Running')
}

# ---------------------------------------------------------------------------
# Application definitions — one entry per ADFS native client application
# ---------------------------------------------------------------------------

$AppDefinitions = @(
    [PSCustomObject]@{
        GroupName     = 'Admin Console'
        ClientId      = 'admin-console'
        ServiceLabel  = 'admin'
        RedirectPaths = @('/authenticated', '/signin-callback', '/signout-callback')
    },
    [PSCustomObject]@{
        GroupName     = 'DVR Console'
        ClientId      = 'dvr-console'
        ServiceLabel  = 'dvr'
        RedirectPaths = @('/authenticated', '/signin-callback', '/signout-callback')
    },
    [PSCustomObject]@{
        GroupName     = 'Device Dashboard'
        ClientId      = 'device-dashboard'
        ServiceLabel  = 'device'
        RedirectPaths = @('/authenticated', '/signin-callback', '/signout-callback')
    },
    [PSCustomObject]@{
        GroupName     = 'ADAM Console'
        ClientId      = 'adam-console'
        ServiceLabel  = 'explorer'
        RedirectPaths = @('/auth-callback', '/authenticated', '/signin-callback', '/signout-callback')
    },
    [PSCustomObject]@{
        GroupName     = 'ADAM API'
        ClientId      = 'adam-api'
        ServiceLabel  = 'wti'
        RedirectPaths = @('/authenticated', '/signin-callback', '/signout-callback')
    }
)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Test-IsAdmin)) {
    Stop-Script "This script must be run as Administrator."
}

# Validate service account options
$serviceAccountCount = 0
if ($null -ne $ServiceAccountCredential)              { $serviceAccountCount++ }
if (-not [string]::IsNullOrWhiteSpace($GroupServiceAccountIdentifier)) { $serviceAccountCount++ }
if ($UseNetworkService)                               { $serviceAccountCount++ }

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
    Write-Host "Checking ADFS Windows feature..." -ForegroundColor Cyan

    $feature = Get-WindowsFeature -Name ADFS-Federation -ErrorAction SilentlyContinue
    if ($null -eq $feature) {
        Stop-Script "Get-WindowsFeature returned nothing. Ensure this is a Windows Server with the Server Manager module available."
    }

    if ($feature.InstallState -eq 'Installed') {
        Write-Host "ADFS-Federation feature is already installed." -ForegroundColor Green
    }
    else {
        Write-Host "Installing ADFS-Federation feature..." -ForegroundColor Cyan
        try {
            $result = Install-WindowsFeature -Name ADFS-Federation -IncludeManagementTools -ErrorAction Stop
            if ($result.Success) {
                Write-Host "ADFS-Federation installed successfully." -ForegroundColor Green
                if ($result.RestartNeeded -ne 'No') {
                    Write-Host "WARNING: A restart may be required before proceeding." -ForegroundColor Yellow
                    if (-not (Confirm-Action "Continue without restarting? (y/n)")) {
                        Stop-Script "Cancelled. Restart the server and re-run the script."
                    }
                }
            }
            else {
                Stop-Script "ADFS-Federation feature installation failed."
            }
        }
        catch {
            Stop-Script "Failed to install ADFS-Federation: $($_.Exception.Message)"
        }
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

$exportable = -not $NoExportable

try {
    $importedCerts = Import-PfxToLocalMachineMy -FilePath $PfxPath -Password $PfxPassword -Exportable:$exportable -NonInteractive:$NonInteractive
}
catch {
    Stop-Script "PFX import failed: $($_.Exception.Message)"
}

$leafCert = Get-BestLeafCertificate -Certificates $importedCerts

if ($null -eq $leafCert) {
    Stop-Script "No usable leaf certificate with a private key was found after PFX import."
}

$thumbprint  = $leafCert.Thumbprint
$certSans    = @(Get-CertificateDnsNames -Cert $leafCert)
$newSuffix   = Get-NewHostSuffixFromSans -DnsNames $certSans

Write-Host "Certificate imported:" -ForegroundColor Green
Write-Host ("  Subject       : {0}" -f $leafCert.Subject)
Write-Host ("  Thumbprint    : {0}" -f $thumbprint)
Write-Host ("  NotAfter      : {0}" -f $leafCert.NotAfter)
if ($certSans.Count -gt 0) {
    Write-Host ("  SANs          : {0}" -f ($certSans -join ', '))
}

# ---------------------------------------------------------------------------
# Step 3: Grant private key access to ADFS service account
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
    if ($OverrideServiceAccount) {
        $farmParams['OverrideServiceAccount'] = $true
    }
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
catch {
    Stop-Script "Install-AdfsFarm failed: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Step 7: Wait for ADFS service
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Waiting for ADFS service to start..." -ForegroundColor Cyan

if (Wait-AdfsService -TimeoutSeconds 120) {
    Write-Host "ADFS service is running." -ForegroundColor Green
}
else {
    Write-Host "WARNING: ADFS service did not reach Running state within 120 seconds." -ForegroundColor Yellow
    Write-Host "Attempting to continue — some steps may fail if the service is not ready." -ForegroundColor Yellow
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

# Ensure HTTP.SYS bindings are correct regardless of cmdlet result
Write-Host "Verifying HTTP.SYS SSL bindings via netsh..." -ForegroundColor Cyan

try {
    $httpSysBindings = @(Get-HttpSysSslBindings)
    $stale = @($httpSysBindings | Where-Object { $_.CertHash -and $_.CertHash -ine $thumbprint })
    $missing443 = -not ($httpSysBindings | Where-Object { $_.Binding -match ':443$' -and $_.CertHash -ieq $thumbprint })

    if ($stale.Count -eq 0 -and -not $missing443) {
        Write-Host "HTTP.SYS bindings are correct." -ForegroundColor Green
    }
    else {
        # Update stale bindings
        foreach ($b in $stale) {
            $typeArg = "$($b.Type)=$($b.Binding)"
            & netsh http delete sslcert $typeArg 2>&1 | Out-Null
            $r = @(& netsh http add sslcert $typeArg certhash=$thumbprint appid=$($b.AppId) certstorename=$($b.Store) 2>&1)
            $status = if ($LASTEXITCODE -eq 0) { "Updated" } else { "FAILED" }
            $color  = if ($LASTEXITCODE -eq 0) { "Green"   } else { "Red"    }
            Write-Host ("  [{0}] {1}" -f $status, $b.Binding) -ForegroundColor $color
        }

        # Ensure 0.0.0.0:443 is bound if nothing bound it yet
        if ($missing443) {
            $adfsAppId = '{5d89a20c-beab-4389-8f50-3dba3ec5af60}'
            Set-HttpSysSslBinding -IpPort "0.0.0.0:443" -Thumbprint $thumbprint -AppId $adfsAppId
        }
    }
}
catch {
    Write-Host "netsh verification failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# Step 9: Service Communications certificate
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Setting Service Communications certificate..." -ForegroundColor Cyan

try {
    Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $thumbprint -ErrorAction Stop
    Write-Host "Service Communications certificate set." -ForegroundColor Green
}
catch {
    Write-Host "Service Communications update failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# Step 10: CORS trusted origins
# ---------------------------------------------------------------------------

if (-not $SkipCors) {
    Write-Host ""
    Write-Host "Configuring CORS trusted origins from certificate SANs..." -ForegroundColor Cyan

    $corsLabels = @('admin', 'dvr', 'device', 'explorer', 'wti')
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
        Write-Host "CORS origins to set:" -ForegroundColor Gray
        $corsOrigins | ForEach-Object { Write-Host "  $_" }

        try {
            Set-AdfsResponseHeaders -CORSTrustedOrigins $corsOrigins.ToArray() -ErrorAction Stop
            Write-Host "CORS trusted origins configured." -ForegroundColor Green
        }
        catch {
            Write-Host "CORS configuration failed: $($_.Exception.Message)" -ForegroundColor Red
        }
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
# Step 11: Application group and native client app registration
# ---------------------------------------------------------------------------

if (-not $SkipAppRegistration) {
    Write-Host ""
    Write-Host "Registering application groups and native client applications..." -ForegroundColor Cyan

    foreach ($def in $AppDefinitions) {
        $san = Resolve-HostnameFromSans -ServiceLabel $def.ServiceLabel -SanNames $certSans

        if ([string]::IsNullOrWhiteSpace($san)) {
            Write-Host ""
            Write-Host "  [$($def.GroupName)] No matching SAN for label '$($def.ServiceLabel)' — skipped." -ForegroundColor Yellow
            continue
        }

        $redirectUris = @($def.RedirectPaths | ForEach-Object { "https://$san$_" })

        Write-Host ""
        Write-Host "  $($def.GroupName)" -ForegroundColor Cyan
        Write-Host "    Client ID     : $($def.ClientId)"
        Write-Host "    Hostname      : $san"
        Write-Host "    Redirect URIs :"
        $redirectUris | ForEach-Object { Write-Host "      $_" }

        # Create application group (idempotent)
        $existingGroup = Get-AdfsApplicationGroup -ApplicationGroupIdentifier $def.ClientId -ErrorAction SilentlyContinue
        if ($null -eq $existingGroup) {
            try {
                Add-AdfsApplicationGroup `
                    -Name $def.GroupName `
                    -ApplicationGroupIdentifier $def.ClientId `
                    -ErrorAction Stop | Out-Null
                Write-Host "    Application group created." -ForegroundColor Green
            }
            catch {
                Write-Host "    Failed to create application group: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }
        }
        else {
            Write-Host "    Application group already exists." -ForegroundColor Yellow
        }

        # Create native client application (idempotent)
        $existingApp = Get-AdfsNativeClientApplication -ApplicationGroupIdentifier $def.ClientId -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $def.GroupName }

        if ($null -eq $existingApp) {
            try {
                Add-AdfsNativeClientApplication `
                    -ApplicationGroupIdentifier $def.ClientId `
                    -Name $def.GroupName `
                    -Identifier "$($def.ClientId)-client" `
                    -RedirectUri $redirectUris `
                    -ErrorAction Stop | Out-Null
                Write-Host "    Native client application registered." -ForegroundColor Green
            }
            catch {
                Write-Host "    Failed to register native client application: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "    Native client application already exists — updating redirect URIs." -ForegroundColor Yellow
            try {
                Set-AdfsNativeClientApplication `
                    -TargetApplication $existingApp `
                    -RedirectUri $redirectUris `
                    -ErrorAction Stop | Out-Null
                Write-Host "    Redirect URIs updated." -ForegroundColor Green
            }
            catch {
                Write-Host "    Failed to update redirect URIs: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}
else {
    Write-Host ""
    Write-Host "Skipping application registration (-SkipAppRegistration specified)." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Step 12: Restart ADFS service
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
catch {
    Write-Host "ADFS service restart failed: $($_.Exception.Message)" -ForegroundColor Red
}

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
