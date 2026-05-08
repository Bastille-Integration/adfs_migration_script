# Requires: Run as Administrator on an ADFS node with the ADFS PowerShell module
# Example:
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx"
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -PfxPassword (Read-Host "PFX Password" -AsSecureString)
# Optional overrides:
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -OldHostSuffix "bn.nga.mil" -NewHostSuffix "rta.fak"

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PfxPath,

    [SecureString]$PfxPassword,

    [string]$OldHostSuffix,

    [string]$NewHostSuffix,

    [string]$ExpectedDnsName,

    [string]$CorsExtraOrigins = '',

    [switch]$NoExportable,

    [switch]$SkipServiceCommunications,

    [switch]$SkipAdfsSsl,

    [switch]$SkipCors,

    [switch]$SkipFederationServiceProperties,

    [switch]$NonInteractive
)

function Stop-Script {
    param([string]$Message)
    Write-Error $Message
    exit 1
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Stop-Script "Unable to verify Administrator privileges: $($_.Exception.Message)"
    }
}

function Import-AdfsSafe {
    try {
        Import-Module ADFS -ErrorAction Stop | Out-Null
    }
    catch {
        Stop-Script "Failed to import ADFS module: $($_.Exception.Message)"
    }
}

function Confirm-Action {
    param([string]$Prompt)

    if ($NonInteractive) {
        return $true
    }

    $answer = Read-Host $Prompt
    return ($answer -match '^(y|yes)$')
}

function Get-SecureStringIsEmpty {
    param([SecureString]$Value)

    if ($null -eq $Value) { return $true }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        return [string]::IsNullOrEmpty($plain)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Get-CertificateDnsNames {
    param($Cert)

    $names = @()

    try {
        if ($null -ne $Cert.DnsNameList) {
            $names += @($Cert.DnsNameList | ForEach-Object { $_.Unicode })
        }
    }
    catch {
    }

    return @(
        $names |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Sort-Object -Unique
    )
}

function Get-NewHostSuffixFromCertificateSans {
    param($Cert)

    $dnsNames = @(Get-CertificateDnsNames -Cert $Cert)
    if ($dnsNames.Count -eq 0) { return $null }

    $splitNames = [System.Collections.Generic.List[string[]]]::new()
    foreach ($name in $dnsNames) {
        $splitNames.Add(@($name -split '\.'))
    }

    $minLabels = ($splitNames | ForEach-Object { $_.Count } | Measure-Object -Minimum).Minimum

    # Need at least host.domain.tld (3 labels) to extract a meaningful suffix
    if ($minLabels -lt 3) { return $null }

    $maxSuffixLen = $minLabels - 1
    $firstLabels = $splitNames[0]

    for ($len = $maxSuffixLen; $len -ge 2; $len--) {
        $candidateSuffix = ($firstLabels | Select-Object -Last $len) -join '.'
        $allMatch = $true
        foreach ($labels in $splitNames) {
            if (($labels | Select-Object -Last $len) -join '.' -ne $candidateSuffix) {
                $allMatch = $false
                break
            }
        }
        if ($allMatch) {
            return $candidateSuffix
        }
    }

    return $null
}

function Get-NewHostSuffixFromCertificateWildcardSan {
    param($Cert)

    if ($null -eq $Cert) {
        return $null
    }

    $dnsNames = @(Get-CertificateDnsNames -Cert $Cert)

    foreach ($name in $dnsNames) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $trimmed = $name.Trim().ToLowerInvariant()
        if ($trimmed.StartsWith('*.')) {
            $suffix = $trimmed.Substring(2)
            if (-not [string]::IsNullOrWhiteSpace($suffix)) {
                return $suffix
            }
        }
    }

    return $null
}

function Get-SubjectCommonName {
    param($Cert)

    if ($null -eq $Cert -or [string]::IsNullOrWhiteSpace($Cert.Subject)) {
        return $null
    }

    if ($Cert.Subject -match '(?i)(?:^|,\s*)CN\s*=\s*([^,]+)') {
        return $matches[1].Trim()
    }

    return $null
}

function Test-CertificateNameMatch {
    param(
        $Cert,
        [string]$ExpectedName
    )

    $expected = $ExpectedName.Trim().ToLowerInvariant()
    $sanNames = Get-CertificateDnsNames -Cert $Cert
    $subjectCn = Get-SubjectCommonName -Cert $Cert
    $subjectCnNorm = $null

    if (-not [string]::IsNullOrWhiteSpace($subjectCn)) {
        $subjectCnNorm = $subjectCn.Trim().ToLowerInvariant()
    }

    $matchedBy = @()

    if ($sanNames -contains $expected) {
        $matchedBy += "SAN"
    }

    if (-not [string]::IsNullOrWhiteSpace($subjectCnNorm) -and $subjectCnNorm -eq $expected) {
        $matchedBy += "Subject CN"
    }

    return [PSCustomObject]@{
        ExpectedName = $ExpectedName
        SubjectCN    = $subjectCn
        SanNames     = $sanNames
        IsMatch      = ($matchedBy.Count -gt 0)
        MatchedBy    = $matchedBy
    }
}

function Get-CertSummary {
    param($Cert)

    if ($null -eq $Cert) { return "<null>" }

    $dnsNames = @()
    try {
        $dnsNames = Get-CertificateDnsNames -Cert $Cert
    }
    catch {
        $dnsNames = @()
    }

    return [PSCustomObject]@{
        Subject       = $Cert.Subject
        Thumbprint    = $Cert.Thumbprint
        NotBefore     = $Cert.NotBefore
        NotAfter      = $Cert.NotAfter
        HasPrivateKey = $Cert.HasPrivateKey
        DnsNameList   = ($dnsNames -join ', ')
    }
}

function Import-PfxToLocalMachineMy {
    param(
        [string]$FilePath,
        [SecureString]$Password,
        [bool]$Exportable
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        Stop-Script "PFX file not found: $FilePath"
    }

    $beforeThumbprints = @(
        Get-ChildItem -Path Cert:\LocalMachine\My |
        ForEach-Object { $_.Thumbprint }
    )

    $params = @{
        FilePath          = $FilePath
        CertStoreLocation = 'Cert:\LocalMachine\My'
        ErrorAction       = 'Stop'
    }

    if ($Exportable) {
        $params['Exportable'] = $true
    }

    $passwordIsEmpty = Get-SecureStringIsEmpty -Value $Password

    try {
        if (-not $passwordIsEmpty) {
            $params['Password'] = $Password
        }

        $imported = Import-PfxCertificate @params
    }
    catch {
        if (-not $passwordIsEmpty) {
            throw
        }

        $params.Remove('Password') | Out-Null
        $imported = Import-PfxCertificate @params
    }

    $after = @(Get-ChildItem -Path Cert:\LocalMachine\My)

    $newCerts = @(
        $after | Where-Object {
            $beforeThumbprints -notcontains $_.Thumbprint
        }
    )

    if (-not $newCerts -or $newCerts.Count -eq 0) {
        $newCerts = @($imported)
    }

    return ,$newCerts
}

function Get-BestLeafCertificate {
    param([array]$Certificates)

    $candidates = @(
        $Certificates |
        Where-Object {
            $_ -and
            $_.PSObject.Properties.Name -contains 'HasPrivateKey' -and
            $_.HasPrivateKey
        } |
        Sort-Object NotAfter -Descending
    )

    if (-not $candidates -or $candidates.Count -eq 0) {
        return $null
    }

    foreach ($cert in $candidates) {
        try {
            $basicConstraints = $cert.Extensions | Where-Object {
                $_.Oid.FriendlyName -eq 'Basic Constraints'
            }

            if (-not $basicConstraints) {
                return $cert
            }

            $formatted = $basicConstraints.Format($true)
            if ($formatted -notmatch 'Subject Type=CA') {
                return $cert
            }
        }
        catch {
            return $cert
        }
    }

    return $candidates[0]
}

function Get-HostSuffixFromCorsTrustedOrigins {
    try {
        $headers = Get-AdfsResponseHeaders -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to read ADFS response headers for suffix detection: $($_.Exception.Message)"
        return $null
    }

    foreach ($origin in @($headers.CORSTrustedOrigins)) {
        if ([string]::IsNullOrWhiteSpace($origin)) { continue }

        $parsed = $null
        if (-not [System.Uri]::TryCreate($origin, [System.UriKind]::Absolute, [ref]$parsed)) {
            continue
        }

        $hostname = $parsed.Host.ToLowerInvariant()
        $parts = $hostname.Split('.')

        if ($parts.Count -ge 3) {
            return (($parts | Select-Object -Skip 1) -join '.')
        }
    }

    return $null
}

function Normalize-UriString {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $v = $Value.Trim()
    if ($v.Length -gt 1 -and $v.EndsWith('/')) {
        $v = $v.Substring(0, $v.Length - 1)
    }

    return $v.ToLowerInvariant()
}

function Parse-OriginList {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    return @(
        $Value -split '[,\s]+' |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Replace-HostSuffix {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UriString,

        [Parameter(Mandatory = $true)]
        [string]$OldSuffix,

        [Parameter(Mandatory = $true)]
        [string]$NewSuffix
    )

    $parsed = $null
    if (-not [System.Uri]::TryCreate($UriString, [System.UriKind]::Absolute, [ref]$parsed)) {
        Write-Warning "Skipping invalid absolute URI: $UriString"
        return $null
    }

    $oldSuffixNorm = $OldSuffix.Trim().ToLowerInvariant()
    $newSuffixNorm = $NewSuffix.Trim().ToLowerInvariant()
    $hostNorm = $parsed.Host.ToLowerInvariant()

    $newHost = $null

    if ($hostNorm -eq $oldSuffixNorm) {
        $newHost = $newSuffixNorm
    }
    elseif ($hostNorm.EndsWith("." + $oldSuffixNorm)) {
        $prefixLength = $parsed.Host.Length - $OldSuffix.Length
        $prefix = $parsed.Host.Substring(0, $prefixLength)
        $newHost = $prefix + $NewSuffix
    }
    else {
        return $null
    }

    $builder = New-Object System.UriBuilder($parsed)
    $builder.Host = $newHost
    return $builder.Uri.AbsoluteUri
}

function Replace-HostUsingSans {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UriString,

        [Parameter(Mandatory = $true)]
        [string[]]$SanNames,

        [string]$OldSuffix
    )

    $parsed = $null
    if (-not [System.Uri]::TryCreate($UriString, [System.UriKind]::Absolute, [ref]$parsed)) {
        Write-Warning "Skipping invalid absolute URI: $UriString"
        return $null
    }

    $oldHost = $parsed.Host.ToLowerInvariant()

    if (-not [string]::IsNullOrWhiteSpace($OldSuffix)) {
        $oldSuffixNorm = $OldSuffix.Trim().ToLowerInvariant()
        if ($oldHost -ne $oldSuffixNorm -and -not $oldHost.EndsWith('.' + $oldSuffixNorm)) {
            return $null
        }
    }

    # Service label is the first dot-delimited segment of the old hostname
    $serviceLabel = ($oldHost -split '\.')[0]

    $newHost = $null
    $bestScore = -1

    foreach ($san in $SanNames) {
        $sanFirstLabel = ($san -split '\.')[0].ToLowerInvariant()
        $sanSegments = @($sanFirstLabel -split '-')

        if ($sanSegments -contains $serviceLabel) {
            # Prefer the match whose first label is shortest (most specific/direct match)
            $score = 1000 - $sanFirstLabel.Length
            if ($score -gt $bestScore) {
                $bestScore = $score
                $newHost = $san
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($newHost)) {
        Write-Warning "No matching SAN found for host '$oldHost' (service label: '$serviceLabel'), skipping: $UriString"
        return $null
    }

    $builder = New-Object System.UriBuilder($parsed)
    $builder.Host = $newHost
    return $builder.Uri.AbsoluteUri
}

function Convert-ToCorsOrigin {
    param([string]$UriString)

    if ([string]::IsNullOrWhiteSpace($UriString)) {
        return $null
    }

    $parsed = $null
    if (-not [System.Uri]::TryCreate($UriString.Trim(), [System.UriKind]::Absolute, [ref]$parsed)) {
        Write-Warning "Skipping invalid CORS URI/origin: $UriString"
        return $null
    }

    $origin = "{0}://{1}" -f $parsed.Scheme.ToLowerInvariant(), $parsed.Host.ToLowerInvariant()

    if (-not $parsed.IsDefaultPort) {
        $origin = "{0}:{1}" -f $origin, $parsed.Port
    }

    return $origin
}

function Replace-SuffixInText {
    param(
        [string]$Text,
        [string]$OldSuffix,
        [string]$NewSuffix
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $escapedOld = [Regex]::Escape($OldSuffix)
    return ([Regex]::Replace($Text, $escapedOld, $NewSuffix, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
}

function Build-ReplacedRedirectList {
    param(
        [string[]]$ExistingRedirects,
        [string]$OldSuffix,
        [string]$NewSuffix,
        [string[]]$SanNames = @()
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $result = New-Object 'System.Collections.Generic.List[string]'

    foreach ($uri in @($ExistingRedirects)) {
        if ([string]::IsNullOrWhiteSpace($uri)) { continue }

        $migrated = $null
        if ($SanNames.Count -gt 0) {
            $migrated = Replace-HostUsingSans -UriString $uri -SanNames $SanNames -OldSuffix $OldSuffix
        }
        else {
            $migrated = Replace-HostSuffix -UriString $uri -OldSuffix $OldSuffix -NewSuffix $NewSuffix
        }

        if (-not [string]::IsNullOrWhiteSpace($migrated)) {
            if ($set.Add($migrated)) {
                [void]$result.Add($migrated)
            }
        }
    }

    return ,$result.ToArray()
}

function Get-AllNativeApps {
    $apps = @()

    foreach ($group in Get-AdfsApplicationGroup | Sort-Object Name) {
        try {
            $nativeApps = @(Get-AdfsNativeClientApplication -ApplicationGroup $group -ErrorAction Stop)
            foreach ($app in $nativeApps) {
                $apps += [PSCustomObject]@{
                    GroupName   = $group.Name
                    AppObject   = $app
                    Name        = $app.Name
                    Identifier  = $app.Identifier
                    RedirectUri = @($app.RedirectUri)
                }
            }
        }
        catch {
            Write-Warning "Failed reading native apps for group '$($group.Name)': $($_.Exception.Message)"
        }
    }

    return ,$apps
}

function Update-NativeAppRedirects {
    param(
        [Parameter(Mandatory = $true)]
        $AppInfo,

        [Parameter(Mandatory = $true)]
        [string]$OldSuffix,

        [Parameter(Mandatory = $true)]
        [string]$NewSuffix,

        [string[]]$SanNames = @()
    )

    $current = @($AppInfo.RedirectUri)
    $updated = Build-ReplacedRedirectList -ExistingRedirects $current -OldSuffix $OldSuffix -NewSuffix $NewSuffix -SanNames $SanNames

    Write-Host ""
    Write-Host "Application Group : $($AppInfo.GroupName)" -ForegroundColor DarkGray
    Write-Host "Native App        : $($AppInfo.Name)" -ForegroundColor Cyan
    Write-Host "Client ID         : $($AppInfo.Identifier)" -ForegroundColor DarkGray

    Write-Host "Current Redirect URIs:" -ForegroundColor Gray
    if ($current.Count -gt 0) {
        $current | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host "  <none>"
    }

    Write-Host "New Redirect URIs (replacement set):" -ForegroundColor Gray
    if ($updated.Count -gt 0) {
        $updated | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host "  <none generated from old suffix match>" -ForegroundColor Yellow
    }

    if ($updated.Count -eq 0) {
        Write-Host "No replacement redirects were generated, so this app was skipped." -ForegroundColor Yellow
        return
    }

    $currentNorm = @($current | ForEach-Object { Normalize-UriString $_ } | Where-Object { $_ } | Sort-Object -Unique)
    $updatedNorm = @($updated | ForEach-Object { Normalize-UriString $_ } | Where-Object { $_ } | Sort-Object -Unique)

    $changed = -not (@(Compare-Object -ReferenceObject $currentNorm -DifferenceObject $updatedNorm).Count -eq 0)
    if (-not $changed) {
        Write-Host "Redirect URI set already matches target state." -ForegroundColor Yellow
        return
    }

    if (-not (Confirm-Action "Replace redirect URIs for this app? (y/n)")) {
        Write-Host "Skipped." -ForegroundColor Yellow
        return
    }

    try {
        Set-AdfsNativeClientApplication `
            -TargetApplication $AppInfo.AppObject `
            -RedirectUri $updated `
            -ErrorAction Stop | Out-Null

        Write-Host "Updated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Update failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Update-FederationServiceProperties {
    param(
        [string]$OldSuffix,
        [string]$NewSuffix
    )

    try {
        $props = Get-AdfsProperties -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to read Federation Service Properties: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $currentDisplayName = $props.DisplayName
    $currentHostName = $props.HostName
    $currentIdentifier = $null

    if ($null -ne $props.Identifier) {
        if ($props.Identifier -is [array]) {
            if ($props.Identifier.Count -gt 0 -and $null -ne $props.Identifier[0]) {
                $currentIdentifier = $props.Identifier[0].AbsoluteUri
            }
        }
        elseif ($props.Identifier.PSObject.Properties.Name -contains 'AbsoluteUri') {
            $currentIdentifier = $props.Identifier.AbsoluteUri
        }
        else {
            $currentIdentifier = [string]$props.Identifier
        }
    }

    $newDisplayName = Replace-SuffixInText -Text $currentDisplayName -OldSuffix $OldSuffix -NewSuffix $NewSuffix
    $newHostName = Replace-SuffixInText -Text $currentHostName -OldSuffix $OldSuffix -NewSuffix $NewSuffix
    $newIdentifier = Replace-SuffixInText -Text $currentIdentifier -OldSuffix $OldSuffix -NewSuffix $NewSuffix

    $changes = @()

    if (-not [string]::IsNullOrWhiteSpace($newDisplayName) -and $newDisplayName -ne $currentDisplayName) {
        $changes += [PSCustomObject]@{
            Property = 'DisplayName'
            Current  = $currentDisplayName
            New      = $newDisplayName
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($newHostName) -and $newHostName -ne $currentHostName) {
        $changes += [PSCustomObject]@{
            Property = 'HostName'
            Current  = $currentHostName
            New      = $newHostName
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($newIdentifier) -and $newIdentifier -ne $currentIdentifier) {
        $changes += [PSCustomObject]@{
            Property = 'Identifier'
            Current  = $currentIdentifier
            New      = $newIdentifier
        }
    }

    Write-Host ""
    Write-Host "Current Federation Service Properties:" -ForegroundColor Gray
    Write-Host "  DisplayName : $currentDisplayName"
    Write-Host "  HostName    : $currentHostName"
    Write-Host "  Identifier  : $currentIdentifier"

    if ($changes.Count -eq 0) {
        Write-Host "No Federation Service Properties matched the old suffix." -ForegroundColor Yellow
        return
    }

    Write-Host "New Federation Service Properties:" -ForegroundColor Gray
    foreach ($change in $changes) {
        Write-Host ("  {0}: {1}" -f $change.Property, $change.New)
    }

    if (-not (Confirm-Action "Apply Federation Service Property changes? (y/n)")) {
        Write-Host "Skipped Federation Service Properties update." -ForegroundColor Yellow
        return
    }

    try {
        $setParams = @{}

        if (-not [string]::IsNullOrWhiteSpace($newDisplayName) -and $newDisplayName -ne $currentDisplayName) {
            $setParams['DisplayName'] = $newDisplayName
        }

        if (-not [string]::IsNullOrWhiteSpace($newHostName) -and $newHostName -ne $currentHostName) {
            $setParams['HostName'] = $newHostName
        }

        if (-not [string]::IsNullOrWhiteSpace($newIdentifier) -and $newIdentifier -ne $currentIdentifier) {
            $setParams['Identifier'] = $newIdentifier
        }

        if ($setParams.Count -eq 0) {
            Write-Host "No Federation Service Property updates were needed." -ForegroundColor Yellow
            return
        }

        Set-AdfsProperties @setParams -ErrorAction Stop | Out-Null
        Write-Host "Federation Service Properties updated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Federation Service Properties update failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Update-CorsTrustedOrigins {
    param(
        [string]$OldSuffix,
        [string]$NewSuffix,
        [string]$ParamExtraOrigins,
        [string[]]$SanNames = @()
    )

    try {
        $headers = Get-AdfsResponseHeaders -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to read ADFS response headers: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $existing = @()
    if ($null -ne $headers.CORSTrustedOrigins) {
        $existing = @($headers.CORSTrustedOrigins)
    }

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $combined = New-Object 'System.Collections.Generic.List[string]'

    foreach ($origin in $existing) {
        if ([string]::IsNullOrWhiteSpace($origin)) { continue }

        $migrated = $null
        if ($SanNames.Count -gt 0) {
            $migrated = Replace-HostUsingSans -UriString $origin -SanNames $SanNames -OldSuffix $OldSuffix
        }
        else {
            $migrated = Replace-HostSuffix -UriString $origin -OldSuffix $OldSuffix -NewSuffix $NewSuffix
        }
        if (-not [string]::IsNullOrWhiteSpace($migrated)) {
            $normalized = Convert-ToCorsOrigin -UriString $migrated
            if (-not [string]::IsNullOrWhiteSpace($normalized)) {
                if ($set.Add($normalized)) {
                    [void]$combined.Add($normalized)
                }
            }
        }
    }

    foreach ($origin in (Parse-OriginList -Value $ParamExtraOrigins)) {
        if ([string]::IsNullOrWhiteSpace($origin)) { continue }

        $normalized = Convert-ToCorsOrigin -UriString $origin
        if (-not [string]::IsNullOrWhiteSpace($normalized)) {
            if ($set.Add($normalized)) {
                [void]$combined.Add($normalized)
            }
        }
    }

    Write-Host ""
    Write-Host "Current CORS Trusted Origins:" -ForegroundColor Gray
    if ($existing.Count -gt 0) {
        $existing | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host "  <none>"
    }

    Write-Host "New CORS Trusted Origins (replacement set):" -ForegroundColor Gray
    if ($combined.Count -gt 0) {
        $combined | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host "  <none generated from old suffix match or extras>" -ForegroundColor Yellow
    }

    if ($combined.Count -eq 0) {
        Write-Host "No replacement CORS origins were generated, so CORS was skipped." -ForegroundColor Yellow
        return
    }

    if (-not (Confirm-Action "Replace CORS trusted origins with this list? (y/n)")) {
        Write-Host "Skipped CORS update." -ForegroundColor Yellow
        return
    }

    try {
        Set-AdfsResponseHeaders -CORSTrustedOrigins $combined.ToArray() -ErrorAction Stop
        Write-Host "CORS updated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "CORS update failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Main ---
if (-not (Test-IsAdmin)) {
    Stop-Script "This script must be run as Administrator."
}

Import-AdfsSafe

$exportable = -not $NoExportable

Write-Host ""
Write-Host "Importing PFX into Cert:\LocalMachine\My ..." -ForegroundColor Cyan

try {
    $importedCerts = Import-PfxToLocalMachineMy -FilePath $PfxPath -Password $PfxPassword -Exportable:$exportable
}
catch {
    Stop-Script "PFX import failed: $($_.Exception.Message)"
}

$leafCert = Get-BestLeafCertificate -Certificates $importedCerts

if ($null -eq $leafCert) {
    Stop-Script "PFX import completed, but no usable leaf certificate with a private key was found in Cert:\LocalMachine\My."
}

$thumbprint = $leafCert.Thumbprint
$certSanNames = @(Get-CertificateDnsNames -Cert $leafCert)

Write-Host "Imported certificate selected:" -ForegroundColor Green
$summary = Get-CertSummary -Cert $leafCert
Write-Host ("  Subject       : {0}" -f $summary.Subject)
Write-Host ("  Thumbprint    : {0}" -f $summary.Thumbprint)
Write-Host ("  NotBefore     : {0}" -f $summary.NotBefore)
Write-Host ("  NotAfter      : {0}" -f $summary.NotAfter)
Write-Host ("  HasPrivateKey : {0}" -f $summary.HasPrivateKey)
if (-not [string]::IsNullOrWhiteSpace($summary.DnsNameList)) {
    Write-Host ("  DNS Names     : {0}" -f $summary.DnsNameList)
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedDnsName)) {
    Write-Host ""
    Write-Host "Checking certificate name match..." -ForegroundColor Cyan

    $nameCheck = Test-CertificateNameMatch -Cert $leafCert -ExpectedName $ExpectedDnsName

    Write-Host ("  Expected Name : {0}" -f $nameCheck.ExpectedName)
    Write-Host ("  Subject CN    : {0}" -f $(if ([string]::IsNullOrWhiteSpace($nameCheck.SubjectCN)) { "<none>" } else { $nameCheck.SubjectCN }))

    if ($nameCheck.SanNames.Count -gt 0) {
        Write-Host "  SAN DNS Names :"
        $nameCheck.SanNames | ForEach-Object { Write-Host ("    " + $_) }
    }
    else {
        Write-Host "  SAN DNS Names : <none>"
    }

    if ($nameCheck.IsMatch) {
        Write-Host ("Certificate name check passed via: {0}" -f ($nameCheck.MatchedBy -join ', ')) -ForegroundColor Green
    }
    else {
        Write-Host "WARNING: Certificate name check failed. Expected name was not found in SAN or Subject CN." -ForegroundColor Yellow

        if (-not (Confirm-Action "Continue anyway? (y/n)")) {
            Write-Host "Cancelled by user." -ForegroundColor Yellow
            exit 0
        }
    }
}

if ([string]::IsNullOrWhiteSpace($NewHostSuffix)) {
    Write-Host ""
    Write-Host "Attempting to auto-detect new host suffix from certificate SANs..." -ForegroundColor Cyan

    $NewHostSuffix = Get-NewHostSuffixFromCertificateWildcardSan -Cert $leafCert

    if ([string]::IsNullOrWhiteSpace($NewHostSuffix)) {
        $NewHostSuffix = Get-NewHostSuffixFromCertificateSans -Cert $leafCert
    }

    if ([string]::IsNullOrWhiteSpace($NewHostSuffix)) {
        Stop-Script "Could not determine new host suffix from certificate SAN. Please provide -NewHostSuffix."
    }

    Write-Host "Auto-detected new host suffix: $NewHostSuffix" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "Using provided new host suffix: $NewHostSuffix" -ForegroundColor Cyan
}

if ([string]::IsNullOrWhiteSpace($OldHostSuffix)) {
    Write-Host ""
    Write-Host "Attempting to auto-detect old host suffix from CORSTrustedOrigins..." -ForegroundColor Cyan

    $OldHostSuffix = Get-HostSuffixFromCorsTrustedOrigins

    if ([string]::IsNullOrWhiteSpace($OldHostSuffix)) {
        Stop-Script "Could not determine old host suffix automatically. Please provide -OldHostSuffix."
    }

    Write-Host "Auto-detected old host suffix: $OldHostSuffix" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "Using provided old host suffix: $OldHostSuffix" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Suffix mapping:" -ForegroundColor Cyan
Write-Host "  Old: $OldHostSuffix"
Write-Host "  New: $NewHostSuffix"

if (-not $NonInteractive) {
    if (-not (Confirm-Action "Proceed with certificate binding and suffix replacement? (y/n)")) {
        Stop-Script "Cancelled by user."
    }
}

$nativeApps = Get-AllNativeApps

if (-not $nativeApps -or $nativeApps.Count -eq 0) {
    Write-Host "No native client applications found." -ForegroundColor Yellow
    $toProcess = @()
}
else {
    Write-Host ""
    Write-Host "Select native apps to process:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $nativeApps.Count; $i++) {
        Write-Host ("{0}. {1}  [{2}]" -f ($i + 1), $nativeApps[$i].Name, $nativeApps[$i].GroupName)
    }

    $toProcess = @()

    if ($NonInteractive) {
        $toProcess = $nativeApps
    }
    else {
        $selection = Read-Host "Selection (all or comma-separated numbers)"
        if ($selection -eq 'all') {
            $toProcess = $nativeApps
        }
        else {
            foreach ($part in ($selection -split ',')) {
                $indexText = $part.Trim()
                if ($indexText -notmatch '^\d+$') {
                    Write-Warning "Ignoring invalid selection: $indexText"
                    continue
                }

                $index = [int]$indexText
                if ($index -lt 1 -or $index -gt $nativeApps.Count) {
                    Write-Warning "Ignoring out-of-range selection: $index"
                    continue
                }

                $toProcess += $nativeApps[$index - 1]
            }
        }
    }

    foreach ($app in $toProcess) {
        Update-NativeAppRedirects -AppInfo $app -OldSuffix $OldHostSuffix -NewSuffix $NewHostSuffix -SanNames $certSanNames
    }
}

if (-not $SkipFederationServiceProperties) {
    Update-FederationServiceProperties -OldSuffix $OldHostSuffix -NewSuffix $NewHostSuffix
}
else {
    Write-Host ""
    Write-Host "Federation Service Properties update skipped because -SkipFederationServiceProperties was specified." -ForegroundColor Yellow
}

if (-not $SkipCors) {
    Update-CorsTrustedOrigins -OldSuffix $OldHostSuffix -NewSuffix $NewHostSuffix -ParamExtraOrigins $CorsExtraOrigins -SanNames $certSanNames
}
else {
    Write-Host ""
    Write-Host "CORS update skipped because -SkipCors was specified." -ForegroundColor Yellow
}

if (-not $SkipServiceCommunications) {
    Write-Host ""
    Write-Host "About to set AD FS Service Communications certificate to thumbprint:" -ForegroundColor Cyan
    Write-Host "  $thumbprint"

    if (Confirm-Action "Apply Service Communications certificate change? (y/n)") {
        try {
            Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $thumbprint -ErrorAction Stop
            Write-Host "Service Communications certificate updated successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "Service Communications update failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Skipped Service Communications update." -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "Skipped Service Communications update because -SkipServiceCommunications was specified." -ForegroundColor Yellow
}

if (-not $SkipAdfsSsl) {
    Write-Host ""
    Write-Host "About to set AD FS SSL certificate to thumbprint:" -ForegroundColor Cyan
    Write-Host "  $thumbprint"

    if (Confirm-Action "Apply AD FS SSL certificate change? (y/n)") {
        try {
            Set-AdfsSslCertificate -Thumbprint $thumbprint -ErrorAction Stop
            Write-Host "AD FS SSL certificate updated successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "AD FS SSL update failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Skipped AD FS SSL update." -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "Skipped AD FS SSL update because -SkipAdfsSsl was specified." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Restarting ADFS service..." -ForegroundColor Cyan

try {
    Restart-Service -Name adfssrv -Force -ErrorAction Stop

    $service = Get-Service -Name adfssrv -ErrorAction Stop
    $timeoutSeconds = 60
    $elapsed = 0

    while ($service.Status -ne 'Running' -and $elapsed -lt $timeoutSeconds) {
        Start-Sleep -Seconds 2
        $elapsed += 2
        $service.Refresh()
    }

    if ($service.Status -eq 'Running') {
        Write-Host "ADFS service restarted successfully." -ForegroundColor Green
    }
    else {
        Write-Host "ADFS service restart timed out. Current status: $($service.Status)" -ForegroundColor Red
    }
}
catch {
    Write-Host "ADFS service restart failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
Write-Host ("Selected thumbprint: {0}" -f $thumbprint) -ForegroundColor DarkGray
Write-Host ("Old suffix        : {0}" -f $OldHostSuffix) -ForegroundColor DarkGray
Write-Host ("New suffix        : {0}" -f $NewHostSuffix) -ForegroundColor DarkGray