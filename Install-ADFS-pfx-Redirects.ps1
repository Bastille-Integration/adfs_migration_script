# Version: 2.7
# Requires: Run as Administrator on an ADFS node with the ADFS PowerShell module
# Example:
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx"
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -PfxPassword (Read-Host "PFX Password" -AsSecureString)
# Optional overrides:
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -OldHostSuffix "bn.nga.mil" -NewHostSuffix "rta.fak"
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -TargetAdfsHostname "wids-auth-adfs-abl17.newdomain.com"
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -Site "home" -SiteOnly   (ADFS host derived from current federation host)
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -PfxPath "C:\Temp\adfs-cert.pfx" -EnableUpdatePassword -TokenCertificateDuration 1825
#   .\Invoke-AdfsCertAndSuffixMigration.ps1 -Version   (or -v)  -> print version and exit

[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    # Print the script version and exit. (-v is an alias.)
    [Parameter(ParameterSetName = 'Version')]
    [Alias('v')]
    [switch]$Version,

    [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
    [string]$PfxPath,

    [SecureString]$PfxPassword,

    [string]$OldHostSuffix,

    [string]$NewHostSuffix,

    # The desired FQDN for the ADFS service (e.g. "wids-auth-adfs-abl17.newdomain.com").
    # Used directly for the Federation Service HostName, Identifier, and CORS origin, so it
    # must be an exact hostname that exists in the certificate SANs.
    # OPTIONAL with -Site: it then defaults to the current federation host, which the site
    # code re-codes (auth.adfs -> auth-<site>.adfs). Without -Site it is required (a domain
    # migration must state the new host); the script prompts interactively if omitted.
    [string]$TargetAdfsHostname,

    [string]$ExpectedDnsName,

    # Optional site code. When supplied, every app host is re-coded to its
    # "<first-label>-<site>" form (e.g. admin -> admin-<site>) as both a redirect URI
    # and a CORS origin, and the ADFS/federation host is site-coded too
    # (auth.adfs -> auth-<site>.adfs). The site host REPLACES the base everywhere, and
    # any previously-deployed site is stripped, so ONLY the named site is registered
    # (no base host, no stale site left behind). Prompted interactively if omitted;
    # leave blank for none.
    [string]$Site = '',

    # DEPRECATED / no-op. -Site now always replaces the base host (and any prior
    # site), so this switch is no longer needed. Accepted so existing invocations
    # do not break.
    [switch]$SiteOnly,

    [string]$CorsExtraOrigins = '',

    [switch]$NoExportable,

    [switch]$SkipServiceCommunications,

    [switch]$SkipAdfsSsl,

    [switch]$SkipCors,

    [switch]$SkipFederationServiceProperties,

    # Enable the ADFS update-password portal endpoint (/adfs/portal/updatepassword/).
    [switch]$EnableUpdatePassword,

    # Set the token-signing/decryption certificate duration (days). 0 = leave unchanged.
    [int]$TokenCertificateDuration = 0,

    # Immediately roll over (regenerate) the token-signing/decryption certificates.
    # DISRUPTIVE: relying parties must re-consume metadata afterward. Opt-in only.
    [switch]$RolloverTokenCerts,

    [switch]$NonInteractive
)

$ScriptVersion = '2.7'

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

function Get-TargetAdfsHostname {
    param(
        [string]$ProvidedValue,
        [string[]]$SanNames,
        [bool]$NonInteractive = $false
    )

    # If a value was already supplied via parameter, validate and return it
    if (-not [string]::IsNullOrWhiteSpace($ProvidedValue)) {
        $hostname = $ProvidedValue.Trim().ToLowerInvariant()
        Write-Host ""
        Write-Host "Using provided target ADFS hostname: $hostname" -ForegroundColor Cyan
        return $hostname
    }

    if ($NonInteractive) {
        Stop-Script "No -TargetAdfsHostname was provided and the script is running non-interactively. Please supply -TargetAdfsHostname."
    }

    Write-Host ""
    Write-Host "Enter the desired ADFS service hostname (FQDN)." -ForegroundColor Cyan
    Write-Host "This will be used for the Federation Service HostName, Identifier, and CORS origin." -ForegroundColor Cyan

    if ($SanNames.Count -gt 0) {
        Write-Host "Certificate SANs available:" -ForegroundColor Gray
        $SanNames | Where-Object { -not $_.StartsWith('*.') } | ForEach-Object { Write-Host "  $_" }
    }

    $hostname = $null
    while ([string]::IsNullOrWhiteSpace($hostname)) {
        $raw = Read-Host "Target ADFS hostname (e.g. wids-auth-adfs-abl17.newdomain.com)"
        $raw = $raw.Trim().ToLowerInvariant()

        if ([string]::IsNullOrWhiteSpace($raw)) {
            Write-Host "Hostname cannot be empty. Please try again." -ForegroundColor Yellow
            continue
        }

        # Basic FQDN sanity check: must contain at least one dot and no spaces
        if ($raw -notmatch '^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$' -or $raw -notmatch '\.') {
            Write-Host "That does not look like a valid FQDN. Please try again." -ForegroundColor Yellow
            continue
        }

        $hostname = $raw
    }

    # Warn if the hostname is not in the cert SANs (not a hard failure - operator may know best)
    if ($SanNames.Count -gt 0) {
        $inSan = $false
        foreach ($san in $SanNames) {
            if ($san -eq $hostname) { $inSan = $true; break }
            if ($san.StartsWith('*.')) {
                $wildcardDomain = $san.Substring(2)
                $parts = $hostname -split '\.'
                if ($parts.Count -ge 2 -and $hostname -eq ($parts[0] + '.' + $wildcardDomain)) {
                    $inSan = $true; break
                }
            }
        }

        if (-not $inSan) {
            Write-Host ""
            Write-Host "WARNING: '$hostname' was not found in the certificate SANs." -ForegroundColor Yellow
            Write-Host "The TLS binding may fail if the certificate does not cover this name." -ForegroundColor Yellow
            if (-not (Confirm-Action "Continue anyway? (y/n)")) {
                Stop-Script "Cancelled by user."
            }
        }
        else {
            Write-Host "Hostname confirmed in certificate SANs." -ForegroundColor Green
        }
    }

    return $hostname
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

    $wildcardSuffixes = @()
    foreach ($name in $dnsNames) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $trimmed = $name.Trim().ToLowerInvariant()
        if ($trimmed.StartsWith('*.')) {
            $suffix = $trimmed.Substring(2)
            if (-not [string]::IsNullOrWhiteSpace($suffix)) { $wildcardSuffixes += $suffix }
        }
    }
    if ($wildcardSuffixes.Count -eq 0) { return $null }

    # A cert may carry several wildcards (e.g. *.bn-wids.internal AND
    # *.adfs.bn-wids.internal). The app-host domain is the base registrable
    # domain, so prefer the SHORTEST wildcard suffix (fewest labels). Otherwise a
    # deeper wildcard like *.adfs.<domain> would hijack the suffix and rewrite
    # admin.<old> as admin.adfs.<new>. The ADFS host is set separately via
    # -TargetAdfsHostname, so it does not need the deeper wildcard here.
    return ($wildcardSuffixes | Sort-Object @{ Expression = { ($_ -split '\.').Count } }, @{ Expression = { $_.Length } } | Select-Object -First 1)
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

    # Wildcard SAN match: *.domain.tld covers expected.domain.tld
    if ($matchedBy.Count -eq 0) {
        foreach ($san in $sanNames) {
            if (-not $san.StartsWith('*.')) { continue }
            $wildcardDomain = $san.Substring(2)
            $expectedParts = $expected -split '\.'
            if ($expectedParts.Count -ge 2 -and ($expected -eq $expectedParts[0] + '.' + $wildcardDomain)) {
                $matchedBy += "Wildcard SAN ($san)"
                break
            }
        }
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
        [bool]$Exportable,
        [bool]$NonInteractive = $false
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

        # Passwordless attempt failed - PFX may be password-protected
        if ($NonInteractive) {
            Stop-Script "PFX import failed and no password was provided. Use -PfxPassword to supply one."
        }

        Write-Host "PFX import failed without a password. The file may be password-protected." -ForegroundColor Yellow
        $promptedPassword = Read-Host "Enter PFX password" -AsSecureString

        if (Get-SecureStringIsEmpty -Value $promptedPassword) {
            Stop-Script "No password entered. Cannot import PFX."
        }

        $params['Password'] = $promptedPassword
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

function Grant-CertPrivateKeyReadAccess {
    param(
        $Cert,
        [string]$Account
    )

    try {
        $privateKey = $Cert.PrivateKey
        if ($null -eq $privateKey) {
            Write-Warning "Certificate has no accessible private key - skipping ACL update for '$Account'."
            return
        }

        $keyContainerName = $privateKey.CspKeyContainerInfo.UniqueKeyContainerName
        $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyContainerName

        if (-not (Test-Path -LiteralPath $keyPath)) {
            Write-Warning "Private key file not found at '$keyPath' - skipping ACL update for '$Account'."
            return
        }

        $acl = Get-Acl -Path $keyPath
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
                $s = $Matches[1].Trim()
                if ($s -ne '(null)') { $current.Store = $s }
            }
        }
    }
    if ($null -ne $current) { [void]$bindings.Add($current) }

    return ,$bindings.ToArray()
}

function Select-StaleFederationBindings {
    # From a list of HTTP.SYS bindings, return the hostnameport bindings on the ADFS
    # ports (443/49443) whose PARENT domain (everything after the first label) equals
    # KeepHost's parent, but whose hostname is neither KeepHost nor localhost - i.e.
    # sibling/leftover federation hosts from earlier runs, sites, or domains
    # (auth.adfs.<d>, auth-office.adfs.<d>, auth-backup.adfs.<d> when keeping
    # auth-home.adfs.<d>). Matching on the parent domain isolates federation hosts and
    # leaves app hosts (admin.<d>, a different parent) and unrelated :443 sites alone.
    # Pure/testable (no netsh).
    param($Bindings, [string]$KeepHost)

    if ([string]::IsNullOrWhiteSpace($KeepHost)) { return @() }
    $keep = $KeepHost.Trim().ToLowerInvariant()
    $keepParts = $keep -split '\.', 2
    if ($keepParts.Count -lt 2) { return @() }
    $parent = $keepParts[1]
    $ports = @('443', '49443')

    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($b in @($Bindings)) {
        if ($b.Type -ne 'hostnameport') { continue }
        $idx = $b.Binding.LastIndexOf(':')
        if ($idx -lt 1) { continue }
        $h = $b.Binding.Substring(0, $idx).Trim().ToLowerInvariant()
        $p = $b.Binding.Substring($idx + 1).Trim()
        if ($ports -notcontains $p) { continue }
        if ($h -eq 'localhost' -or $h -eq $keep) { continue }
        $hParts = $h -split '\.', 2
        if ($hParts.Count -lt 2) { continue }
        if ($hParts[1] -eq $parent) { [void]$out.Add($b) }
    }
    return $out.ToArray()
}

function Update-HttpSysSslBinding {
    param(
        $Binding,
        [string]$NewThumbprint
    )

    $typeArg = "$($Binding.Type)=$($Binding.Binding)"

    & netsh http delete sslcert $typeArg 2>&1 | Out-Null

    $result = @(& netsh http add sslcert $typeArg `
        certhash=$NewThumbprint `
        appid=$($Binding.AppId) `
        certstorename=$($Binding.Store) 2>&1)

    if ($LASTEXITCODE -eq 0) {
        Write-Host ("  Updated [{0}] {1}" -f $Binding.Type, $Binding.Binding) -ForegroundColor Green
    }
    else {
        Write-Host ("  Failed [{0}] {1}: {2}" -f $Binding.Type, $Binding.Binding, ($result -join ' ')) -ForegroundColor Red
    }
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

function Get-MostCommonHostSuffix {
    # Given a set of hostnames, return the parent suffix shared by the MOST of them.
    # Candidate suffixes are each host's parent (first label stripped); the winner is
    # the suffix that the greatest number of hosts end with, tie-broken by the fewest
    # labels (the more general/base domain). This avoids picking a deeper federation-
    # host suffix (e.g. adfs.<domain>, shared by only the one ADFS host) over the base
    # app-host domain (<domain>) that every host shares.
    param([string[]]$Hosts)

    $hs = @($Hosts |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim().ToLowerInvariant() })
    if ($hs.Count -eq 0) { return $null }

    $candidates = @()
    foreach ($h in $hs) {
        $parts = $h.Split('.')
        if ($parts.Count -ge 3) {
            $candidates += (($parts | Select-Object -Skip 1) -join '.')
        }
    }
    $candidates = @($candidates | Sort-Object -Unique)
    if ($candidates.Count -eq 0) { return $null }

    $best = $null; $bestScore = -1; $bestLabels = [int]::MaxValue
    foreach ($c in $candidates) {
        $score  = @($hs | Where-Object { $_ -eq $c -or $_.EndsWith('.' + $c) }).Count
        $labels = ($c.Split('.')).Count
        if ($score -gt $bestScore -or ($score -eq $bestScore -and $labels -lt $bestLabels)) {
            $best = $c; $bestScore = $score; $bestLabels = $labels
        }
    }
    return $best
}

function Get-HostSuffixFromCorsTrustedOrigins {
    try {
        $headers = Get-AdfsResponseHeaders -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to read ADFS response headers for suffix detection: $($_.Exception.Message)"
        return $null
    }

    $hosts = @()
    foreach ($origin in @($headers.CORSTrustedOrigins)) {
        if ([string]::IsNullOrWhiteSpace($origin)) { continue }

        $parsed = $null
        if (-not [System.Uri]::TryCreate($origin, [System.UriKind]::Absolute, [ref]$parsed)) {
            continue
        }
        $hosts += $parsed.Host
    }

    return (Get-MostCommonHostSuffix -Hosts $hosts)
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

    # Capture the labels above OldSuffix as both a dotted prefix (preserves the
    # original structure, e.g. wids-auth.adfs-abl15) and a hyphen-collapsed service
    # label (for segment/flat-SAN fallback matching). The matcher below prefers a
    # SAN that keeps the dotted prefix, so multi-label hosts are not flattened.
    $hostParts   = $oldHost -split '\.'
    $domainDepth = if (-not [string]::IsNullOrWhiteSpace($OldSuffix)) {
                       ($OldSuffix.Trim().ToLowerInvariant() -split '\.').Count
                   } else { 0 }
    $subParts    = if ($domainDepth -gt 0 -and $hostParts.Count -gt $domainDepth) {
                       $hostParts[0..($hostParts.Count - $domainDepth - 1)]
                   } else { @($hostParts[0]) }
    $serviceLabel = $subParts -join '-'
    # Dotted prefix preserves the original multi-label structure so the ADFS host
    # wids-auth.adfs-abl15 keeps its dot instead of collapsing to wids-auth-adfs-abl15.
    $oldPrefix = ($subParts -join '.').ToLowerInvariant()

    $newHost = $null
    $bestScore = -1

    foreach ($san in $SanNames) {
        $sanHost = $san.ToLowerInvariant()
        $sanFirstLabel = ($sanHost -split '\.')[0]
        $sanSegments = @($sanFirstLabel -split '-')

        $score = -1
        if ($sanHost.StartsWith($oldPrefix + '.')) {
            # Structure-preserving: the SAN keeps the exact subdomain prefix and only the
            # domain suffix changed (wids-auth.adfs-abl15.<old> -> wids-auth.adfs-abl15.<new>).
            # Strongest, and it leaves the original dotted form intact.
            $score = 3000
        }
        elseif ($sanFirstLabel -eq $serviceLabel) {
            # Collapsed label equals a flat SAN first label (wids-auth-adfs-abl15);
            # only used when the cert has no structure-preserving SAN.
            $score = 2000
        }
        elseif ($sanSegments -contains $serviceLabel) {
            # Service token appears as a hyphen segment (admin -> wids-admin-abl15).
            # Prefer the match whose first label is shortest (most specific/direct match).
            $score = 1000 - $sanFirstLabel.Length
        }
        if ($score -gt $bestScore) {
            $bestScore = $score
            $newHost = $san
        }
    }

    if ([string]::IsNullOrWhiteSpace($newHost)) {
        # Wildcard fallback: old-suffix filter above already confirmed this host should be
        # migrated; pair the original service label with the wildcard's domain. Prefer the
        # SHORTEST wildcard (base domain) so a deeper *.adfs.<domain> does not splice an
        # extra label into app hosts (admin.<old> -> admin.adfs.<new>).
        $wild = @($SanNames | Where-Object { $_.StartsWith('*.') } |
            Sort-Object @{ Expression = { ($_ -split '\.').Count } }, @{ Expression = { $_.Length } })
        if ($wild.Count -gt 0) {
            $newHost = $serviceLabel + '.' + $wild[0].Substring(2)
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

function Resolve-HostnameFromSans {
    param(
        [string]$OldHostname,
        [string[]]$SanNames,
        [string]$OldSuffix
    )

    if ([string]::IsNullOrWhiteSpace($OldHostname)) { return $null }

    $oldHost = $OldHostname.Trim().ToLowerInvariant()

    if (-not [string]::IsNullOrWhiteSpace($OldSuffix)) {
        $oldSuffixNorm = $OldSuffix.Trim().ToLowerInvariant()
        if ($oldHost -ne $oldSuffixNorm -and -not $oldHost.EndsWith('.' + $oldSuffixNorm)) {
            return $null
        }
    }

    # Capture the labels above OldSuffix as both a dotted prefix (preserves the
    # original structure, e.g. wids-auth.adfs-abl15) and a hyphen-collapsed service
    # label (for segment/flat-SAN fallback matching). The matcher below prefers a
    # SAN that keeps the dotted prefix, so multi-label hosts are not flattened.
    $hostParts   = $oldHost -split '\.'
    $domainDepth = if (-not [string]::IsNullOrWhiteSpace($OldSuffix)) {
                       ($OldSuffix.Trim().ToLowerInvariant() -split '\.').Count
                   } else { 0 }
    $subParts    = if ($domainDepth -gt 0 -and $hostParts.Count -gt $domainDepth) {
                       $hostParts[0..($hostParts.Count - $domainDepth - 1)]
                   } else { @($hostParts[0]) }
    $serviceLabel = $subParts -join '-'
    # Dotted prefix preserves the original multi-label structure (wids-auth.adfs-abl15
    # stays dotted rather than collapsing to wids-auth-adfs-abl15).
    $oldPrefix = ($subParts -join '.').ToLowerInvariant()

    $bestMatch = $null
    $bestScore = -1

    foreach ($san in $SanNames) {
        $sanHost = $san.ToLowerInvariant()
        $sanFirstLabel = ($sanHost -split '\.')[0]
        $sanSegments = @($sanFirstLabel -split '-')
        $score = -1
        if ($sanHost.StartsWith($oldPrefix + '.')) {
            # Structure-preserving: SAN keeps the exact subdomain prefix, only the domain
            # changed (wids-auth.adfs-abl15.<old> -> wids-auth.adfs-abl15.<new>). Strongest.
            $score = 3000
        }
        elseif ($sanFirstLabel -eq $serviceLabel) {
            # Collapsed label equals a flat SAN first label (wids-auth-adfs-abl15);
            # only used when the cert has no structure-preserving SAN.
            $score = 2000
        }
        elseif ($sanSegments -contains $serviceLabel) {
            $score = 1000 - $sanFirstLabel.Length
        }
        if ($score -gt $bestScore) {
            $bestScore = $score
            $bestMatch = $san
        }
    }

    if ([string]::IsNullOrWhiteSpace($bestMatch)) {
        # Wildcard fallback: old-suffix filter above already confirmed this host should be
        # migrated; pair the original service label with the wildcard's domain. Prefer the
        # SHORTEST wildcard (base domain) so a deeper *.adfs.<domain> does not add a label.
        $wild = @($SanNames | Where-Object { $_.StartsWith('*.') } |
            Sort-Object @{ Expression = { ($_ -split '\.').Count } }, @{ Expression = { $_.Length } })
        if ($wild.Count -gt 0) {
            $bestMatch = $serviceLabel + '.' + $wild[0].Substring(2)
        }
    }

    if ([string]::IsNullOrWhiteSpace($bestMatch)) {
        Write-Warning "No matching SAN found for hostname '$OldHostname' (service label: '$serviceLabel')"
    }

    return $bestMatch
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

function Get-SiteCodeFromAdfsHost {
    # Infer the currently-deployed site code from a federation hostname: the trailing
    # hyphen segment of its first DNS label, when that label has more than one
    # segment. auth-home.adfs.<d> -> 'home'; auth.adfs.<d> -> ''; the flat
    # wids-auth-adfs-abl16.<d> -> 'abl16'. Used so a site switch strips the old site
    # rather than stacking. Returns '' when no site can be inferred.
    param([string]$Hostname)
    if ([string]::IsNullOrWhiteSpace($Hostname)) { return '' }
    $first = ($Hostname -split '\.')[0]
    $segs = $first -split '-'
    if ($segs.Count -lt 2) { return '' }
    return $segs[-1]
}

function Add-SiteToHost {
    # Set the first DNS label's site code to "-<Site>", removing an existing
    # "-<CurrentSite>" suffix first so switching sites does not stack
    # (admin-home + Site office, CurrentSite home -> admin-office). With no
    # CurrentSite this is a plain append (admin -> admin-<Site>). Returns $null if
    # no site/host, or the label already carries "-<Site>" (idempotent no-op signal).
    param([string]$Hostname, [string]$Site, [string]$CurrentSite = '')
    if ([string]::IsNullOrWhiteSpace($Site) -or [string]::IsNullOrWhiteSpace($Hostname)) { return $null }
    $labels = $Hostname -split '\.'
    if ([string]::IsNullOrWhiteSpace($labels[0])) { return $null }
    $first = $labels[0]
    if ($first -match ('-' + [regex]::Escape($Site) + '$')) { return $null }
    if (-not [string]::IsNullOrWhiteSpace($CurrentSite) -and
        $CurrentSite -ne $Site -and
        $first -match ('-' + [regex]::Escape($CurrentSite) + '$')) {
        $first = $first.Substring(0, $first.Length - ($CurrentSite.Length + 1))
    }
    $labels[0] = $first + '-' + $Site
    return ($labels -join '.')
}

function Add-SiteToUri {
    # Site-code the host of a full URI, preserving scheme/path/port.
    param([string]$UriString, [string]$Site, [string]$CurrentSite = '')
    $u = $null
    if (-not [System.Uri]::TryCreate($UriString, [System.UriKind]::Absolute, [ref]$u)) { return $null }
    $newHost = Add-SiteToHost -Hostname $u.Host -Site $Site -CurrentSite $CurrentSite
    if ([string]::IsNullOrWhiteSpace($newHost)) { return $null }
    $b = New-Object System.UriBuilder($u)
    $b.Host = $newHost
    return $b.Uri.AbsoluteUri
}

function Build-ReplacedRedirectList {
    param(
        [string[]]$ExistingRedirects,
        [string]$OldSuffix,
        [string]$NewSuffix,
        [string[]]$SanNames = @(),
        [string]$Site = '',
        # The currently-deployed site code (inferred from the federation host), so a
        # site switch strips it before applying the new one instead of stacking.
        [string]$CurrentSite = '',
        # Deprecated/no-op: -Site now always replaces the base host. Accepted so
        # existing invocations do not break.
        [switch]$SiteOnly
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

        if ([string]::IsNullOrWhiteSpace($migrated)) { continue }

        # With a site code, the site host REPLACES the base host (and any prior site
        # is stripped via CurrentSite), so only the named site is ever registered.
        # Add-SiteToUri returns null when the host is already on the target site;
        # keep it as-is in that case.
        if (-not [string]::IsNullOrWhiteSpace($Site)) {
            $siteUri = Add-SiteToUri -UriString $migrated -Site $Site -CurrentSite $CurrentSite
            $emit = if ([string]::IsNullOrWhiteSpace($siteUri)) { $migrated } else { $siteUri }
            if ($set.Add($emit)) { [void]$result.Add($emit) }
            continue
        }

        if ($set.Add($migrated)) {
            [void]$result.Add($migrated)
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

        [string[]]$SanNames = @(),

        [string]$Site = '',

        [string]$CurrentSite = '',

        [switch]$SiteOnly
    )

    $current = @($AppInfo.RedirectUri)
    $updated = Build-ReplacedRedirectList -ExistingRedirects $current -OldSuffix $OldSuffix -NewSuffix $NewSuffix -SanNames $SanNames -Site $Site -CurrentSite $CurrentSite

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
        [string]$NewSuffix,
        [string[]]$SanNames = @(),
        # When supplied, HostName and Identifier are set directly to this FQDN / a URI
        # built from it, rather than being derived from heuristics.
        [string]$TargetAdfsHostname = ''
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

    # DisplayName is human-readable text. In heuristic mode a suffix swap is enough;
    # in explicit mode it is aligned to the target hostname below so it matches HostName.
    $newDisplayName = Replace-SuffixInText -Text $currentDisplayName -OldSuffix $OldSuffix -NewSuffix $NewSuffix

    if (-not [string]::IsNullOrWhiteSpace($TargetAdfsHostname)) {
        # --- Explicit hostname mode ---
        # Set HostName directly to what the operator specified.
        $newHostName = $TargetAdfsHostname.Trim().ToLowerInvariant()
        # Keep DisplayName consistent with the new HostName (avoids a stale prefix
        # like auth.adfs.<domain> when the host is auth-<site>.adfs.<domain>).
        $newDisplayName = $newHostName

        # Rebuild Identifier by replacing only the host portion of the existing URI,
        # preserving its scheme, path, and query so the federation metadata URL stays valid.
        $newIdentifier = $null
        if (-not [string]::IsNullOrWhiteSpace($currentIdentifier)) {
            $parsedId = $null
            if ([System.Uri]::TryCreate($currentIdentifier, [System.UriKind]::Absolute, [ref]$parsedId)) {
                $builder = New-Object System.UriBuilder($parsedId)
                $builder.Host = $newHostName
                $newIdentifier = $builder.Uri.AbsoluteUri
            }
            else {
                # Not a valid URI - fall back to plain text suffix replacement
                $newIdentifier = Replace-SuffixInText -Text $currentIdentifier -OldSuffix $OldSuffix -NewSuffix $NewSuffix
            }
        }
    }
    elseif ($SanNames.Count -gt 0) {
        # --- SAN heuristic mode (no explicit hostname supplied) ---
        $newHostName = Resolve-HostnameFromSans -OldHostname $currentHostName -SanNames $SanNames -OldSuffix $OldSuffix

        $newIdentifier = $null
        if (-not [string]::IsNullOrWhiteSpace($currentIdentifier)) {
            $newIdentifier = Replace-HostUsingSans -UriString $currentIdentifier -SanNames $SanNames -OldSuffix $OldSuffix
        }
    }
    else {
        $newHostName = Replace-SuffixInText -Text $currentHostName -OldSuffix $OldSuffix -NewSuffix $NewSuffix
        $newIdentifier = Replace-SuffixInText -Text $currentIdentifier -OldSuffix $OldSuffix -NewSuffix $NewSuffix
    }

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

function Resolve-AppCorsOrigins {
    param(
        [string[]]$SanNames,
        [string]$TargetAdfsHostname,
        [string]$OldSuffix = '',
        [string]$NewSuffix = '',
        [string]$ParamExtraOrigins = '',
        [string]$Site = '',
        # Currently-deployed site code (from the federation host); a site switch
        # strips it instead of stacking.
        [string]$CurrentSite = '',
        # Deprecated/no-op: -Site now always replaces the base app origin.
        [switch]$SiteOnly
    )

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $result = New-Object 'System.Collections.Generic.List[string]'
    $adfsOrigin = $null

    Write-Host ""
    Write-Host "Resolving CORS trusted origins..." -ForegroundColor Cyan

    if (-not [string]::IsNullOrWhiteSpace($TargetAdfsHostname)) {
        $origin = "https://" + $TargetAdfsHostname.Trim().ToLowerInvariant()
        $adfsOrigin = $origin
        if ($set.Add($origin)) {
            [void]$result.Add($origin)
            Write-Host "  + $origin  [ADFS hostname]" -ForegroundColor DarkCyan
        }
    }

    # Try cert SANs first (host-specific certs with explicit app SANs). The label
    # list covers the Bastille browser apps that need a CORS origin. 'wti' and
    # 'wtiapi' are distinct hyphen segments, so each matches only its own host
    # (wids-wti-* vs wids-wtiapi-*).
    foreach ($label in @('admin', 'dvr', 'device', 'explorer', 'lighthouse', 'wtiapi', 'wti')) {
        foreach ($san in ($SanNames | Where-Object { -not $_.StartsWith('*.') })) {
            $firstLabel = ($san -split '\.')[0].ToLowerInvariant()
            if (@($firstLabel -split '-') -contains $label) {
                $origin = "https://$san"
                if ($set.Add($origin)) {
                    [void]$result.Add($origin)
                    Write-Host "  + $origin  [cert SAN label: $label]" -ForegroundColor DarkCyan
                }
                break
            }
        }
    }

    # Supplement from native app redirect URIs - covers wildcard-cert deployments
    # where app hostnames do not appear individually in the cert SANs.
    # Redirect URIs are already on the new suffix (updated earlier in the script),
    # so migration is a no-op for already-current URIs and corrects any that were
    # skipped during the redirect update step.
    try {
        foreach ($group in (Get-AdfsApplicationGroup -ErrorAction Stop | Sort-Object Name)) {
            foreach ($app in @(Get-AdfsNativeClientApplication -ApplicationGroup $group -ErrorAction SilentlyContinue)) {
                foreach ($uri in @($app.RedirectUri)) {
                    $newUri = $null
                    if ($SanNames.Count -gt 0) {
                        $newUri = Replace-HostUsingSans -UriString $uri -SanNames $SanNames -OldSuffix $OldSuffix
                    }
                    if ([string]::IsNullOrWhiteSpace($newUri) -and
                        -not [string]::IsNullOrWhiteSpace($OldSuffix) -and
                        -not [string]::IsNullOrWhiteSpace($NewSuffix)) {
                        $newUri = Replace-HostSuffix -UriString $uri -OldSuffix $OldSuffix -NewSuffix $NewSuffix
                    }
                    # If both migration paths returned null the URI is already on the
                    # new suffix (or is unrelated); use it as-is.
                    if ([string]::IsNullOrWhiteSpace($newUri)) { $newUri = $uri }

                    $normalized = Convert-ToCorsOrigin -UriString $newUri
                    if (-not [string]::IsNullOrWhiteSpace($normalized) -and $set.Add($normalized)) {
                        [void]$result.Add($normalized)
                        Write-Host "  + $normalized  [redirect URI: $($app.Name)]" -ForegroundColor DarkCyan
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Could not read native app redirect URIs for CORS resolution: $($_.Exception.Message)"
    }

    foreach ($origin in (Parse-OriginList -Value $ParamExtraOrigins)) {
        $normalized = Convert-ToCorsOrigin -UriString $origin
        if (-not [string]::IsNullOrWhiteSpace($normalized) -and $set.Add($normalized)) {
            [void]$result.Add($normalized)
            Write-Host "  + $normalized  [extra origin]" -ForegroundColor DarkCyan
        }
    }

    # Add a site-coded variant for each APP origin (admin -> admin-<site>). The
    # ADFS host origin ($adfsOrigin) is excluded because the caller already passes
    # it site-coded (TargetAdfsHostname = effective host); skipping avoids double-coding.
    if (-not [string]::IsNullOrWhiteSpace($Site)) {
        # The site host REPLACES the base app origin (and any prior site is stripped
        # via CurrentSite), so only the named site is registered. The ADFS origin is
        # already on the effective (site-coded) host, so it is preserved as-is.
        $appOrigins = @($result | Where-Object { $_ -ne $adfsOrigin })
        $set.Clear()
        $result = New-Object 'System.Collections.Generic.List[string]'
        if (-not [string]::IsNullOrWhiteSpace($adfsOrigin) -and $set.Add($adfsOrigin)) {
            [void]$result.Add($adfsOrigin)
        }
        foreach ($o in $appOrigins) {
            $parsed = $null
            if (-not [System.Uri]::TryCreate($o, [System.UriKind]::Absolute, [ref]$parsed)) { continue }
            $siteHost = Add-SiteToHost -Hostname $parsed.Host -Site $Site -CurrentSite $CurrentSite
            # Already on the target site (returns null) -> keep the origin as-is.
            $emitHost = if ([string]::IsNullOrWhiteSpace($siteHost)) { $parsed.Host } else { $siteHost }
            $emit = $parsed.Scheme + '://' + $emitHost
            if ($set.Add($emit)) {
                [void]$result.Add($emit)
                Write-Host "  + $emit  [site: $Site]" -ForegroundColor DarkCyan
            }
        }
    }

    # Return a flat array (no leading comma). The caller wraps this in @(), and a
    # comma-wrapped return would nest as Object[1] -> when bound to the [string[]]
    # ProposedOrigins parameter it collapses to a single space-joined string.
    return $result.ToArray()
}

function Update-CorsTrustedOrigins {
    param(
        [string]$OldSuffix,
        [string]$NewSuffix,
        [string]$ParamExtraOrigins,
        [string[]]$SanNames = @(),
        # When supplied the primary ADFS origin is built directly from this hostname
        # rather than derived from existing origins via heuristics.
        [string]$TargetAdfsHostname = '',
        # When supplied (built by Resolve-AppCorsOrigins) derivation is skipped
        # and this list is used directly as the replacement set.
        [string[]]$ProposedOrigins = @()
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
        # Normalize: ADFS may return a [string[]] array, a comma-delimited string,
        # or a space-delimited string depending on how origins were previously written.
        $existing = @(
            @($headers.CORSTrustedOrigins) |
            ForEach-Object { $_ -split '[\s,]+' } |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $combined = New-Object 'System.Collections.Generic.List[string]'

    if ($ProposedOrigins.Count -gt 0) {
        # Clean replace: the trusted-origin set becomes EXACTLY the freshly-resolved
        # proposed list. Existing origins are NOT merged back, so old/stale origins
        # (and any entry not re-derived by discovery) are removed. Use the
        # interactive editor or -CorsExtraOrigins to add anything not auto-resolved.
        foreach ($origin in $ProposedOrigins) {
            if (-not [string]::IsNullOrWhiteSpace($origin) -and $set.Add($origin)) {
                [void]$combined.Add($origin)
            }
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($TargetAdfsHostname)) {
        # --- Explicit hostname mode ---
        # Derive the ADFS HTTPS origin directly from the target hostname.
        $targetOrigin = "https://" + $TargetAdfsHostname.Trim().ToLowerInvariant()
        if ($set.Add($targetOrigin)) {
            [void]$combined.Add($targetOrigin)
        }

        # Preserve any existing origins that do NOT belong to the old suffix
        # (e.g. other trusted apps) so we don't wipe unrelated entries.
        foreach ($origin in $existing) {
            if ([string]::IsNullOrWhiteSpace($origin)) { continue }
            $normalized = Convert-ToCorsOrigin -UriString $origin
            if ([string]::IsNullOrWhiteSpace($normalized)) { continue }

            # Skip origins that belong to the old suffix - they are replaced by $targetOrigin
            if (-not [string]::IsNullOrWhiteSpace($OldSuffix)) {
                $parsedCheck = $null
                if ([System.Uri]::TryCreate($origin, [System.UriKind]::Absolute, [ref]$parsedCheck)) {
                    $hostCheck = $parsedCheck.Host.ToLowerInvariant()
                    $oldSuffixNorm = $OldSuffix.Trim().ToLowerInvariant()
                    if ($hostCheck -eq $oldSuffixNorm -or $hostCheck.EndsWith('.' + $oldSuffixNorm)) {
                        continue
                    }
                }
            }

            if ($set.Add($normalized)) {
                [void]$combined.Add($normalized)
            }
        }

        foreach ($origin in (Parse-OriginList -Value $ParamExtraOrigins)) {
            if ([string]::IsNullOrWhiteSpace($origin)) { continue }
            $normalized = Convert-ToCorsOrigin -UriString $origin
            if (-not [string]::IsNullOrWhiteSpace($normalized) -and $set.Add($normalized)) {
                [void]$combined.Add($normalized)
            }
        }
    }
    else {
        # --- Heuristic mode (no explicit hostname supplied) ---
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
            if (-not [string]::IsNullOrWhiteSpace($normalized) -and $set.Add($normalized)) {
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

    if (-not $NonInteractive) {
        $applyList = $false
        while (-not $applyList) {
            Write-Host ""
            Write-Host "CORS Trusted Origins to apply:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $combined.Count; $i++) {
                Write-Host ("  [{0}] {1}" -f ($i + 1), $combined[$i])
            }
            Write-Host ""
            Write-Host "  y          apply this list" -ForegroundColor Gray
            Write-Host "  n          skip CORS update" -ForegroundColor Gray
            Write-Host "  add <url>  add an origin to the list" -ForegroundColor Gray
            Write-Host "  rm <n>     remove entry by number" -ForegroundColor Gray
            $response = (Read-Host "Action").Trim()

            if ($response -eq 'y') {
                $applyList = $true
            }
            elseif ($response -eq 'n') {
                Write-Host "Skipped CORS update." -ForegroundColor Yellow
                return
            }
            elseif ($response -match '^add\s+(.+)$') {
                $newUrl = $Matches[1].Trim()
                $normalized = Convert-ToCorsOrigin -UriString $newUrl
                if ([string]::IsNullOrWhiteSpace($normalized)) {
                    Write-Host "  Invalid URL - must be an absolute URI (e.g. https://host.example.com)." -ForegroundColor Red
                }
                elseif ($set.Add($normalized)) {
                    [void]$combined.Add($normalized)
                    Write-Host "  Added: $normalized" -ForegroundColor Green
                }
                else {
                    Write-Host "  Already in list: $normalized" -ForegroundColor Yellow
                }
            }
            elseif ($response -match '^rm\s+(\d+)$') {
                $idx = [int]$Matches[1] - 1
                if ($idx -ge 0 -and $idx -lt $combined.Count) {
                    $removed = $combined[$idx]
                    $combined.RemoveAt($idx)
                    [void]$set.Remove($removed)
                    Write-Host "  Removed: $removed" -ForegroundColor Yellow
                }
                else {
                    Write-Host "  Invalid number. Enter a value between 1 and $($combined.Count)." -ForegroundColor Red
                }
            }
            else {
                Write-Host "  Unrecognized input. Use: y, n, add <url>, rm <n>" -ForegroundColor Red
            }
        }
    }

    if ($combined.Count -eq 0) {
        Write-Host "No origins remaining - CORS update skipped." -ForegroundColor Yellow
        return
    }

    try {
        $originsArray = [string[]]($combined.ToArray())
        Write-Host "Writing $($originsArray.Count) CORS trusted origin(s) to ADFS..." -ForegroundColor Cyan
        $originsArray | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkCyan }
        Set-AdfsResponseHeaders -EnableCORS $true -CORSTrustedOrigins $originsArray -ErrorAction Stop
        Write-Host "CORS updated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "CORS update failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Main ---
if ($Version) {
    Write-Host "Install-ADFS-pfx-Redirects.ps1 version $ScriptVersion"
    return
}

if (-not (Test-IsAdmin)) {
    Stop-Script "This script must be run as Administrator."
}

Import-AdfsSafe

$exportable = -not $NoExportable

Write-Host ""
Write-Host "Importing PFX into Cert:\LocalMachine\My ..." -ForegroundColor Cyan

try {
    $importedCerts = Import-PfxToLocalMachineMy -FilePath $PfxPath -Password $PfxPassword -Exportable:$exportable -NonInteractive:$NonInteractive
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

Write-Host ""
Write-Host "Granting ADFS service account read access to private key..." -ForegroundColor Cyan
Grant-CertPrivateKeyReadAccess -Cert $leafCert -Account "NT SERVICE\adfssrv"

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

# Optional site code: registers <app>-<site> hosts (and, with -SiteOnly, replaces
# the base host). Resolved before the ADFS hostname so it can drive the default
# below.
if (-not $NonInteractive -and -not $PSBoundParameters.ContainsKey('Site')) {
    $resp = (Read-Host "Optional site code (replaces base/other-site app hosts; blank = none)").Trim()
    if (-not [string]::IsNullOrWhiteSpace($resp)) { $Site = $resp }
}

if ($PSBoundParameters.ContainsKey('SiteOnly')) {
    Write-Host ""
    Write-Host "Note: -SiteOnly is deprecated and ignored; -Site now always replaces the base host (and any prior site)." -ForegroundColor Yellow
}

# Record the current federation hostname BEFORE any change. Used as (a) the default
# base ADFS host when -Site is given without -TargetAdfsHostname, and (b) the old
# host for stale HTTP.SYS SSL-binding cleanup after a hostname-only change (the
# thumbprint-based sweep below only catches OLD-CERT bindings, not an old host on
# the same cert).
$previousAdfsHostname = $null
try { $previousAdfsHostname = (Get-AdfsProperties -ErrorAction Stop).HostName } catch {}

# The site code currently deployed (inferred from the live federation host). When a
# different -Site is given, this lets the script STRIP the old site instead of
# stacking it, so a site switch never leaves the previous site's hosts behind.
$CurrentSite = Get-SiteCodeFromAdfsHost -Hostname $previousAdfsHostname

# With -Site, the base ADFS host defaults to the current federation host (which the
# site code then re-codes), so -TargetAdfsHostname is optional. Without -Site it is
# still required: a domain migration must state the new ADFS host explicitly.
if (-not [string]::IsNullOrWhiteSpace($Site) -and
    [string]::IsNullOrWhiteSpace($TargetAdfsHostname) -and
    -not [string]::IsNullOrWhiteSpace($previousAdfsHostname)) {
    $TargetAdfsHostname = $previousAdfsHostname
    Write-Host ""
    Write-Host "No -TargetAdfsHostname given; using the current federation host as the base: $TargetAdfsHostname" -ForegroundColor Cyan
}

# Prompt (or accept) the desired ADFS FQDN before asking the operator to confirm.
# This is collected early so it appears in the confirmation summary.
$TargetAdfsHostname = Get-TargetAdfsHostname `
    -ProvidedValue $TargetAdfsHostname `
    -SanNames $certSanNames `
    -NonInteractive:$NonInteractive

Write-Host ""
Write-Host "Target ADFS hostname : $TargetAdfsHostname" -ForegroundColor Cyan

# When a site code is given, the ADFS/federation host is site-coded like the app
# hosts: auth.adfs.<domain> -> auth-<site>.adfs.<domain>. The site host REPLACES the
# base everywhere (HostName/Identifier/DisplayName + redirects + CORS), and any prior
# site is stripped (via CurrentSite), so only the named site is ever registered.
$effectiveAdfsHostname = $TargetAdfsHostname
if (-not [string]::IsNullOrWhiteSpace($Site)) {
    Write-Host "Site code            : $Site  (only <app>-$Site hosts; base/other-site removed)" -ForegroundColor Cyan
    if (-not [string]::IsNullOrWhiteSpace($CurrentSite) -and $CurrentSite -ne $Site) {
        Write-Host "Replacing current site: $CurrentSite -> $Site" -ForegroundColor Cyan
    }
    $codedAdfs = Add-SiteToHost -Hostname $TargetAdfsHostname -Site $Site -CurrentSite $CurrentSite
    if (-not [string]::IsNullOrWhiteSpace($codedAdfs)) {
        $effectiveAdfsHostname = $codedAdfs
        Write-Host "ADFS host (site-coded): $effectiveAdfsHostname" -ForegroundColor Cyan
    }
}

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
        Update-NativeAppRedirects -AppInfo $app -OldSuffix $OldHostSuffix -NewSuffix $NewHostSuffix -SanNames $certSanNames -Site $Site -CurrentSite $CurrentSite
    }
}

if (-not $SkipFederationServiceProperties) {
    Update-FederationServiceProperties `
        -OldSuffix $OldHostSuffix `
        -NewSuffix $NewHostSuffix `
        -SanNames $certSanNames `
        -TargetAdfsHostname $effectiveAdfsHostname
}
else {
    Write-Host ""
    Write-Host "Federation Service Properties update skipped because -SkipFederationServiceProperties was specified." -ForegroundColor Yellow
}

if (-not $SkipCors) {
    $proposedCorsOrigins = @(Resolve-AppCorsOrigins `
        -SanNames $certSanNames `
        -TargetAdfsHostname $effectiveAdfsHostname `
        -OldSuffix $OldHostSuffix `
        -NewSuffix $NewHostSuffix `
        -ParamExtraOrigins $CorsExtraOrigins `
        -Site $Site `
        -CurrentSite $CurrentSite)

    Update-CorsTrustedOrigins `
        -OldSuffix $OldHostSuffix `
        -NewSuffix $NewHostSuffix `
        -ParamExtraOrigins $CorsExtraOrigins `
        -SanNames $certSanNames `
        -TargetAdfsHostname $effectiveAdfsHostname `
        -ProposedOrigins $proposedCorsOrigins
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
    Write-Host "AD FS SSL certificate update..." -ForegroundColor Cyan
    Write-Host "  New thumbprint: $thumbprint"

    try {
        $currentSslBindings = @(Get-AdfsSslCertificate -ErrorAction Stop)
        if ($currentSslBindings.Count -gt 0) {
            Write-Host "Current SSL bindings:" -ForegroundColor Gray
            foreach ($binding in $currentSslBindings) {
                $marker = if ($binding.CertificateHash -ieq $thumbprint) { " [already set]" } else { "" }
                Write-Host ("  {0}:{1}  ->  {2}{3}" -f $binding.HostName, $binding.PortNumber, $binding.CertificateHash, $marker)
            }
        }
    }
    catch {
        Write-Warning "Could not read current SSL bindings: $($_.Exception.Message)"
        $currentSslBindings = @()
    }

    # Snapshot old thumbprints now so we can target only ADFS-owned bindings later
    $oldSslThumbprints = @(
        $currentSslBindings |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.CertificateHash) -and $_.CertificateHash -ine $thumbprint } |
        ForEach-Object { $_.CertificateHash } |
        Sort-Object -Unique
    )

    if (Confirm-Action "Apply AD FS SSL certificate change? (y/n)") {
        try {
            Set-AdfsSslCertificate -Thumbprint $thumbprint -ErrorAction Stop

            $updatedBindings = @(Get-AdfsSslCertificate -ErrorAction SilentlyContinue)
            $stale = @($updatedBindings | Where-Object { $_.CertificateHash -ine $thumbprint })

            if ($stale.Count -eq 0) {
                Write-Host "AD FS SSL certificate updated successfully." -ForegroundColor Green
            }
            else {
                Write-Host "SSL certificate set, but some bindings still show the old thumbprint:" -ForegroundColor Yellow
                foreach ($binding in $updatedBindings) {
                    $isCurrent = $binding.CertificateHash -ieq $thumbprint
                    $status = if ($isCurrent) { "OK   " } else { "STALE" }
                    $color  = if ($isCurrent) { "Green" } else { "Yellow" }
                    Write-Host ("  [{0}] {1}:{2}  ->  {3}" -f $status, $binding.HostName, $binding.PortNumber, $binding.CertificateHash) -ForegroundColor $color
                }

                Write-Host ""
                Write-Host "Updating stale HTTP.SYS bindings directly via netsh..." -ForegroundColor Cyan

                try {
                    $httpSysBindings = @(Get-HttpSysSslBindings)
                    $staleHttpSys = @($httpSysBindings | Where-Object {
                        $_.CertHash -and $oldSslThumbprints -contains $_.CertHash
                    })

                    if ($staleHttpSys.Count -eq 0) {
                        Write-Host "No stale HTTP.SYS bindings found for old certificate." -ForegroundColor Yellow
                    }
                    else {
                        foreach ($b in $staleHttpSys) {
                            Update-HttpSysSslBinding -Binding $b -NewThumbprint $thumbprint
                        }
                    }
                }
                catch {
                    Write-Host "netsh binding update failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        catch {
            Write-Host "AD FS SSL update failed: $($_.Exception.Message)" -ForegroundColor Red
        }

        # Final sweep: delete any remaining HTTP.SYS bindings still referencing the old cert
        if ($oldSslThumbprints.Count -gt 0) {
            try {
                $remainingOld = @(Get-HttpSysSslBindings | Where-Object {
                    $_.CertHash -and $oldSslThumbprints -contains $_.CertHash
                })

                if ($remainingOld.Count -gt 0) {
                    Write-Host ""
                    Write-Host "Removing remaining stale HTTP.SYS bindings for old certificate..." -ForegroundColor Cyan
                    foreach ($b in $remainingOld) {
                        $typeArg = "$($b.Type)=$($b.Binding)"
                        & netsh http delete sslcert $typeArg 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host ("  Removed [{0}] {1}" -f $b.Type, $b.Binding) -ForegroundColor Green
                        }
                        else {
                            Write-Host ("  Failed to remove [{0}] {1}" -f $b.Type, $b.Binding) -ForegroundColor Yellow
                        }
                    }
                }
            }
            catch {
                Write-Warning "Failed to clean up remaining stale bindings: $($_.Exception.Message)"
            }
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

# Universal stale federation-host SSL cleanup (runs on EVERY SSL-updating run, not
# just -Site). The stale-by-thumbprint sweep above only catches OLD-CERT bindings;
# this removes leftover federation-host bindings that sit on the CURRENT cert -
# the immediately-previous host after a -Site/host change, AND any older sibling
# hosts (auth.adfs, auth-office.adfs, auth-backup.adfs, ...) accumulated over prior
# runs. Scoped to the ADFS host's own parent domain, so app hosts and unrelated
# :443 sites are never touched.
if (-not $SkipAdfsSsl) {
    # The host ADFS now uses: the effective host unless federation props were skipped
    # (then the live host is unchanged = previous).
    $keepHost = if ($SkipFederationServiceProperties) { $previousAdfsHostname } else { $effectiveAdfsHostname }
    if (-not [string]::IsNullOrWhiteSpace($keepHost)) {
        try {
            $staleFed = @(Select-StaleFederationBindings -Bindings (Get-HttpSysSslBindings) -KeepHost $keepHost)
            if ($staleFed.Count -gt 0) {
                Write-Host ""
                Write-Host ("Removing stale federation-host SSL bindings (keeping " + $keepHost + ")...") -ForegroundColor Cyan
                foreach ($b in $staleFed) {
                    & netsh http delete sslcert hostnameport=$($b.Binding) 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) { Write-Host ("  Removed " + $b.Binding) -ForegroundColor Green }
                    else { Write-Host ("  Failed to remove " + $b.Binding) -ForegroundColor Yellow }
                }
            }
        }
        catch {
            Write-Warning "Stale federation-host binding cleanup failed: $($_.Exception.Message)"
        }
    }
}

# --- Optional ADFS configuration tweaks (token certs, endpoints) ---

if ($TokenCertificateDuration -gt 0) {
    Write-Host ""
    Write-Host "Setting token-signing/decryption certificate duration to $TokenCertificateDuration days..." -ForegroundColor Cyan
    try {
        $beforeDuration = (Get-AdfsProperties -ErrorAction Stop).CertificateDuration
        Set-AdfsProperties -CertificateDuration $TokenCertificateDuration -ErrorAction Stop
        Write-Host "CertificateDuration updated ($beforeDuration -> $TokenCertificateDuration days). Applies to the NEXT generated token certs." -ForegroundColor Green
    }
    catch { Write-Host "Failed to set CertificateDuration: $($_.Exception.Message)" -ForegroundColor Red }
}

if ($RolloverTokenCerts) {
    Write-Host ""
    Write-Host "WARNING: -RolloverTokenCerts will regenerate the token-signing/decryption certificates NOW" -ForegroundColor Yellow
    Write-Host "         and make them primary immediately. Every relying party / application trust must" -ForegroundColor Yellow
    Write-Host "         re-consume ADFS metadata (or the new token-signing cert) afterward, or logins to" -ForegroundColor Yellow
    Write-Host "         those apps will fail until they do." -ForegroundColor Yellow
    $doRoll = $NonInteractive -or (Confirm-Action "Proceed with urgent token-certificate rollover? (y/n)")
    if ($doRoll) {
        try {
            Update-AdfsCertificate -Urgent -ErrorAction Stop
            Write-Host "Token certificates rolled over." -ForegroundColor Green
        }
        catch { Write-Host "Token certificate rollover failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "Skipped token-certificate rollover." -ForegroundColor Yellow }
}

if ($EnableUpdatePassword) {
    Write-Host ""
    Write-Host "Enabling the update-password endpoint (/adfs/portal/updatepassword/)..." -ForegroundColor Cyan
    try {
        Enable-AdfsEndpoint -TargetAddressPath "/adfs/portal/updatepassword/" -ErrorAction Stop | Out-Null
        Write-Host "Update-password endpoint enabled." -ForegroundColor Green
    }
    catch { Write-Host "Failed to enable update-password endpoint: $($_.Exception.Message)" -ForegroundColor Red }
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
Write-Host ("Selected thumbprint  : {0}" -f $thumbprint) -ForegroundColor DarkGray
Write-Host ("Old suffix           : {0}" -f $OldHostSuffix) -ForegroundColor DarkGray
Write-Host ("New suffix           : {0}" -f $NewHostSuffix) -ForegroundColor DarkGray
Write-Host ("Target ADFS hostname : {0}" -f $TargetAdfsHostname) -ForegroundColor DarkGray
