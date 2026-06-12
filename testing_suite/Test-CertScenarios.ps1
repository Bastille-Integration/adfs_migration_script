# Version: 1.0
# Offline regression test for the SAN-based hostname rewriting in
# Install-ADFS-pfx-Redirects.ps1, driven by two fixture PFX files that mirror the
# two certificate conventions Bastille deployments use in the field:
#
#   1. FLAT COMPOUND (certs/test-flat-oraphys.pfx) - every host is listed
#      explicitly as wids-<app>-<site>.<domain>, with NO wildcard, and a
#      FLATTENED federation host (wids-auth-adfs-<site>.<domain>). Mirrors the
#      Phosphorus/Building2 style. Fake domain: oraphys-lab.example, site lab16.
#
#   2. STANDARD WILDCARD (certs/test-wildcard-acme.pfx) - <domain>,
#      *.<domain>, and a dotted federation host auth.adfs.<domain>. Mirrors the
#      bn.internal style. Random fake domain: acme-secure.test.
#
# It loads the shipped functions from the migration script WITHOUT running the
# migration, then exercises the resolvers against a simulated "fresh from-scratch"
# bn.internal deployment. It makes NO changes and does NOT require a live ADFS node
# (the ADFS module is optional). On a box without Get-PfxData the cert-reading
# checks are skipped and the rewriting logic is tested against the known SAN sets.
#
# Usage (from the testing_suite directory):
#   .\Test-CertScenarios.ps1
#   .\Test-CertScenarios.ps1 -ScriptPath ..\Install-ADFS-pfx-Redirects.ps1

[CmdletBinding()]
param(
    [string]$ScriptPath = '',
    [string]$CertDir = '',
    [string]$PfxPassword = 'Bastille-Test-Pfx!'
)

$ErrorActionPreference = 'Stop'

# --- Resolve paths. This test lives in testing_suite/; the migration script is
# normally one directory up, and the fixtures live in ./certs next to this file. ---
$here = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($here) -and $MyInvocation.MyCommand.Path) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrWhiteSpace($here)) { $here = (Get-Location).Path }

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $candidates = @(
        (Join-Path (Split-Path -Parent $here) 'Install-ADFS-pfx-Redirects.ps1'),
        (Join-Path $here 'Install-ADFS-pfx-Redirects.ps1'),
        (Join-Path (Get-Location).Path 'Install-ADFS-pfx-Redirects.ps1')
    )
    $ScriptPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($ScriptPath)) { $ScriptPath = $candidates[0] }
}
if ([string]::IsNullOrWhiteSpace($CertDir)) { $CertDir = Join-Path $here 'certs' }

# --- Load the shipped functions (everything before the '# --- Main ---' marker) ---
if (-not (Test-Path $ScriptPath)) { throw "Migration script not found: $ScriptPath" }
$raw = Get-Content $ScriptPath -Raw
$end = $raw.IndexOf('# --- Main ---')
$fi  = $raw.IndexOf('function ')
if ($fi -lt 0 -or $end -lt 0 -or $end -le $fi) { throw "Could not locate the function block in $ScriptPath" }
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('_certfuncs_' + [guid]::NewGuid().ToString('N') + '.ps1')
Set-Content -Path $tmp -Value $raw.Substring($fi, $end - $fi) -Encoding ASCII
. $tmp
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

# --- Test harness ---
$script:Pass = 0
$script:Fail = 0
$script:Skip = 0
function Assert {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        Write-Host ("  [PASS] " + $Name) -ForegroundColor Green
        $script:Pass++
    }
    else {
        Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red
        if ($Detail) { Write-Host ("         " + $Detail) -ForegroundColor DarkYellow }
        $script:Fail++
    }
}
function Skip {
    param([string]$Name, [string]$Reason = '')
    Write-Host ("  [SKIP] " + $Name + $(if ($Reason) { "  ($Reason)" } else { "" })) -ForegroundColor DarkGray
    $script:Skip++
}

# Wrap a SAN string list as a cert-like object so the shipped suffix functions
# (which read .DnsNameList.Unicode) can be driven from a known SAN set even when
# no real cert is loaded.
function New-CertLike {
    param([string[]]$Sans)
    return [pscustomobject]@{ DnsNameList = @($Sans | ForEach-Object { [pscustomobject]@{ Unicode = $_ } }) }
}

# Read the SAN list from a fixture PFX so the certs themselves are validated. Prefer
# the Windows Get-PfxData path (mirrors how the migration script consumes a PFX); fall
# back to openssl so the fixtures are still tested on macOS/Linux/CI. The reader is
# 'none' only when neither is available (then cert reads are skipped).
$canGetPfx  = [bool](Get-Command Get-PfxData -ErrorAction SilentlyContinue)
$canOpenssl = [bool](Get-Command openssl -ErrorAction SilentlyContinue)
$pfxReader  = if ($canGetPfx) { 'Get-PfxData' } elseif ($canOpenssl) { 'openssl' } else { 'none' }

function Get-PfxSansViaOpenssl {
    param([string]$PfxPath, [string]$Password)
    # Decrypt the leaf cert (legacy 3DES PKCS#12) and pull its SAN DNS names.
    $pem = & openssl pkcs12 -in $PfxPath -clcerts -nokeys -legacy -passin "pass:$Password" 2>$null | Out-String
    if ([string]::IsNullOrWhiteSpace($pem)) { return @() }
    $san = $pem | & openssl x509 -noout -ext subjectAltName 2>$null | Out-String
    $names = @()
    foreach ($m in [regex]::Matches($san, 'DNS:([^,\s]+)')) { $names += $m.Groups[1].Value }
    return @($names | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object -Unique)
}

function Get-PfxSans {
    param([string]$PfxPath, [string]$Password)
    if (-not (Test-Path $PfxPath)) { return $null }
    try {
        if ($pfxReader -eq 'Get-PfxData') {
            $sec  = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $data = Get-PfxData -FilePath $PfxPath -Password $sec -ErrorAction Stop
            $cert = $data.EndEntityCertificates[0]
            $sans = @(Get-CertificateDnsNames -Cert $cert)
            if ($sans.Count -eq 0) {
                $c2   = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @($PfxPath, $Password)
                $sans = @(Get-CertificateDnsNames -Cert $c2)
            }
            return @($sans)
        }
        elseif ($pfxReader -eq 'openssl') {
            return @(Get-PfxSansViaOpenssl -PfxPath $PfxPath -Password $Password)
        }
        return $null
    }
    catch {
        Write-Warning ("Failed reading PFX '{0}': {1}" -f $PfxPath, $_.Exception.Message)
        return $null
    }
}

# A simulated fresh Install-ADFS-pfx-From_Scratch.ps1 deployment (bn.internal): the
# starting point both scenarios migrate AWAY from.
$OldSuffix    = 'bn.internal'
$OldAppLabels = @('admin', 'dvr', 'device', 'explorer', 'lighthouse', 'wtiapi', 'wti', 'api')
$OldFedHost   = 'auth.adfs.bn.internal'

# --- Scenario definitions ---
$scenarios = @(
    [pscustomobject]@{
        Name                 = 'FLAT COMPOUND (no wildcard) - oraphys-lab.example'
        PfxFile              = 'test-flat-oraphys.pfx'
        ExpectedSans         = @(
            'wids-lab16.oraphys-lab.example','wids-admin-lab16.oraphys-lab.example',
            'wids-dvr-lab16.oraphys-lab.example','wids-device-lab16.oraphys-lab.example',
            'wids-explorer-lab16.oraphys-lab.example','wids-lighthouse-lab16.oraphys-lab.example',
            'wids-wtiapi-lab16.oraphys-lab.example','wids-wti-lab16.oraphys-lab.example',
            'wids-api-lab16.oraphys-lab.example','wids-auth-adfs-lab16.oraphys-lab.example',
            'wids-elastic-lab16.oraphys-lab.example','wids-kafka-lab16.oraphys-lab.example',
            'wids-redis-lab16.oraphys-lab.example'
        )
        ExpectWildcardSuffix = $null                       # no wildcard in this cert
        ExpectSansSuffix     = 'oraphys-lab.example'        # common 2-label suffix
        AppMap               = @{
            'admin'      = 'wids-admin-lab16.oraphys-lab.example'
            'dvr'        = 'wids-dvr-lab16.oraphys-lab.example'
            'device'     = 'wids-device-lab16.oraphys-lab.example'
            'explorer'   = 'wids-explorer-lab16.oraphys-lab.example'
            'lighthouse' = 'wids-lighthouse-lab16.oraphys-lab.example'
            'wtiapi'     = 'wids-wtiapi-lab16.oraphys-lab.example'
            'wti'        = 'wids-wti-lab16.oraphys-lab.example'
            'api'        = 'wids-api-lab16.oraphys-lab.example'
        }
        # Flat certs flatten auth.adfs into one label, so a dotted old federation
        # host does NOT auto-resolve; it must be supplied via -TargetAdfsHostname.
        ExpectFedResolves    = $false
        ExpectFedHost        = ''
        ExplicitFedHost      = 'wids-auth-adfs-lab16.oraphys-lab.example'
    },
    [pscustomobject]@{
        Name                 = 'STANDARD WILDCARD - acme-secure.test'
        PfxFile              = 'test-wildcard-acme.pfx'
        ExpectedSans         = @('acme-secure.test','*.acme-secure.test','auth.adfs.acme-secure.test')
        ExpectWildcardSuffix = 'acme-secure.test'
        ExpectSansSuffix     = $null                        # bare 2-label SAN blocks the SANs-suffix path
        AppMap               = @{
            'admin'      = 'admin.acme-secure.test'
            'dvr'        = 'dvr.acme-secure.test'
            'device'     = 'device.acme-secure.test'
            'explorer'   = 'explorer.acme-secure.test'
            'lighthouse' = 'lighthouse.acme-secure.test'
            'wtiapi'     = 'wtiapi.acme-secure.test'
            'wti'        = 'wti.acme-secure.test'
            'api'        = 'api.acme-secure.test'
        }
        # The dotted federation host is preserved structurally across the suffix swap.
        ExpectFedResolves    = $true
        ExpectFedHost        = 'auth.adfs.acme-secure.test'
        ExplicitFedHost      = 'auth.adfs.acme-secure.test'
    }
)

Write-Host ""
Write-Host "================ Cert-scenario regression test ================" -ForegroundColor Cyan
Write-Host ("  Migration script : " + $ScriptPath)
Write-Host ("  Fixture dir      : " + $CertDir)
Write-Host ("  PFX reader       : " + $(if ($pfxReader -eq 'none') { 'none (cert-read checks SKIPPED)' } else { "$pfxReader (cert-read checks ON)" }))

foreach ($s in $scenarios) {
    Write-Host ""
    Write-Host ("===== " + $s.Name + " =====") -ForegroundColor Magenta

    # --- Load (or fall back to known) SAN set ---
    $pfxPath  = Join-Path $CertDir $s.PfxFile
    $certSans = Get-PfxSans -PfxPath $pfxPath -Password $PfxPassword

    if ($pfxReader -eq 'none') {
        Skip ("read SANs from " + $s.PfxFile) 'no PFX reader (Get-PfxData/openssl) available'
    }
    elseif ($null -eq $certSans) {
        Assert ("read SANs from " + $s.PfxFile) $false "Could not load $pfxPath (missing file or wrong password)"
    }
    else {
        $got = @($certSans | Sort-Object -Unique)
        $exp = @($s.ExpectedSans | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
        $match = (@(Compare-Object $got $exp).Count -eq 0)
        Assert ("PFX SANs match the expected set (" + $got.Count + " names)") $match ("got: " + ($got -join ', '))
    }

    # SAN set actually used for the rewriting assertions (cert when available, else known).
    $sans = if ($certSans) { @($certSans) } else { @($s.ExpectedSans) }
    $certLike = New-CertLike -Sans $sans

    # --- Suffix detection ---
    $wild = Get-NewHostSuffixFromCertificateWildcardSan -Cert $certLike
    if ($null -eq $s.ExpectWildcardSuffix) {
        Assert "wildcard suffix is absent" ([string]::IsNullOrWhiteSpace($wild)) ("got: '$wild'")
    }
    else {
        Assert ("wildcard suffix = " + $s.ExpectWildcardSuffix) ($wild -eq $s.ExpectWildcardSuffix) ("got: '$wild'")
    }

    $sansSuffix = Get-NewHostSuffixFromCertificateSans -Cert $certLike
    if ($null -eq $s.ExpectSansSuffix) {
        Assert "SANs-common suffix is absent" ([string]::IsNullOrWhiteSpace($sansSuffix)) ("got: '$sansSuffix'")
    }
    else {
        Assert ("SANs-common suffix = " + $s.ExpectSansSuffix) ($sansSuffix -eq $s.ExpectSansSuffix) ("got: '$sansSuffix'")
    }

    # --- Per-app hostname rewriting (old <app>.bn.internal -> cert convention) ---
    foreach ($label in $OldAppLabels) {
        $old = "$label.$OldSuffix"
        $new = Resolve-HostnameFromSans -OldHostname $old -SanNames $sans -OldSuffix $OldSuffix
        $want = $s.AppMap[$label]
        Assert ("$old -> $want") ($new -eq $want) ("got: '$new'")
    }

    # --- wti / wtiapi must NOT cross-match ---
    $wti    = Resolve-HostnameFromSans -OldHostname "wti.$OldSuffix"    -SanNames $sans -OldSuffix $OldSuffix
    $wtiapi = Resolve-HostnameFromSans -OldHostname "wtiapi.$OldSuffix" -SanNames $sans -OldSuffix $OldSuffix
    Assert "wti and wtiapi resolve to different hosts" ($wti -ne $wtiapi) ("wti='$wti' wtiapi='$wtiapi'")

    # --- Federation (ADFS) host behavior ---
    $fed = Resolve-HostnameFromSans -OldHostname $OldFedHost -SanNames $sans -OldSuffix $OldSuffix
    if ($s.ExpectFedResolves) {
        Assert ("$OldFedHost -> $($s.ExpectFedHost) (structure preserved)") ($fed -eq $s.ExpectFedHost) ("got: '$fed'")
    }
    else {
        Assert "flat federation host does NOT auto-resolve (set via -TargetAdfsHostname)" ([string]::IsNullOrWhiteSpace($fed)) ("got: '$fed'")
    }
    # The explicit federation host is covered by the cert (SAN or wildcard).
    $fedMatch = Test-CertificateNameMatch -Cert $certLike -ExpectedName $s.ExplicitFedHost
    Assert ("cert covers federation host " + $s.ExplicitFedHost) ([bool]$fedMatch.IsMatch) ("matchedBy: " + ($fedMatch.MatchedBy -join ', '))

    # --- Build-ReplacedRedirectList: -Site now REPLACES the base host by default ---
    # Expected site host is built with the shipped Add-SiteToHost (codes the FIRST
    # DNS label, e.g. admin -> admin-site9 / wids-admin-lab16 -> wids-admin-lab16-site9).
    $adminBase = ("https://" + $s.AppMap['admin'] + "/adfs/oauth/callback")
    $adminSite = ("https://" + (Add-SiteToHost -Hostname $s.AppMap['admin'] -Site 'site9') + "/adfs/oauth/callback")

    $existing = @(
        "https://admin.$OldSuffix/adfs/oauth/callback",
        "https://wti.$OldSuffix/cb",
        "https://wtiapi.$OldSuffix/api"
    )
    # The shipped function returns a comma-wrapped array (keeps single-item results
    # as arrays for Set-AdfsNativeClientApplication); pipe through to flatten it.
    $rebuilt = Build-ReplacedRedirectList -ExistingRedirects $existing -OldSuffix $OldSuffix -SanNames $sans -Site 'site9' | ForEach-Object { $_ }
    Assert "[-Site] contains the site-coded admin URI"      ($rebuilt -contains $adminSite) ("have: " + ($rebuilt -join ' | '))
    Assert "[-Site] base admin URI is REPLACED (not kept)"  (-not ($rebuilt -contains $adminBase)) ("have: " + ($rebuilt -join ' | '))
    $leakedOld = @($rebuilt | Where-Object { $_ -match [regex]::Escape($OldSuffix) })
    Assert "[-Site] no old-suffix hosts remain"             ($leakedOld.Count -eq 0) ("leaked: " + ($leakedOld -join ' | '))
    $doubleCoded = @($rebuilt | Where-Object { $_ -match 'site9-site9' })
    Assert "[-Site] no host is double site-coded"           ($doubleCoded.Count -eq 0) ("double: " + ($doubleCoded -join ' | '))
}

Write-Host ""
Write-Host "===== Old-suffix detection (Get-MostCommonHostSuffix) =====" -ForegroundColor Magenta
# Regression: a deeper federation-host suffix (adfs.<domain>, shared by ONE host)
# must not beat the base app-host domain shared by all hosts. This is the bug that
# made -Site home skip every redirect (picked 'adfs.bn-wids.internal').
$mixedHosts = @(
    'admin-home.bn-wids.internal','device-home.bn-wids.internal','dvr-home.bn-wids.internal',
    'explorer-home.bn-wids.internal','wti-home.bn-wids.internal','auth-home.adfs.bn-wids.internal'
)
$suffix = Get-MostCommonHostSuffix -Hosts $mixedHosts
Assert "mixed app + federation hosts -> base domain (not adfs.<domain>)" ($suffix -eq 'bn-wids.internal') ("got: '$suffix'")
# Base + home + ADFS (the 11-origin pre-cleanup set) still resolves to the base.
$suffix2 = Get-MostCommonHostSuffix -Hosts @('admin.bn-wids.internal','admin-home.bn-wids.internal','auth-home.adfs.bn-wids.internal')
Assert "base + home + adfs -> base domain" ($suffix2 -eq 'bn-wids.internal') ("got: '$suffix2'")
# A flat single-domain set resolves to that domain.
$suffix3 = Get-MostCommonHostSuffix -Hosts @('wids-admin-lab16.oraphys-lab.example','wids-dvr-lab16.oraphys-lab.example')
Assert "flat hosts -> shared domain" ($suffix3 -eq 'oraphys-lab.example') ("got: '$suffix3'")

Write-Host ""
Write-Host "===== Site re-coding (replace base / idempotent / switch) =====" -ForegroundColor Magenta
# Wildcard domain so any host under it resolves (a flat cert has no site-coded SANs).
$wsan = @('bn-wids.internal', '*.bn-wids.internal')
$wsuf = 'bn-wids.internal'

# Current-site detection from the federation host.
Assert "site from auth-home.adfs.<d> = home"  ((Get-SiteCodeFromAdfsHost -Hostname 'auth-home.adfs.bn-wids.internal') -eq 'home') ''
Assert "site from auth.adfs.<d> = (none)"      ([string]::IsNullOrEmpty((Get-SiteCodeFromAdfsHost -Hostname 'auth.adfs.bn-wids.internal'))) ''
Assert "site from wids-auth-adfs-abl16.<d> = abl16" ((Get-SiteCodeFromAdfsHost -Hostname 'wids-auth-adfs-abl16.oraphys-lab.example') -eq 'abl16') ''

# Base -> site: base host replaced, only the site host remains.
$r1 = Build-ReplacedRedirectList -ExistingRedirects @('https://admin.bn-wids.internal/cb') -OldSuffix $wsuf -SanNames $wsan -Site 'home' | ForEach-Object { $_ }
Assert "base -> home: site host present"       ($r1 -contains 'https://admin-home.bn-wids.internal/cb') ("have: " + ($r1 -join ' | '))
Assert "base -> home: base removed"            (-not ($r1 -contains 'https://admin.bn-wids.internal/cb')) ("have: " + ($r1 -join ' | '))

# Idempotent: already on 'home', deploy 'home' again -> unchanged, single entry.
$r2 = Build-ReplacedRedirectList -ExistingRedirects @('https://admin-home.bn-wids.internal/cb') -OldSuffix $wsuf -SanNames $wsan -Site 'home' -CurrentSite 'home' | ForEach-Object { $_ }
Assert "home -> home idempotent (single host)" (@($r2).Count -eq 1 -and $r2 -contains 'https://admin-home.bn-wids.internal/cb') ("have: " + ($r2 -join ' | '))

# Switch: on 'home', deploy 'office' (CurrentSite home) -> only office, no home left.
$r3 = Build-ReplacedRedirectList -ExistingRedirects @('https://admin-home.bn-wids.internal/cb') -OldSuffix $wsuf -SanNames $wsan -Site 'office' -CurrentSite 'home' | ForEach-Object { $_ }
Assert "home -> office: office host present"   ($r3 -contains 'https://admin-office.bn-wids.internal/cb') ("have: " + ($r3 -join ' | '))
Assert "home -> office: home stripped (no remnant/stacking)" (@($r3 | Where-Object { $_ -match 'home' }).Count -eq 0) ("have: " + ($r3 -join ' | '))

Write-Host ""
Write-Host "===== Stale federation-host SSL binding cleanup =====" -ForegroundColor Magenta
# Runs on every SSL-updating run: removes sibling/leftover federation hosts on the
# ADFS ports, scoped to the ADFS host's parent domain; leaves the current host,
# localhost, app hosts (different parent), and unrelated :443 sites alone.
$bindings = @(
    [pscustomobject]@{ Type='hostnameport'; Binding='auth-home.adfs.bn-wids.internal:443' },    # keep (current)
    [pscustomobject]@{ Type='hostnameport'; Binding='auth-home.adfs.bn-wids.internal:49443' },   # keep (current)
    [pscustomobject]@{ Type='hostnameport'; Binding='auth.adfs.bn-wids.internal:443' },          # STALE sibling
    [pscustomobject]@{ Type='hostnameport'; Binding='auth-office.adfs.bn-wids.internal:49443' }, # STALE sibling
    [pscustomobject]@{ Type='hostnameport'; Binding='auth-backup.adfs.bn-wids.internal:443' },   # STALE sibling
    [pscustomobject]@{ Type='hostnameport'; Binding='localhost:443' },                           # keep
    [pscustomobject]@{ Type='hostnameport'; Binding='admin-home.bn-wids.internal:443' },         # keep (app host, diff parent)
    [pscustomobject]@{ Type='hostnameport'; Binding='auth.adfs.contoso.com:443' },               # keep (unrelated domain)
    [pscustomobject]@{ Type='ipport';       Binding='0.0.0.0:443' }                              # keep (ipport, not hostnameport)
)
$stale = @(Select-StaleFederationBindings -Bindings $bindings -KeepHost 'auth-home.adfs.bn-wids.internal')
$staleSet = @($stale | ForEach-Object { $_.Binding })
Assert "stale sweep removes the 3 sibling federation hosts" ($stale.Count -eq 3) ("got: " + ($staleSet -join ', '))
Assert "stale sweep keeps current host (443/49443)"  (-not ($staleSet -match 'auth-home\.adfs')) ("got: " + ($staleSet -join ', '))
Assert "stale sweep keeps localhost"                 (-not ($staleSet -contains 'localhost:443')) ''
Assert "stale sweep keeps app host (different parent)" (-not ($staleSet -contains 'admin-home.bn-wids.internal:443')) ''
Assert "stale sweep keeps unrelated domain"          (-not ($staleSet -match 'contoso')) ''
Assert "stale sweep ignores ipport bindings"         (-not ($staleSet -contains '0.0.0.0:443')) ''
# No KeepHost -> nothing removed (safety).
Assert "stale sweep is a no-op without a keep host"  (@(Select-StaleFederationBindings -Bindings $bindings -KeepHost '').Count -eq 0) ''

Write-Host ""
$color = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
Write-Host ("================ RESULT: {0} passed, {1} failed, {2} skipped ================" -f $script:Pass, $script:Fail, $script:Skip) -ForegroundColor $color
if ($script:Fail -gt 0) { exit 1 }
