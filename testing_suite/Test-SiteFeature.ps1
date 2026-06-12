# Version: 1.1
# Live, self-restoring test for the -Site feature of Install-ADFS-pfx-Redirects.ps1.
#
# Loads the shipped functions from the migration script (without running the
# migration), applies a -Site code to the LIVE ADFS native-app redirect URIs and
# CORS origins, prints before/after, runs PASS/FAIL assertions, then restores the
# exact pre-existing state in a finally block (runs even if an assertion throws).
#
# -Site semantics (v2.6+): the site host REPLACES the base, and any currently-
# deployed site (detected from the federation host) is stripped - so this test
# asserts the site-coded host is PRESENT, the prior host is REMOVED, the redirect
# count is unchanged (1:1 re-code, not additive), and nothing is double/stacked.
#
# It does NOT touch certificates, Federation Service properties, or restart ADFS.
#
# Requires: Run as Administrator on an ADFS node with the ADFS PowerShell module.
# Lives in testing_suite/; auto-locates the migration script one directory up.
# Usage (from the testing_suite directory):
#   .\Test-SiteFeature.ps1
#   .\Test-SiteFeature.ps1 -Site sitetest -ScriptPath ..\Install-ADFS-pfx-Redirects.ps1

[CmdletBinding()]
param(
    [string]$ScriptPath = '',
    [string]$Site = 'sitetest'
)

$ErrorActionPreference = 'Stop'
Import-Module ADFS -ErrorAction Stop

# Resolve the migration script path. This test lives in testing_suite/, so the
# migration script is normally one directory up; also accept same-dir and CWD.
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $base = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($base) -and $MyInvocation.MyCommand.Path) { $base = Split-Path -Parent $MyInvocation.MyCommand.Path }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = (Get-Location).Path }
    $candidates = @(
        (Join-Path (Split-Path -Parent $base) 'Install-ADFS-pfx-Redirects.ps1'),  # parent dir (repo layout)
        (Join-Path $base 'Install-ADFS-pfx-Redirects.ps1'),                        # same dir
        (Join-Path (Get-Location).Path 'Install-ADFS-pfx-Redirects.ps1')           # current dir
    )
    $ScriptPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($ScriptPath)) { $ScriptPath = $candidates[0] }
}

# --- Load the shipped functions (everything before the '# --- Main ---' marker) ---
if (-not (Test-Path $ScriptPath)) { throw "Script not found: $ScriptPath" }
$raw = Get-Content $ScriptPath -Raw
$end = $raw.IndexOf('# --- Main ---')
$fi  = $raw.IndexOf('function ')
if ($fi -lt 0 -or $end -lt 0 -or $end -le $fi) { throw "Could not locate the function block in $ScriptPath" }
$tmp = Join-Path $env:TEMP ('_sitefuncs_' + [guid]::NewGuid().ToString('N') + '.ps1')
Set-Content -Path $tmp -Value $raw.Substring($fi, $end - $fi) -Encoding ASCII
. $tmp
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

# --- Test helpers ---
$script:Pass = 0
$script:Fail = 0
function Assert {
    param([string]$Name, [bool]$Condition)
    if ($Condition) { Write-Host ("  [PASS] " + $Name) -ForegroundColor Green; $script:Pass++ }
    else            { Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red;   $script:Fail++ }
}

# Independent expectation builders (NOT the shipped Add-SiteTo* - so the test
# verifies behavior rather than just re-deriving from the implementation). Mirrors
# the v2.6+ replace semantics: strip a current-site suffix, then apply the new site;
# a host already on the target site is unchanged.
function Expect-SiteHost {
    param([string]$Hostname, [string]$Site, [string]$CurrentSite = '')
    $labels = $Hostname -split '\.'
    $first = $labels[0]
    if ($first -match ('-' + [regex]::Escape($Site) + '$')) { return $Hostname }   # already target site
    if (-not [string]::IsNullOrWhiteSpace($CurrentSite) -and $CurrentSite -ne $Site -and
        $first -match ('-' + [regex]::Escape($CurrentSite) + '$')) {
        $first = $first.Substring(0, $first.Length - ($CurrentSite.Length + 1))
    }
    $labels[0] = $first + '-' + $Site
    return ($labels -join '.')
}
function Expect-SiteUri {
    param([string]$Uri, [string]$Site, [string]$CurrentSite = '')
    $u = [System.Uri]$Uri
    $b = New-Object System.UriBuilder($u)
    $b.Host = (Expect-SiteHost -Hostname $u.Host -Site $Site -CurrentSite $CurrentSite)
    return $b.Uri.AbsoluteUri
}
function Expect-SiteOrigin {
    param([string]$Origin, [string]$Site, [string]$CurrentSite = '')
    $u = [System.Uri]$Origin
    return ($u.Scheme + '://' + (Expect-SiteHost -Hostname $u.Host -Site $Site -CurrentSite $CurrentSite))
}

function Get-NativeAppMap {
    $list = @()
    foreach ($g in (Get-AdfsApplicationGroup | Sort-Object Name)) {
        foreach ($a in @(Get-AdfsNativeClientApplication -ApplicationGroup $g -ErrorAction SilentlyContinue)) {
            $list += [PSCustomObject]@{ Group = $g.Name; Name = $a.Name; Id = $a.Identifier; Uris = @($a.RedirectUri) }
        }
    }
    return $list
}
function Get-NativeApp { param([string]$Id) @(Get-AdfsNativeClientApplication) | Where-Object { $_.Identifier -eq $Id } | Select-Object -First 1 }

# Print the full relevant ADFS configuration under a labelled banner so each
# phase (previous / modified / restored) can be validated end to end.
function Show-State {
    param([string]$Label)
    Write-Host ""
    Write-Host ("################################################################" ) -ForegroundColor Cyan
    Write-Host ("##  " + $Label) -ForegroundColor Cyan
    Write-Host ("################################################################" ) -ForegroundColor Cyan

    Write-Host "-- Federation Service Properties --" -ForegroundColor White
    $p = Get-AdfsProperties
    Write-Host ("   HostName            : " + $p.HostName)
    Write-Host ("   Identifier          : " + $p.Identifier)
    Write-Host ("   DisplayName         : " + $p.DisplayName)

    Write-Host "-- Application Groups --" -ForegroundColor White
    foreach ($g in (Get-AdfsApplicationGroup | Sort-Object Name)) {
        Write-Host ("   [" + $g.Name + "]") -ForegroundColor Gray
        foreach ($a in @(Get-AdfsNativeClientApplication -ApplicationGroupIdentifier $g.ApplicationGroupIdentifier -ErrorAction SilentlyContinue)) {
            Write-Host ("     Native : " + $a.Name + "   (ClientId " + $a.Identifier + ")")
            @($a.RedirectUri) | Sort-Object | ForEach-Object { Write-Host ("        redirect : " + $_) }
        }
    }

    Write-Host "-- CORS (Response Headers) --" -ForegroundColor White
    $h = Get-AdfsResponseHeaders
    Write-Host ("   CORSEnabled : " + $h.CORSEnabled + "   (origins: " + @($h.CORSTrustedOrigins).Count + ")")
    @($h.CORSTrustedOrigins) | Sort-Object | ForEach-Object { Write-Host ("        origin : " + $_) }

    Write-Host "-- SSL Bindings --" -ForegroundColor White
    Get-AdfsSslCertificate | Sort-Object HostName, PortNumber | ForEach-Object {
        Write-Host ("   " + $_.HostName + ":" + $_.PortNumber + " -> " + $_.CertificateHash)
    }
}

# --- Discover environment from the bound cert + federation properties ---
$svcThumb = (@(Get-AdfsCertificate -CertificateType Service-Communications))[0].Thumbprint
$cert     = Get-Item ("Cert:\LocalMachine\My\" + $svcThumb)
$sans     = Get-CertificateDnsNames -Cert $cert
$suffix   = Get-NewHostSuffixFromCertificateWildcardSan -Cert $cert
if ([string]::IsNullOrWhiteSpace($suffix)) { $suffix = Get-NewHostSuffixFromCertificateSans -Cert $cert }
$adfsHost = (Get-AdfsProperties).HostName.ToLowerInvariant()
$adfsOrigin = "https://" + $adfsHost
# The site currently deployed (inferred from the federation host), so the test
# re-codes home -> <Site> by stripping the old site rather than stacking it.
$currentSite = Get-SiteCodeFromAdfsHost -Hostname $adfsHost
# -Site site-codes the federation host too (replacing it, since it is singular).
$effectiveAdfsHost = Add-SiteToHost -Hostname $adfsHost -Site $Site -CurrentSite $currentSite
if ([string]::IsNullOrWhiteSpace($effectiveAdfsHost)) { $effectiveAdfsHost = $adfsHost }
$effectiveAdfsOrigin = "https://" + $effectiveAdfsHost

Write-Host ""
Write-Host "================ Test: -Site '$Site' ================" -ForegroundColor Cyan
Write-Host ("  Suffix             : " + $suffix)
Write-Host ("  ADFS host          : " + $adfsHost)
Write-Host ("  Current site       : " + $(if ($currentSite) { $currentSite } else { '(none)' }))
Write-Host ("  ADFS host (coded)  : " + $effectiveAdfsHost + "   (federation host is site-coded / replaced)")
Write-Host ("  Cert SANs          : " + ($sans -join ', '))

# --- Capture baseline ---
$baseApps        = Get-NativeAppMap
$baseCors        = @((Get-AdfsResponseHeaders).CORSTrustedOrigins)
$baseCorsEnabled = [bool](Get-AdfsResponseHeaders).CORSEnabled

# The shipped Update-CorsTrustedOrigins reads $NonInteractive from scope; set it so
# the CORS apply runs without the interactive add/rm editor during the test.
$NonInteractive = $true

Show-State "1. PREVIOUS ENVIRONMENT (baseline, before any change)"

try {
    # ===== APPLY -Site via the shipped functions =====
    # 6>$null suppresses the migration functions' own Write-Host progress so the
    # three Show-State snapshots stay clean. Return values still flow normally.
    foreach ($e in $baseApps) {
        $new = Build-ReplacedRedirectList -ExistingRedirects $e.Uris -OldSuffix $suffix -NewSuffix $suffix -SanNames $sans -Site $Site -CurrentSite $currentSite
        Set-AdfsNativeClientApplication -TargetApplication (Get-NativeApp -Id $e.Id) -RedirectUri $new -ErrorAction Stop
    }
    $proposed = @(Resolve-AppCorsOrigins -SanNames $sans -TargetAdfsHostname $effectiveAdfsHost -OldSuffix $suffix -NewSuffix $suffix -ParamExtraOrigins '' -Site $Site -CurrentSite $currentSite 6>$null)
    Update-CorsTrustedOrigins -OldSuffix $suffix -NewSuffix $suffix -ParamExtraOrigins '' -SanNames $sans -TargetAdfsHostname $effectiveAdfsHost -ProposedOrigins $proposed 6>$null

    # ===== MODIFIED (SITE) ENVIRONMENT =====
    $afterApps = Get-NativeAppMap
    $afterCors = @((Get-AdfsResponseHeaders).CORSTrustedOrigins)
    Show-State ("2. MODIFIED ENVIRONMENT (after -Site '" + $Site + "')")

    # ===== ASSERTIONS =====
    Write-Host ""
    Write-Host "---------------- ASSERTIONS ----------------" -ForegroundColor Cyan

    Write-Host "Redirect URIs (site host replaces base/prior-site, 1:1):"
    foreach ($e in $baseApps) {
        $a = $afterApps | Where-Object { $_.Id -eq $e.Id } | Select-Object -First 1
        Assert ("redirect count unchanged : " + $e.Name) (@($a.Uris).Count -eq @($e.Uris).Count)
        foreach ($u in $e.Uris) {
            $exp = Expect-SiteUri -Uri $u -Site $Site -CurrentSite $currentSite
            Assert ("site host present : " + $exp) ($a.Uris -contains $exp)
            if ($exp -ne $u) {
                Assert ("prior host replaced : " + $u) (-not ($a.Uris -contains $u))
            }
        }
    }

    Write-Host "CORS origins:"
    Assert ("CORS origin count unchanged") (@($afterCors).Count -eq @($baseCors).Count)
    foreach ($o in $baseCors) {
        if ($o -eq $adfsOrigin) { continue }   # federation host handled separately below
        $exp = Expect-SiteOrigin -Origin $o -Site $Site -CurrentSite $currentSite
        Assert ("site origin present : " + $exp) ($afterCors -contains $exp)
        if ($exp -ne $o) {
            Assert ("prior origin replaced : " + $o) (-not ($afterCors -contains $o))
        }
    }
    # Federation host: site-coded form present (replaces the base).
    Assert ("ADFS host site-coded present : " + $effectiveAdfsOrigin) ($afterCors -contains $effectiveAdfsOrigin)
    # Nothing double/stacked: no host carries -<Site>-<Site> or -<currentSite>-<Site>.
    $stackPatterns = @(("-" + $Site + "-" + $Site))
    if ($currentSite -and $currentSite -ne $Site) { $stackPatterns += ("-" + $currentSite + "-" + $Site) }
    $stacked = @($afterCors | Where-Object { $h = ([System.Uri]$_).Host; ($stackPatterns | Where-Object { $h -match [regex]::Escape($_) }) })
    Assert ("no double/stacked site coding in CORS") ($stacked.Count -eq 0)
    # Prior site fully gone (when switching sites).
    if ($currentSite -and $currentSite -ne $Site) {
        $remnant = @($afterCors | Where-Object { ([System.Uri]$_).Host -match ('-' + [regex]::Escape($currentSite) + '(\.|$)') })
        Assert ("prior site '$currentSite' fully removed from CORS") ($remnant.Count -eq 0)
    }
}
finally {
    # ===== CLEANUP: restore exact baseline =====
    Write-Host ""
    Write-Host "---------------- CLEANUP (restore baseline) ----------------" -ForegroundColor Yellow
    foreach ($e in $baseApps) {
        try { Set-AdfsNativeClientApplication -TargetApplication (Get-NativeApp -Id $e.Id) -RedirectUri $e.Uris -ErrorAction Stop }
        catch { Write-Host ("  restore failed for " + $e.Name + ": " + $_.Exception.Message) -ForegroundColor Red }
    }
    Set-AdfsResponseHeaders -EnableCORS $baseCorsEnabled -CORSTrustedOrigins $baseCors

    Show-State "3. RESTORED ENVIRONMENT (reset - should match #1)"

    # Verify restore matches baseline
    $restoredCors = @((Get-AdfsResponseHeaders).CORSTrustedOrigins)
    Assert ("CORS restored to baseline") (@(Compare-Object -ReferenceObject $baseCors -DifferenceObject $restoredCors).Count -eq 0)
    foreach ($e in $baseApps) {
        $r = Get-NativeAppMap | Where-Object { $_.Id -eq $e.Id } | Select-Object -First 1
        Assert ("redirects restored: " + $e.Name) (@(Compare-Object -ReferenceObject $e.Uris -DifferenceObject $r.Uris).Count -eq 0)
    }
}

Write-Host ""
$resultColor = 'Green'
if ($script:Fail -gt 0) { $resultColor = 'Red' }
Write-Host ("================ RESULT: {0} passed, {1} failed ================" -f $script:Pass, $script:Fail) -ForegroundColor $resultColor
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }
