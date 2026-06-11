# Version: 1.0
# Test suite for the -Site feature of Install-ADFS-pfx-Redirects.ps1.
#
# Loads the shipped functions from the migration script (without running the
# migration), applies a -Site code to the LIVE ADFS native-app redirect URIs and
# CORS origins, prints before/after, runs PASS/FAIL assertions, then restores the
# exact pre-existing state in a finally block (runs even if an assertion throws).
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

# Independent expectation builders (not the shipped Add-SiteTo* - so the test
# verifies behavior rather than just re-deriving from the implementation).
function Expect-SiteUri {
    param([string]$Uri, [string]$Site)
    $u = [System.Uri]$Uri
    $labels = $u.Host -split '\.'
    $labels[0] = $labels[0] + '-' + $Site
    $b = New-Object System.UriBuilder($u)
    $b.Host = ($labels -join '.')
    return $b.Uri.AbsoluteUri
}
function Expect-SiteOrigin {
    param([string]$Origin, [string]$Site)
    $u = [System.Uri]$Origin
    $labels = $u.Host -split '\.'
    $labels[0] = $labels[0] + '-' + $Site
    return ($u.Scheme + '://' + ($labels -join '.'))
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
    Write-Host ("   AutoCertRollover    : " + $p.AutoCertificateRollover)
    Write-Host ("   CertificateDuration : " + $p.CertificateDuration)

    Write-Host "-- Application Groups --" -ForegroundColor White
    foreach ($g in (Get-AdfsApplicationGroup | Sort-Object Name)) {
        Write-Host ("   [" + $g.Name + "]") -ForegroundColor Gray
        foreach ($a in @(Get-AdfsNativeClientApplication -ApplicationGroupIdentifier $g.ApplicationGroupIdentifier -ErrorAction SilentlyContinue)) {
            Write-Host ("     Native : " + $a.Name + "   (ClientId " + $a.Identifier + ")")
            @($a.RedirectUri) | Sort-Object | ForEach-Object { Write-Host ("        redirect : " + $_) }
        }
        foreach ($w in @(Get-AdfsWebApiApplication -ApplicationGroupIdentifier $g.ApplicationGroupIdentifier -ErrorAction SilentlyContinue)) {
            Write-Host ("     WebAPI : " + $w.Name + "   (AccessControlPolicy: " + $w.AccessControlPolicyName + ")")
            @($w.Identifier) | ForEach-Object { Write-Host ("        identifier : " + $_) }
        }
    }

    Write-Host "-- CORS (Response Headers) --" -ForegroundColor White
    $h = Get-AdfsResponseHeaders
    Write-Host ("   CORSEnabled : " + $h.CORSEnabled + "   (origins: " + @($h.CORSTrustedOrigins).Count + ")")
    @($h.CORSTrustedOrigins) | Sort-Object | ForEach-Object { Write-Host ("        origin : " + $_) }

    Write-Host "-- Certificates --" -ForegroundColor White
    Get-AdfsCertificate | Sort-Object CertificateType | ForEach-Object {
        Write-Host ("   " + $_.CertificateType + " : " + $_.Thumbprint + "   IsPrimary=" + $_.IsPrimary)
    }

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
# -Site site-codes the federation host too (auth.adfs -> auth-<site>.adfs), matching
# the main script. The federation host is singular, so it is replaced (not base+variant).
$effectiveAdfsHost   = Add-SiteToHost -Hostname $adfsHost -Site $Site
if ([string]::IsNullOrWhiteSpace($effectiveAdfsHost)) { $effectiveAdfsHost = $adfsHost }
$effectiveAdfsOrigin = "https://" + $effectiveAdfsHost

Write-Host ""
Write-Host "================ Test: -Site '$Site' ================" -ForegroundColor Cyan
Write-Host ("  Suffix             : " + $suffix)
Write-Host ("  ADFS host          : " + $adfsHost)
Write-Host ("  ADFS host (coded)  : " + $effectiveAdfsHost + "   (federation host is site-coded)")
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
        $new = Build-ReplacedRedirectList -ExistingRedirects $e.Uris -OldSuffix $suffix -NewSuffix $suffix -SanNames $sans -Site $Site
        Set-AdfsNativeClientApplication -TargetApplication (Get-NativeApp -Id $e.Id) -RedirectUri $new -ErrorAction Stop
    }
    $proposed = @(Resolve-AppCorsOrigins -SanNames $sans -TargetAdfsHostname $effectiveAdfsHost -OldSuffix $suffix -NewSuffix $suffix -ParamExtraOrigins '' -Site $Site 6>$null)
    Update-CorsTrustedOrigins -OldSuffix $suffix -NewSuffix $suffix -ParamExtraOrigins '' -SanNames $sans -TargetAdfsHostname $effectiveAdfsHost -ProposedOrigins $proposed 6>$null

    # ===== MODIFIED (SITE) ENVIRONMENT =====
    $afterApps = Get-NativeAppMap
    $afterCors = @((Get-AdfsResponseHeaders).CORSTrustedOrigins)
    Show-State ("2. MODIFIED ENVIRONMENT (after -Site '" + $Site + "')")

    # ===== ASSERTIONS =====
    Write-Host ""
    Write-Host "---------------- ASSERTIONS ----------------" -ForegroundColor Cyan

    Write-Host "Redirect URIs:"
    foreach ($e in $baseApps) {
        $a = $afterApps | Where-Object { $_.Id -eq $e.Id } | Select-Object -First 1
        foreach ($u in $e.Uris) {
            Assert ("base preserved : " + $u) ($a.Uris -contains $u)
            Assert ("site variant   : " + (Expect-SiteUri -Uri $u -Site $Site)) ($a.Uris -contains (Expect-SiteUri -Uri $u -Site $Site))
        }
    }

    Write-Host "CORS origins:"
    foreach ($o in $baseCors) {
        if ($o -eq $adfsOrigin) { continue }   # federation host handled separately below
        Assert ("base preserved : " + $o) ($afterCors -contains $o)
        $exp = Expect-SiteOrigin -Origin $o -Site $Site
        Assert ("site variant   : " + $exp) ($afterCors -contains $exp)
    }
    # Federation host: site-coded form present (replaces the base), and not double-coded.
    Assert ("ADFS host site-coded present : " + $effectiveAdfsOrigin) ($afterCors -contains $effectiveAdfsOrigin)
    $doubleCoded = Expect-SiteOrigin -Origin $effectiveAdfsOrigin -Site $Site
    Assert ("ADFS host not double-coded ($doubleCoded absent)") (-not ($afterCors -contains $doubleCoded))
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
