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
# Usage:
#   .\Test-SiteFeature.ps1
#   .\Test-SiteFeature.ps1 -Site sitetest -ScriptPath .\Install-ADFS-pfx-Redirects.ps1

[CmdletBinding()]
param(
    [string]$ScriptPath = '',
    [string]$Site = 'sitetest'
)

$ErrorActionPreference = 'Stop'
Import-Module ADFS -ErrorAction Stop

# Resolve the migration script path (param > script dir > current dir).
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $base = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($base) -and $MyInvocation.MyCommand.Path) { $base = Split-Path -Parent $MyInvocation.MyCommand.Path }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = (Get-Location).Path }
    $ScriptPath = Join-Path $base 'Install-ADFS-pfx-Redirects.ps1'
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

# Print the full live state (redirect URIs per app + CORS) under a labelled banner.
function Show-State {
    param([string]$Label)
    Write-Host ""
    Write-Host ("================ " + $Label + " ================") -ForegroundColor Cyan
    foreach ($g in (Get-AdfsApplicationGroup | Sort-Object Name)) {
        foreach ($a in @(Get-AdfsNativeClientApplication -ApplicationGroup $g -ErrorAction SilentlyContinue)) {
            Write-Host ("  [{0}] {1}" -f $g.Name, $a.Name) -ForegroundColor Gray
            @($a.RedirectUri) | Sort-Object | ForEach-Object { Write-Host ("      " + $_) }
        }
    }
    $h = Get-AdfsResponseHeaders
    Write-Host ("  CORS (Enabled={0}, {1} origins):" -f $h.CORSEnabled, @($h.CORSTrustedOrigins).Count) -ForegroundColor Gray
    @($h.CORSTrustedOrigins) | Sort-Object | ForEach-Object { Write-Host ("      " + $_) }
}

# --- Discover environment from the bound cert + federation properties ---
$svcThumb = (@(Get-AdfsCertificate -CertificateType Service-Communications))[0].Thumbprint
$cert     = Get-Item ("Cert:\LocalMachine\My\" + $svcThumb)
$sans     = Get-CertificateDnsNames -Cert $cert
$suffix   = Get-NewHostSuffixFromCertificateWildcardSan -Cert $cert
if ([string]::IsNullOrWhiteSpace($suffix)) { $suffix = Get-NewHostSuffixFromCertificateSans -Cert $cert }
$adfsHost = (Get-AdfsProperties).HostName.ToLowerInvariant()
$adfsOrigin = "https://" + $adfsHost

Write-Host ""
Write-Host "================ Test: -Site '$Site' ================" -ForegroundColor Cyan
Write-Host ("  Suffix    : " + $suffix)
Write-Host ("  ADFS host : " + $adfsHost + "   (must NOT be site-coded)")
Write-Host ("  Cert SANs : " + ($sans -join ', '))

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
    foreach ($e in $baseApps) {
        $new = Build-ReplacedRedirectList -ExistingRedirects $e.Uris -OldSuffix $suffix -NewSuffix $suffix -SanNames $sans -Site $Site
        Set-AdfsNativeClientApplication -TargetApplication (Get-NativeApp -Id $e.Id) -RedirectUri $new -ErrorAction Stop
    }
    $proposed = @(Resolve-AppCorsOrigins -SanNames $sans -TargetAdfsHostname $adfsHost -OldSuffix $suffix -NewSuffix $suffix -ParamExtraOrigins '' -Site $Site)
    Update-CorsTrustedOrigins -OldSuffix $suffix -NewSuffix $suffix -ParamExtraOrigins '' -SanNames $sans -TargetAdfsHostname $adfsHost -ProposedOrigins $proposed

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
        Assert ("base preserved : " + $o) ($afterCors -contains $o)
        if ($o -ne $adfsOrigin) {
            $exp = Expect-SiteOrigin -Origin $o -Site $Site
            Assert ("site variant   : " + $exp) ($afterCors -contains $exp)
        }
    }
    $adfsSiteOrigin = Expect-SiteOrigin -Origin $adfsOrigin -Site $Site
    Assert ("ADFS host NOT site-coded ($adfsSiteOrigin absent)") (-not ($afterCors -contains $adfsSiteOrigin))
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
