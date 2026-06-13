# Version: 1.0
# Offline regression test for the SAN-resolution helpers in
# Install-ADFS-pfx-From_Scratch.ps1 - the functions that decide the federation
# service name, the per-app hostnames (redirect URIs), and the CORS origins from a
# certificate's SANs. These must work for BOTH cert conventions:
#
#   * WILDCARD (the standard Bastille bn-wids cert: <d>, *.<d>, *.adfs.<d>)
#   * FLAT per-host (e.g. wids-admin-abl16.<d>, wids-auth-adfs-abl16.<d>)
#   * DOTTED literal (bn.internal style: <d>, *.<d>, auth.adfs.<d>)
#
# It loads the shipped functions (without running the installer) and makes NO
# changes - safe to run anywhere.
#
# Usage (from the testing_suite directory):
#   .\Test-FromScratch.ps1

[CmdletBinding()]
param([string]$ScriptPath = '')

$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($here) -and $MyInvocation.MyCommand.Path) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrWhiteSpace($here)) { $here = (Get-Location).Path }

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $candidates = @(
        (Join-Path (Split-Path -Parent $here) 'Install-ADFS-pfx-From_Scratch.ps1'),
        (Join-Path $here 'Install-ADFS-pfx-From_Scratch.ps1'),
        (Join-Path (Get-Location).Path 'Install-ADFS-pfx-From_Scratch.ps1')
    )
    $ScriptPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($ScriptPath)) { $ScriptPath = $candidates[0] }
}
if (-not (Test-Path $ScriptPath)) { throw "Script not found: $ScriptPath" }

# --- Load the shipped functions (from the first 'function ' to the '# Main' banner) ---
$raw = Get-Content $ScriptPath -Raw
$fi  = $raw.IndexOf('function ')
$end = $raw.IndexOf("`n# Main")
if ($fi -lt 0 -or $end -lt 0 -or $end -le $fi) { throw "Could not locate the function block in $ScriptPath" }
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('_fsfuncs_' + [guid]::NewGuid().ToString('N') + '.ps1')
Set-Content -Path $tmp -Value $raw.Substring($fi, $end - $fi) -Encoding ASCII
. $tmp
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

$script:Pass = 0
$script:Fail = 0
function Assert {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { Write-Host ("  [PASS] " + $Name) -ForegroundColor Green; $script:Pass++ }
    else { Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red; if ($Detail) { Write-Host ("         " + $Detail) -ForegroundColor DarkYellow }; $script:Fail++ }
}

# App labels the installer resolves (from $AppDefinitions + the CORS list).
$AppLabels = @('admin', 'dvr', 'device', 'explorer', 'wtiapi')

$scenarios = @(
    [pscustomobject]@{
        Name       = 'WILDCARD (standard bn-wids cert)'
        Sans       = @('bn-wids.internal', '*.bn-wids.internal', '*.adfs.bn-wids.internal')
        ExpectSuffix = 'bn-wids.internal'          # shortest wildcard, not adfs.<d>
        ExpectAdfs   = 'auth.adfs.bn-wids.internal' # derived from *.adfs.<d>
        ExpectApp    = { param($l) "$l.bn-wids.internal" }
    },
    [pscustomobject]@{
        Name       = 'FLAT per-host cert'
        Sans       = @('wids-lab16.oraphys-lab.example', 'wids-admin-lab16.oraphys-lab.example',
                       'wids-dvr-lab16.oraphys-lab.example', 'wids-device-lab16.oraphys-lab.example',
                       'wids-explorer-lab16.oraphys-lab.example', 'wids-wtiapi-lab16.oraphys-lab.example',
                       'wids-auth-adfs-lab16.oraphys-lab.example')
        ExpectSuffix = 'oraphys-lab.example'
        ExpectAdfs   = 'wids-auth-adfs-lab16.oraphys-lab.example'
        ExpectApp    = { param($l) "wids-$l-lab16.oraphys-lab.example" }
    },
    [pscustomobject]@{
        Name       = 'DOTTED literal cert (bn.internal style)'
        Sans       = @('bn.internal', '*.bn.internal', 'auth.adfs.bn.internal')
        ExpectSuffix = 'bn.internal'
        ExpectAdfs   = 'auth.adfs.bn.internal'      # literal dotted SAN
        ExpectApp    = { param($l) "$l.bn.internal" }
    }
)

Write-Host ""
Write-Host "================ From-Scratch resolver regression test ================" -ForegroundColor Cyan
Write-Host ("  Script : " + $ScriptPath)

foreach ($s in $scenarios) {
    Write-Host ""
    Write-Host ("===== " + $s.Name + " =====") -ForegroundColor Magenta

    $suffix = Get-NewHostSuffixFromSans -DnsNames $s.Sans
    Assert ("suffix = " + $s.ExpectSuffix) ($suffix -eq $s.ExpectSuffix) ("got: '$suffix'")

    $adfs = Find-AdfsSanHostname -SanNames $s.Sans
    Assert ("federation host = " + $s.ExpectAdfs) ($adfs -eq $s.ExpectAdfs) ("got: '$adfs'")

    foreach ($l in $AppLabels) {
        $want = (& $s.ExpectApp $l)
        $got  = Resolve-HostnameFromSans -ServiceLabel $l -SanNames $s.Sans
        Assert ("resolve '$l' -> $want") ($got -eq $want) ("got: '$got'")
    }

    # wtiapi must resolve to its own host, never a bare 'wti' host.
    $wtiapi = Resolve-HostnameFromSans -ServiceLabel 'wtiapi' -SanNames $s.Sans
    Assert ("wtiapi host carries 'wtiapi'") ($wtiapi -match 'wtiapi') ("got: '$wtiapi'")
}

# Multi-wildcard: the deeper *.adfs.<d> must NOT splice into app hosts.
$mw = Resolve-HostnameFromSans -ServiceLabel 'admin' -SanNames @('*.bn-wids.internal', '*.adfs.bn-wids.internal')
Assert ("multi-wildcard: admin -> admin.bn-wids.internal (not .adfs.)") ($mw -eq 'admin.bn-wids.internal') ("got: '$mw'")

Write-Host ""
$color = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
Write-Host ("================ RESULT: {0} passed, {1} failed ================" -f $script:Pass, $script:Fail) -ForegroundColor $color
if ($script:Fail -gt 0) { exit 1 }
