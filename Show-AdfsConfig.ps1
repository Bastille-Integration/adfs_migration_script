# Version: 1.0
# Read-only snapshot of the Bastille-relevant ADFS configuration:
# Federation Service properties, each application group's native + Web API apps
# (redirect URIs, client ids, access-control policies), CORS trusted origins,
# certificates, and SSL bindings. Makes no changes.
#
# Requires: Run as Administrator on an ADFS node with the ADFS PowerShell module.
# Usage:   .\Show-AdfsConfig.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module ADFS -ErrorAction Stop

Write-Host "================ Federation Service ================" -ForegroundColor Cyan
$p = Get-AdfsProperties
Write-Host ("  HostName            : " + $p.HostName)
Write-Host ("  Identifier          : " + $p.Identifier)
Write-Host ("  DisplayName         : " + $p.DisplayName)
Write-Host ("  AutoCertRollover    : " + $p.AutoCertificateRollover)
Write-Host ("  CertificateDuration : " + $p.CertificateDuration)

Write-Host ""
Write-Host "================ Application Groups ================" -ForegroundColor Cyan
foreach ($g in (Get-AdfsApplicationGroup | Sort-Object Name)) {
    Write-Host ("  [" + $g.Name + "]") -ForegroundColor Gray
    foreach ($a in @(Get-AdfsNativeClientApplication -ApplicationGroupIdentifier $g.ApplicationGroupIdentifier -ErrorAction SilentlyContinue)) {
        Write-Host ("    Native : " + $a.Name + "   (ClientId " + $a.Identifier + ")")
        @($a.RedirectUri) | Sort-Object | ForEach-Object { Write-Host ("        redirect : " + $_) }
    }
    foreach ($w in @(Get-AdfsWebApiApplication -ApplicationGroupIdentifier $g.ApplicationGroupIdentifier -ErrorAction SilentlyContinue)) {
        Write-Host ("    WebAPI : " + $w.Name + "   (AccessControlPolicy: " + $w.AccessControlPolicyName + ")")
        @($w.Identifier) | ForEach-Object { Write-Host ("        identifier : " + $_) }
    }
}

Write-Host ""
Write-Host "================ CORS (Response Headers) ================" -ForegroundColor Cyan
$h = Get-AdfsResponseHeaders
Write-Host ("  CORSEnabled : " + $h.CORSEnabled + "   (" + @($h.CORSTrustedOrigins).Count + " origins)")
@($h.CORSTrustedOrigins) | Sort-Object | ForEach-Object { Write-Host ("        origin : " + $_) }

Write-Host ""
Write-Host "================ Certificates ================" -ForegroundColor Cyan
Get-AdfsCertificate | Sort-Object CertificateType | ForEach-Object {
    Write-Host ("  " + $_.CertificateType + " : " + $_.Thumbprint + "   IsPrimary=" + $_.IsPrimary)
}

Write-Host ""
Write-Host "================ SSL Bindings ================" -ForegroundColor Cyan
Get-AdfsSslCertificate | Sort-Object HostName, PortNumber | ForEach-Object {
    Write-Host ("  " + $_.HostName + ":" + $_.PortNumber + " -> " + $_.CertificateHash)
}
