# ADFS PFX Certificate & Redirect URI Migration Script

Replaces an ADFS self-signed certificate with a PFX-based certificate and migrates all associated hostname references — native app redirect URIs, CORS trusted origins, and Federation Service Properties — from an old domain suffix to the new one encoded in the certificate.

## Requirements

- Must be run **as Administrator** on an ADFS node
- Windows PowerShell with the `ADFS` module available (`Import-Module ADFS`)
- A valid `.pfx` file containing the new certificate and its private key

---

## What It Does

The script performs the following steps in order:

1. **Imports the PFX** into `Cert:\LocalMachine\My` and selects the best leaf certificate (has private key, is not a CA cert).
2. **Optionally validates** that a specific DNS name appears in the certificate's SAN or Subject CN (`-ExpectedDnsName`).
3. **Determines the old and new host suffixes** — either from explicit parameters or by auto-detection:
   - **New suffix**: extracted from a wildcard SAN (e.g. `*.newdomain.com`) or inferred as the longest common suffix shared by all explicit SANs.
   - **Old suffix**: read from the existing ADFS CORS trusted origins.
4. **Updates redirect URIs** on all ADFS native client applications.
5. **Updates Federation Service Properties** (DisplayName, HostName, Identifier).
6. **Updates CORS Trusted Origins**.
7. **Binds the new certificate** as the ADFS Service Communications certificate and SSL certificate.
8. **Restarts the ADFS service** and waits up to 60 seconds to confirm it comes back up.

### Hostname Matching: Suffix Swap vs. SAN Label Matching

The script uses two hostname replacement strategies depending on the certificate type:

**Suffix swap** (wildcard cert, e.g. `*.example.com`):
The old hostname prefix is preserved and only the domain suffix is replaced.
```
admin.olddomain.com  →  admin.newdomain.com
```

**SAN label matching** (host-specific cert):
When the certificate contains explicit hostnames rather than a wildcard, the script extracts the service label (first DNS segment) from each old hostname and finds the certificate SAN whose first label contains that service name as a hyphen-delimited segment.

Example — cert SANs: `wids-admin-site01.newdomain.com`, `wids-dvr-site01.newdomain.com`, ...

| Old hostname | Service label | Matched SAN |
|---|---|---|
| `admin.olddomain.com` | `admin` | `wids-admin-site01.newdomain.com` |
| `dvr.olddomain.com` | `dvr` | `wids-dvr-site01.newdomain.com` |
| `device.olddomain.com` | `device` | `wids-device-site01.newdomain.com` |
| `explorer.olddomain.com` | `explorer` | `wids-explorer-site01.newdomain.com` |
| `wti.olddomain.com` | `wti` | `wids-wti-site01.newdomain.com` |

URI paths and ports are preserved in both cases. If no SAN match is found for a hostname, that URI is skipped with a warning rather than silently dropped.

---

## Usage

```powershell
.\Install-ADFS-pfx-Redirects.ps1 -PfxPath "C:\Temp\adfs-cert.pfx"
```

The script will auto-detect the old and new host suffixes and prompt for confirmation at each step.

### With a password-protected PFX

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -PfxPassword (Read-Host "PFX Password" -AsSecureString)
```

### With explicit suffix overrides

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -OldHostSuffix "olddomain.com" `
    -NewHostSuffix "newdomain.com"
```

### Validate the certificate covers the ADFS host

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -ExpectedDnsName "wids-auth-adfs-site01.newdomain.com"
```

### Non-interactive (automation / scripted deployment)

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -OldHostSuffix "olddomain.com" `
    -NonInteractive
```

### Skip individual steps

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -SkipCors `
    -SkipFederationServiceProperties
```

---

## Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-PfxPath` | `string` | Yes | Path to the `.pfx` file to import. |
| `-PfxPassword` | `SecureString` | No | Password for the PFX. Prompted if omitted and the file requires one. |
| `-OldHostSuffix` | `string` | No | Domain suffix to replace (e.g. `olddomain.com`). Auto-detected from CORS trusted origins if omitted. |
| `-NewHostSuffix` | `string` | No | Replacement domain suffix. Auto-detected from the certificate SANs if omitted. |
| `-ExpectedDnsName` | `string` | No | A specific DNS name that must appear in the certificate SAN or Subject CN. The script warns and prompts if it is absent. |
| `-CorsExtraOrigins` | `string` | No | Comma-separated list of additional origins to add to CORS trusted origins (merged with migrated origins). |
| `-NoExportable` | `switch` | No | Import the certificate as non-exportable. Exportable by default. |
| `-SkipServiceCommunications` | `switch` | No | Skip binding the new cert as the Service Communications certificate. |
| `-SkipAdfsSsl` | `switch` | No | Skip binding the new cert as the ADFS SSL certificate. |
| `-SkipCors` | `switch` | No | Skip updating CORS trusted origins. |
| `-SkipFederationServiceProperties` | `switch` | No | Skip updating Federation Service Properties (HostName, DisplayName, Identifier). |
| `-NonInteractive` | `switch` | No | Suppress all confirmation prompts. All applicable steps run automatically. Use for scripted deployments. |

---

## Auto-Detection Behavior

### New host suffix

1. Checks for a wildcard SAN (e.g. `*.newdomain.com` → `newdomain.com`).
2. If no wildcard exists, finds the longest domain suffix shared by **all** SANs (e.g. every explicit SAN ends in `.newdomain.com`).
3. Fails with an error if neither approach yields a result — provide `-NewHostSuffix` explicitly.

### Old host suffix

Reads the existing ADFS CORS trusted origins and extracts the domain suffix from the first well-formed origin. Fails if none are found — provide `-OldHostSuffix` explicitly.

---

## Important Notes

- **The redirect URI set is replaced, not merged.** Each native app's redirect URIs are set to exactly the migrated list. Any existing URI that does not match the old suffix is not carried over. Review current registrations before running.
- **Run on every ADFS node.** Certificate binding (`Set-AdfsCertificate`, `Set-AdfsSslCertificate`) must be applied on each node in the farm; the ADFS configuration changes (redirect URIs, CORS, properties) only need to run once.
- **ADFS service restart is always performed** at the end of the script. Plan for a brief service interruption.
- The script requires PowerShell to be running as Administrator. It will exit immediately if the privilege check fails.
