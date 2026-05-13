# ADFS PFX Deployment Scripts

| Script | Purpose |
|---|---|
| `Install-ADFS-pfx-From_Scratch.ps1` | Fresh ADFS deployment — installs the Windows feature, configures the farm, creates AD groups and users, registers all Bastille application groups, and applies access control policies. |
| `Install-ADFS-pfx-Redirects.ps1` | Certificate migration — replaces an existing ADFS self-signed certificate with a PFX and updates all hostname references. |
| `Invoke-AdfsTroubleshoot.ps1` | Troubleshooting — checks ADFS service health, certificate expiry, recent event log errors, and AD/ADFS account lockout status. Can list all locked accounts or target a specific user and unlock them. |

---

# Getting the Scripts onto the Server

## Allow PowerShell to Run the Scripts

Windows Server defaults to a restricted execution policy. If running the scripts produces an error about execution policy, set it for the current session:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

Or permanently for the local machine (requires Administrator):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

---

# Install-ADFS-pfx-From_Scratch.ps1

Performs a complete first-time ADFS configuration for the Bastille Platform using a PFX certificate.

## Requirements

- Must be run **as Administrator** on the target ADFS node
- Windows Server 2016 or later with Server Manager available (`Get-WindowsFeature`)
- Windows PowerShell with the `ADFS` module available (installed automatically with the feature)
- The **Active Directory** PowerShell module (`RSAT-AD-PowerShell`) for AD group and user creation
- A valid `.pfx` file containing the new certificate and its private key

> **IIS note:** Microsoft IIS (`Web-Server`) is required for ADFS to host its endpoints. The script installs it automatically alongside `ADFS-Federation` in Step 1.

---

## What It Does

The script performs the following steps in order:

1. **Installs the ADFS-Federation and Web-Server (IIS) Windows features** (skippable with `-SkipWindowsFeature`).
2. **Imports the PFX** into `Cert:\LocalMachine\My` and selects the best leaf certificate.
3. **Grants the ADFS service account** (`NT SERVICE\adfssrv`) read access to the imported private key.
4. **Resolves the Federation Service Name** from a SAN segment containing `adfs`, or from `-FederationServiceName`.
5. **Installs the ADFS farm** via `Install-AdfsFarm`.
6. **Binds the SSL certificate** and verifies HTTP.SYS bindings directly via `netsh`.
7. **Sets the Service Communications certificate**.
8. **Enables CORS and configures trusted origins** from cert SANs (`EnableCORS $true` + `CORSTrustedOrigins`).
9. **Creates AD security groups** — `Bastille Admins` and `Bastille Users` (skippable with `-SkipAdGroups`).
10. **Creates test AD users** and assigns them to groups (opt-in with `-CreateTestUsers`):
    - `BN Test` → `Bastille Admins`
    - `BN User` → `Bastille Users`
11. **Registers Bastille application groups** in ADFS — one Application Group per product, each with a Native Client Application, a Web API Application, OAuth2 scopes (`openid`, `profile`), and issuance transform claim rules.
12. **Applies access control policies** on each Web API:
    - `Bastille Admin`, `Bastille ADAM`, `Bastille ADAM API` → Permit `Bastille Admins` only
    - `Bastille DVR and Device` → Permit `Bastille Admins` and `Bastille Users`
13. **Restarts the ADFS service**.

### Registered Application Groups

| Application Group | Client ID | Service Labels | Permitted Groups |
|---|---|---|---|
| Bastille Admin | `bastille-admin` | `admin` | Bastille Admins |
| Bastille DVR and Device | `bastille-dvr-device` | `dvr`, `device` | Bastille Admins, Bastille Users |
| Bastille ADAM | `bastille-adam` | `explorer` | Bastille Admins |
| Bastille ADAM API | `bastille-adam-api` | `wti` | Bastille Admins |

Redirect URIs are built at runtime by resolving each service label against the certificate SANs. See [SAN Label Matching](#san-label-matching) below.

### Callback URLs

The following callback URLs are registered per application group, with hostnames resolved from the certificate SANs:

**Admin Console**
- `https://<admin-host>/authenticated`
- `https://<admin-host>/signin-callback`
- `https://<admin-host>/signout-callback`

**DVR Console**
- `https://<dvr-host>/authenticated`
- `https://<dvr-host>/signin-callback`
- `https://<dvr-host>/signout-callback`

**Device Dashboard**
- `https://<device-host>/authenticated`
- `https://<device-host>/signin-callback`
- `https://<device-host>/signout-callback`

**ADAM Explorer**
- `https://<explorer-host>/auth-callback`
- `https://<explorer-host>/authenticated`
- `https://<explorer-host>/signin-callback`
- `https://<explorer-host>/signout-callback`

**ADAM API**
- `https://<wti-host>/authenticated`
- `https://<wti-host>/signin-callback`
- `https://<wti-host>/signout-callback`

### Claim Rules

The following issuance transform rules are applied to every Web API application:

**UPN rule** — issues the user's UPN and group memberships as role claims:
```
@RuleName = "UPN"
c:[Type == "...windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory",
          types = ("...upn", "...role"),
          query = ";userPrincipalName,tokenGroups;{0}", param = c.Value);
```

**Groups-Roles rule** — issues AD token groups as role claims:
```
@RuleName = "Groups-Roles"
c:[Type == "...windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory",
          types = ("...role"),
          query = ";tokenGroups;{0}", param = c.Value);
```

---

## Usage

```powershell
.\Install-ADFS-pfx-From_Scratch.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -ServiceAccountCredential (Get-Credential)
```

### With a Group Managed Service Account (gMSA)

```powershell
.\Install-ADFS-pfx-From_Scratch.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -GroupServiceAccountIdentifier "DOMAIN\adfssvc$"
```

### With a password-protected PFX

```powershell
.\Install-ADFS-pfx-From_Scratch.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -PfxPassword (Read-Host "PFX Password" -AsSecureString) `
    -ServiceAccountCredential (Get-Credential)
```

### Create test users and place groups in a specific OU

```powershell
.\Install-ADFS-pfx-From_Scratch.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -ServiceAccountCredential (Get-Credential) `
    -AdGroupsOu "OU=Bastille,OU=Groups,DC=domain,DC=com" `
    -CreateTestUsers `
    -AdUsersOu  "OU=Bastille,OU=Users,DC=domain,DC=com"
```

### Non-interactive (scripted deployment)

```powershell
.\Install-ADFS-pfx-From_Scratch.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -ServiceAccountCredential $cred `
    -NonInteractive
```

### Skip steps that have already been completed

```powershell
.\Install-ADFS-pfx-From_Scratch.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -ServiceAccountCredential (Get-Credential) `
    -SkipWindowsFeature `
    -SkipAdGroups
```

---

## Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-PfxPath` | `string` | Yes | Path to the `.pfx` file to import. |
| `-PfxPassword` | `SecureString` | No | Password for the PFX. Prompted at runtime if omitted and the file requires one. |
| `-FederationServiceName` | `string` | No | ADFS federation service hostname. Auto-detected from a SAN segment containing `adfs` if omitted. |
| `-FederationServiceDisplayName` | `string` | No | Display name for the federation service. Defaults to `"ADFS Federation Service"`. |
| `-ServiceAccountCredential` | `PSCredential` | — | Service account credential. Mutually exclusive with `-GroupServiceAccountIdentifier` and `-UseNetworkService`. |
| `-GroupServiceAccountIdentifier` | `string` | — | gMSA identifier (e.g. `DOMAIN\adfssvc$`). Mutually exclusive with the other service account options. |
| `-UseNetworkService` | `switch` | — | Use `NT AUTHORITY\Network Service`. Mutually exclusive with the other service account options. |
| `-OverrideServiceAccount` | `switch` | No | Pass `-OverrideServiceAccount` to `Install-AdfsFarm`. Required when using a local or non-domain account. |
| `-NoExportable` | `switch` | No | Import the certificate as non-exportable. Exportable by default. |
| `-SkipWindowsFeature` | `switch` | No | Skip the ADFS-Federation feature installation check. |
| `-SkipAdGroups` | `switch` | No | Skip creation of `Bastille Admins` and `Bastille Users` AD security groups. |
| `-CreateTestUsers` | `switch` | No | Create `BN Test` and `BN User` AD accounts and assign them to their groups. |
| `-AdGroupsOu` | `string` | No | OU distinguished name for group creation. Default AD container if omitted. |
| `-AdUsersOu` | `string` | No | OU distinguished name for user creation. Default AD container if omitted. |
| `-SkipAppRegistration` | `switch` | No | Skip ADFS application group and Web API registration. |
| `-SkipAccessControlPolicies` | `switch` | No | Skip per-group access control policies on Web API applications (leaves `"Permit everyone"`). |
| `-SkipCors` | `switch` | No | Skip CORS trusted origins configuration. |
| `-NonInteractive` | `switch` | No | Suppress all confirmation prompts. |

### Service account — exactly one required

| Option | When to use |
|---|---|
| `-ServiceAccountCredential` | Standard domain user account |
| `-GroupServiceAccountIdentifier` | Group Managed Service Account (gMSA) |
| `-UseNetworkService` | `NT AUTHORITY\Network Service` (lab/dev only) |

---

## SAN Label Matching

Redirect URIs and CORS origins are resolved at runtime by matching service labels against the certificate SANs. The script extracts the first dot-segment of each SAN, splits it by hyphen, and checks whether the service label appears as a segment.

Example — cert SANs include `wids-admin-site01.newdomain.com`:

| Service label | Matched SAN |
|---|---|
| `admin` | `wids-admin-site01.newdomain.com` |
| `dvr` | `wids-dvr-site01.newdomain.com` |
| `device` | `wids-device-site01.newdomain.com` |
| `explorer` | `wids-explorer-site01.newdomain.com` |
| `wti` | `wids-wti-site01.newdomain.com` |

If no SAN matches a label, that application group's redirect URIs are skipped with a warning.

---

## Important Notes

- **One service account parameter is required.** The script exits immediately if none or more than one is supplied.
- **The AD module must be available** for group and user creation steps. If `Get-ADGroup` / `New-ADGroup` are not available, use `-SkipAdGroups` and create the groups manually before running, or install `RSAT-AD-PowerShell`.
- **Access control policies resolve group SIDs at runtime** using `NTAccount.Translate`. The AD groups must exist (created in Step 11 or pre-existing) before the app registration step runs. Use `-SkipAccessControlPolicies` if the groups are not yet available.
- **ADFS service restart is always performed** at the end of the script. Plan for a brief service interruption.
- The script requires PowerShell to be running as Administrator.

---

# Install-ADFS-pfx-Redirects.ps1

Replaces an ADFS self-signed certificate with a PFX-based certificate and migrates all associated hostname references — native app redirect URIs, CORS trusted origins, and Federation Service Properties — from an old domain suffix to the new one encoded in the certificate.

## Requirements

- Must be run **as Administrator** on an ADFS node
- Windows PowerShell with the `ADFS` module available (`Import-Module ADFS`)
- A valid `.pfx` file containing the new certificate and its private key

---

## What It Does

The script performs the following steps in order:

1. **Imports the PFX** into `Cert:\LocalMachine\My` and selects the best leaf certificate (has private key, is not a CA cert).
2. **Grants the ADFS service account** (`NT SERVICE\adfssrv`) read access to the imported private key.
3. **Optionally validates** that a specific DNS name appears in the certificate's SAN or Subject CN (`-ExpectedDnsName`).
4. **Determines the old and new host suffixes** — either from explicit parameters or by auto-detection:
   - **New suffix**: extracted from a wildcard SAN (e.g. `*.newdomain.com`) or inferred as the longest common suffix shared by all explicit SANs.
   - **Old suffix**: read from the existing ADFS CORS trusted origins.
5. **Updates redirect URIs** on all ADFS native client applications.
6. **Updates Federation Service Properties** (DisplayName, HostName, Identifier).
7. **Updates CORS Trusted Origins**.
8. **Binds the new certificate** as the ADFS Service Communications certificate and SSL certificate.
9. **Restarts the ADFS service** and waits up to 60 seconds to confirm it comes back up.

### Hostname Matching: Suffix Swap vs. SAN Label Matching

The script uses two hostname replacement strategies depending on the certificate type:

**Suffix swap** (wildcard cert, e.g. `*.newdomain.com`):
The old hostname prefix is preserved and only the domain suffix is replaced.
```
admin.olddomain.com  →  admin.newdomain.com
```

**SAN label matching** (host-specific cert):
When the certificate contains explicit hostnames rather than a wildcard, the script extracts the service label (first DNS segment) from each old hostname and finds the certificate SAN whose first label contains that service name as a hyphen-delimited segment.

Example — cert SANs: `wids-admin-site01.newdomain.com`, `wids-dvr-site01.newdomain.com`, `wids-auth-adfs-site01.newdomain.com` ...

| Old hostname | Service label | Matched SAN |
|---|---|---|
| `admin.olddomain.com` | `admin` | `wids-admin-site01.newdomain.com` |
| `dvr.olddomain.com` | `dvr` | `wids-dvr-site01.newdomain.com` |
| `device.olddomain.com` | `device` | `wids-device-site01.newdomain.com` |
| `explorer.olddomain.com` | `explorer` | `wids-explorer-site01.newdomain.com` |
| `wti.olddomain.com` | `wti` | `wids-wti-site01.newdomain.com` |
| `adfs.olddomain.com` | `adfs` | `wids-auth-adfs-site01.newdomain.com` |

URI paths and ports are preserved in both cases. If no SAN match is found for a hostname, that URI is skipped with a warning rather than silently dropped.

### Federation Service Properties matching

The three Federation Service Properties are handled differently:

| Property | Strategy |
|---|---|
| `HostName` | SAN label matching — must resolve to a hostname present in the cert |
| `Identifier` | SAN label matching on the URI host component; path is preserved |
| `DisplayName` | Plain suffix swap — human-readable text, not a hostname |

For `HostName`, the service label is extracted and matched against SAN segments. Because ADFS hostnames commonly contain both `adfs` and `auth` as segments (e.g. `wids-auth-adfs-site01`), either label in the old hostname will resolve to the correct SAN.

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

## PFX Password Handling

The script handles password-protected PFX files automatically without requiring the password to be passed upfront.

### Behavior

| Scenario | Result |
|---|---|
| `-PfxPassword` provided, correct | Imports immediately |
| `-PfxPassword` provided, incorrect | Fails with the underlying error from the certificate store |
| No password supplied, PFX is unprotected | Imports immediately |
| No password supplied, PFX is password-protected, interactive mode | Prompts once at runtime; exits cleanly if left blank |
| No password supplied, PFX is password-protected, `-NonInteractive` | Exits with a clear error directing you to use `-PfxPassword` |

### Supplying the password upfront

Pass a `SecureString` via `-PfxPassword`. The recommended way to do this interactively is:

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -PfxPassword (Read-Host "PFX Password" -AsSecureString)
```

For scripted/automated deployments, load the password from a secrets store rather than hardcoding it:

```powershell
$password = ConvertTo-SecureString (Get-Secret -Name "AdfsNewCertPassword") -AsPlainText -Force

.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -PfxPassword $password `
    -NonInteractive
```

---

## SSL Certificate Binding

`Set-AdfsSslCertificate` updates the ADFS configuration store, but the TLS handshake itself is served by **HTTP.SYS** — a kernel-level binding that is managed separately. If that binding is not updated, `openssl s_client` (and any connecting client) will still see the old certificate even though ADFS reports success.

The script handles this in two stages:

**Stage 1 — ADFS cmdlet:**
Calls `Set-AdfsSslCertificate -Thumbprint` and reads back all bindings via `Get-AdfsSslCertificate`, tagging each as `OK` or `STALE`:

```
[OK   ] adfs.newdomain.com:443          ->  <new thumbprint>
[STALE] certauth.adfs.newdomain.com:443 ->  <old thumbprint>
```

**Stage 2 — HTTP.SYS direct update (automatic if Stage 1 has stale entries):**
Before the update, the script snapshots the old ADFS certificate thumbprints from the current bindings. If stale entries remain after Stage 1, it runs `netsh http show sslcert`, finds any binding whose hash matches a known old ADFS thumbprint, and deletes and re-adds it with the new hash. Targeting is limited to the old ADFS thumbprints specifically — IIS or other services sharing the machine are not touched. Both `ipport` (e.g. `0.0.0.0:443`) and `hostnameport` (e.g. `adfs.newdomain.com:443`) binding types are handled. The original `AppId` and certificate store name are preserved.

**Stage 3 — Final cleanup:**
After Stage 2, the script performs one final sweep via `netsh http show sslcert` and deletes any remaining bindings still referencing the old certificate thumbprint. This catches any entry that could not be re-added and ensures no stale binding is left on the system.

After the ADFS service restarts, `openssl s_client` should show the new certificate.

### Private key permissions

A common cause of `Set-AdfsSslCertificate` appearing to succeed but the old certificate remaining in use is that the ADFS service account (`NT SERVICE\adfssrv`) lacks read access to the imported private key. The script grants this permission automatically immediately after the PFX is imported.

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

---

# Invoke-AdfsTroubleshoot.ps1

Troubleshooting script for an ADFS node. Checks service health, certificate expiry, recent event log errors, and Active Directory / ADFS extranet account lockout status. Can list all currently locked AD accounts or target a specific user and unlock them in a single pass.

## Requirements

- Must be run **as Administrator** on an ADFS node
- Windows PowerShell with the `ADFS` module available for ADFS health checks
- The **Active Directory** PowerShell module (`RSAT-AD-PowerShell`) for account lockout operations

Both modules are optional — sections that require a missing module are skipped with a warning.

---

## What It Does

Runs the following checks in order:

1. **ADFS Service** — reports whether `adfssrv` is running.
2. **Certificate Expiry** — checks Token Signing, Token Decryption, Service Communications, and SSL certificates. Highlights anything expiring within `-CertWarnDays` days (default 30) or already expired.
3. **ADFS Configuration** — shows the federation hostname, display name, audit level, and extranet lockout settings. If the audit level is `None`, prints the exact commands to enable auth-failure logging.
4. **Recent Errors and Warnings** — pulls the last `-EventCount` errors and warnings from the `AD FS/Admin` event log and the `Security` log (ADFS Auditing source, if auditing is configured).
5. **Account Lockout** — behavior depends on whether `-Username` is provided:
   - **No `-Username`**: lists every locked AD account with lockout time and bad logon count.
   - **With `-Username`**: shows full status for that account — AD locked/enabled state, bad password count, last bad password attempt, password expiry, last logon — plus ADFS extranet lockout activity if Smart Lockout is enabled.
6. **Unlock** — if the account is locked and `-Unlock` is specified (or the user confirms interactively), the script:
   - Unlocks the AD account via `Unlock-ADAccount`.
   - Resets the ADFS extranet lockout via `Reset-AdfsAccountLockout` (falls back to `Set-AdfsAccountActivity` on older ADFS versions that lack that cmdlet).

---

## Usage

```powershell
.\Invoke-AdfsTroubleshoot.ps1
```

Runs the full ADFS health check and lists all locked AD accounts.

### Check a specific user

```powershell
.\Invoke-AdfsTroubleshoot.ps1 -Username jsmith
```

Shows the user's AD account status and ADFS extranet lockout activity. If the account is locked, prompts to unlock.

### Check and unlock a specific user

```powershell
.\Invoke-AdfsTroubleshoot.ps1 -Username jsmith -Unlock
```

### Non-interactive unlock (scripted / remote use)

```powershell
.\Invoke-AdfsTroubleshoot.ps1 -Username jsmith -Unlock -NonInteractive
```

### Skip the ADFS health checks (AD lockout only)

```powershell
.\Invoke-AdfsTroubleshoot.ps1 -SkipAdfs
```

---

## Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Username` | `string` | No | AD username (SamAccountName or UPN) to check. If omitted, all locked accounts are listed. |
| `-Unlock` | `switch` | No | Unlock the specified user's AD account and reset their ADFS extranet lockout. |
| `-EventCount` | `int` | No | Number of recent error/warning events to retrieve from the event log. Default: `30`. |
| `-CertWarnDays` | `int` | No | Days-remaining threshold for certificate expiry warnings. Default: `30`. |
| `-SkipAdfs` | `switch` | No | Skip all ADFS health checks (service, certs, config, events). Useful when only checking AD account status. |
| `-SkipAd` | `switch` | No | Skip all AD account lockout checks. |
| `-NonInteractive` | `switch` | No | Suppress all confirmation prompts. Unlock proceeds automatically when `-Unlock` is specified. |

---

## Account Lockout: AD vs. ADFS Extranet

The script handles two separate lockout mechanisms:

| Mechanism | What locks the account | How to check | How to reset |
|---|---|---|---|
| **AD Lockout** | Too many bad password attempts reach the Domain Controller | `Get-ADUser … -Properties LockedOut` | `Unlock-ADAccount` |
| **ADFS Extranet Lockout** | Too many bad password attempts from unfamiliar IPs, tracked by ADFS before reaching AD | `Get-AdfsAccountActivity` | `Reset-AdfsAccountLockout` |

A user can be blocked by either or both simultaneously. The `-Unlock` flag resets both in one step.

> **Note:** ADFS deliberately shows a generic "incorrect username or password" message for both wrong passwords and locked accounts to prevent user enumeration. Account lockout can only be confirmed from the server side using this script or ADUC.

---

## Enabling ADFS Auth Failure Logging

By default, ADFS may not log authentication failures to the Security event log. To enable:

```powershell
Set-AdfsProperties -AuditLevel Basic
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
```

After enabling, auth failures will appear in `Event Viewer > Windows Logs > Security` with source `AD FS Auditing`. The troubleshoot script will pick these up automatically.

---

## Important Notes

- The script is read-only except when `-Unlock` is used (or the user confirms an unlock interactively).
- ADFS extranet lockout reset requires ADFS 2016 or later with Smart Lockout enabled (`Set-AdfsProperties -EnableExtranetLockout $true`). The check is silently skipped on older versions or when lockout is disabled.
- The script requires PowerShell to be running as Administrator. It will exit immediately if the privilege check fails.
