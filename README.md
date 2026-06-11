# ADFS PFX Deployment Scripts

PowerShell scripts for standing up, securing, and maintaining ADFS for the Bastille platform — deploying ADFS with a PFX certificate, migrating that certificate, provisioning role-based access, and troubleshooting.

| Script | One-liner |
|---|---|
| `Install-ADFS-pfx-From_Scratch.ps1` | First-time, end-to-end ADFS stand-up from a PFX certificate. |
| `Install-ADFS-pfx-Redirects.ps1` | Migrate an existing ADFS deployment to a new PFX certificate / domain. |
| `New-BastilleAdUsers.ps1` | Guided RBAC provisioning of the AD + ADFS identity layer. |
| `Invoke-AdfsTroubleshoot.ps1` | ADFS health, certificate, and account-lockout diagnostics. |
| `testing_suite/Test-SiteFeature.ps1` | Self-restoring test of the `-Site` feature (run after changing the migration script). |
| `Show-AdfsConfig.ps1` | Read-only snapshot of the ADFS config (federation props, apps/redirects, CORS, certs, SSL bindings). |

## What each script does

**`Install-ADFS-pfx-From_Scratch.ps1`** — Run **once** on a fresh ADFS node. Installs the ADFS + IIS Windows features, configures the federation farm, imports and binds the PFX certificate (both the ADFS config store and the kernel HTTP.SYS bindings), enables CORS, creates the baseline AD groups and test users, registers every Bastille application group with its OAuth clients / Web APIs / claim rules, and applies per-group access-control policies.

**`Install-ADFS-pfx-Redirects.ps1`** — Run when **rotating or replacing** the ADFS certificate, or moving domains. Imports a new PFX and rewrites every hostname reference — native-app redirect URIs, CORS trusted origins, and Federation Service properties — from the old domain suffix to the new one, rebinds the certificate (config store + HTTP.SYS), and restarts the service.

**`New-BastilleAdUsers.ps1`** — Guided, interactive provisioning of the **identity half** of Bastille RBAC (Active Directory + ADFS). Creates the Bastille OU tree, the role-based security groups (`DVROps`, `DVRViewer`, `ADAMOps`, `ADAMViewer`, `BNAdmin`), sample users, and the ADFS Web API access-control policies; can also add a single user by role (Admin / Operator / Viewer). The **application half** (privileges inside the Fusion Center / ADAM) is completed afterward in the Bastille Tools web app — the script prints step-by-step guidance for it and never contacts those systems. Supports `-ReportOnly`, `-WhatIf`, `-NonInteractive`, and `-Help`.

**`Invoke-AdfsTroubleshoot.ps1`** — Day-to-day, read-only diagnostics for an ADFS node: service status, certificate expiry, recent event-log errors, and AD / ADFS extranet account-lockout state. Can list all locked accounts, or target one user and unlock them (both AD and ADFS) in a single pass.

**`testing_suite/Test-SiteFeature.ps1`** — A regression test for `Install-ADFS-pfx-Redirects.ps1`'s `-Site` feature, meant to run after changes to that script. It loads the shipped functions, applies a `-Site` code (default `sitetest`) to the live ADFS redirect URIs and CORS origins, prints before/after, runs PASS/FAIL assertions (every app host gains a `<label>-<site>` variant; the ADFS host stays un-coded), then restores the exact pre-existing state in a `finally` block. Run as Administrator on an ADFS node from the `testing_suite` directory: `.\Test-SiteFeature.ps1` (it auto-locates the migration script one directory up). It does not touch certificates, Federation Service properties, or restart ADFS.

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
| Bastille ADAM API | `bastille-adam-api` | `wtiapi` | Bastille Admins |

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
- `https://<wtiapi-host>/authenticated`
- `https://<wtiapi-host>/signin-callback`
- `https://<wtiapi-host>/signout-callback`

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
| `wtiapi` | `wids-wtiapi-site01.newdomain.com` |

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
5. **Prompts for (or accepts) the target ADFS hostname** — the FQDN the Federation Service will use after migration. Validated against the certificate SANs. Supply via `-TargetAdfsHostname` to skip the prompt.
6. **Updates redirect URIs** on all ADFS native client applications.
7. **Updates Federation Service Properties** (DisplayName, HostName, Identifier).
8. **Resolves, lets you edit, and applies CORS Trusted Origins** — freshly resolves the full origin list from: the ADFS host (first); cert SANs matched by service label (`admin`, `dvr`, `device`, `explorer`, `lighthouse`, `wtiapi`, `wti`) for host-specific certs; the redirect URIs of all registered native apps (covers wildcard-cert deployments); `-Site` variants; and any `-CorsExtraOrigins`. This is a **clean replace** — the trusted-origin set becomes *exactly* this resolved list, so old/stale origins (and anything not re-derived) are removed. The list is shown in an **interactive editor** (unless `-NonInteractive`) where you can `add <url>`, `rm <n>`, apply (`y`), or skip (`n`), then written as a single string array via `Set-AdfsResponseHeaders -EnableCORS $true` in one call.
9. **Binds the new certificate** as the ADFS Service Communications certificate and SSL certificate.
10. **Restarts the ADFS service** and waits up to 60 seconds to confirm it comes back up.

### Hostname Matching: Suffix Swap vs. SAN Label Matching

The script uses two hostname replacement strategies depending on the certificate type:

**Suffix swap** (wildcard cert, e.g. `*.newdomain.com`):
The old hostname prefix is preserved and only the domain suffix is replaced.
```
admin.olddomain.com  →  admin.newdomain.com
```

**SAN label matching** (host-specific cert):
When the certificate contains explicit hostnames rather than a wildcard, the script takes the old hostname's labels above the old suffix and matches a certificate SAN in priority order:

1. **Structure-preserving (preferred):** a SAN that keeps the **exact subdomain prefix**, with only the domain suffix changed. The original form — including any dots — is preserved. This handles the ADFS host `wids-auth.adfs-abl15.<old>` → `wids-auth.adfs-abl15.<new>` (the dot stays a dot), and a host already on the target naming `wids-admin-abl15.<old>` → `wids-admin-abl15.<new>` (cert rotation / domain-only change).
2. **Flat exact match:** the prefix collapsed to a single hyphen-joined label equals a SAN's first label (`wids-auth.adfs-abl15` → flat SAN `wids-auth-adfs-abl15`). Only used when no structure-preserving SAN exists.
3. **Segment match:** the collapsed label appears as a hyphen-delimited segment of a SAN's first label — for short service names (`admin` → `wids-admin-abl15`). The shortest matching first label wins.

Example — cert SANs: `wids-admin-site01.newdomain.com`, `wids-dvr-site01.newdomain.com`, `wids-auth.adfs-site01.newdomain.com` ...

| Old hostname | Matched via | Matched SAN |
|---|---|---|
| `admin.olddomain.com` | segment (`admin`) | `wids-admin-site01.newdomain.com` |
| `dvr.olddomain.com` | segment (`dvr`) | `wids-dvr-site01.newdomain.com` |
| `device.olddomain.com` | segment (`device`) | `wids-device-site01.newdomain.com` |
| `wids-admin-site01.olddomain.com` | structure-preserving | `wids-admin-site01.newdomain.com` |
| `wids-auth.adfs-site01.olddomain.com` | structure-preserving (dot kept) | `wids-auth.adfs-site01.newdomain.com` |

URI paths and ports are preserved in both cases. If no SAN match is found for a hostname — for example an old host whose site code differs from every SAN (`…-abl14` when the cert only covers `…-abl15`) — that URI is skipped with a warning rather than silently dropped, since no correct target exists in the certificate.

### Federation Service Properties and CORS: Explicit vs. Heuristic Mode

How `HostName`, `Identifier`, and CORS origins are resolved depends on whether `-TargetAdfsHostname` is provided.

**Explicit hostname mode** (`-TargetAdfsHostname` supplied or entered interactively):

| Property | How it is set |
|---|---|
| `HostName` | Set directly to the provided FQDN |
| `Identifier` | Existing URI host component replaced with the provided FQDN; scheme, path, and query preserved |
| `DisplayName` | Plain suffix swap (human-readable text) |
| CORS origins | Clean replace with the freshly-resolved set: ADFS host + app hosts from cert SANs (by service label) and native app redirect URIs (wildcard-cert fallback) + `-Site` variants + any `-CorsExtraOrigins`; shown in an interactive editor (`add`/`rm`/`y`/`n`), then applied as a single string array in one call |

**Heuristic mode** (no `-TargetAdfsHostname`, cert has explicit SANs):

| Property | Strategy |
|---|---|
| `HostName` | SAN label matching — must resolve to a hostname present in the cert |
| `Identifier` | SAN label matching on the URI host component; path is preserved |
| `DisplayName` | Plain suffix swap |
| CORS origins | Clean replace with the freshly-resolved set (existing migrated via SAN label matching + discovery); shown in the interactive editor (`add`/`rm`/`y`/`n`) before applying |

Explicit hostname mode is preferred when the ADFS service hostname is known — it is unambiguous and does not depend on heuristic matching.

---

## Usage

```powershell
.\Install-ADFS-pfx-Redirects.ps1 -PfxPath "C:\Temp\adfs-cert.pfx"
```

The script will auto-detect the old and new host suffixes, prompt for the target ADFS hostname (validated against the certificate SANs), and confirm at each step.

### With an explicit target ADFS hostname

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -TargetAdfsHostname "wids-auth-adfs-abl17.newdomain.com"
```

Skips the interactive FQDN prompt and sets the Federation Service HostName, Identifier, and CORS origin directly from the provided value.

### Also register site-coded app hosts (`-Site`)

```powershell
.\Install-ADFS-pfx-Redirects.ps1 `
    -PfxPath "C:\Temp\adfs-cert.pfx" `
    -TargetAdfsHostname "auth.adfs.bn-wids.internal" `
    -Site "home"
```

Pass the **base** ADFS host (`auth.adfs.bn-wids.internal`). With `-Site home` the script registers the `admin-home`, `dvr-home`, … app variants (redirect URIs **and** CORS origins) **and** site-codes the federation host itself to `auth-home.adfs.bn-wids.internal` (HostName / Identifier / DisplayName + its CORS origin). Omit `-Site` to be prompted (blank = none).

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
    -TargetAdfsHostname "wids-auth-adfs-abl17.newdomain.com" `
    -NonInteractive
```

`-TargetAdfsHostname` is required in non-interactive mode — the script will exit with an error if it is omitted.

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
| `-TargetAdfsHostname` | `string` | No | The exact FQDN the ADFS service will use after migration (e.g. `wids-auth-adfs-abl17.newdomain.com`). Prompted interactively if omitted. Required when `-NonInteractive` is set. |
| `-ExpectedDnsName` | `string` | No | A specific DNS name that must appear in the certificate SAN or Subject CN. The script warns and prompts if it is absent. |
| `-Site` | `string` | No | Site code. For every migrated app host, also registers a `<first-label>-<site>` variant (e.g. `admin` → `admin-<site>`) as **both** a redirect URI and a CORS origin, alongside the base host. The **ADFS/federation host is also site-coded** (`auth.adfs` → `auth-<site>.adfs`) — because it's a single host, that **replaces** HostName/Identifier/DisplayName + its CORS origin (pass the base host via `-TargetAdfsHostname`). Prompted interactively if omitted; blank = none. |
| `-CorsExtraOrigins` | `string` | No | Comma-separated list of additional origins to add to CORS trusted origins (merged with migrated origins). |
| `-NoExportable` | `switch` | No | Import the certificate as non-exportable. Exportable by default. |
| `-SkipServiceCommunications` | `switch` | No | Skip binding the new cert as the Service Communications certificate. |
| `-SkipAdfsSsl` | `switch` | No | Skip binding the new cert as the ADFS SSL certificate. |
| `-SkipCors` | `switch` | No | Skip updating CORS trusted origins. |
| `-SkipFederationServiceProperties` | `switch` | No | Skip updating Federation Service Properties (HostName, DisplayName, Identifier). |
| `-EnableUpdatePassword` | `switch` | No | Enable the ADFS update-password portal endpoint (`/adfs/portal/updatepassword/`) so users can change their own password — pairs with `New-BastilleAdUsers.ps1 -ForcePasswordChange`. |
| `-TokenCertificateDuration` | `int` | No | Set the token-signing/decryption certificate duration in days via `Set-AdfsProperties -CertificateDuration` (e.g. `1825` = 5 years). Applies to the **next** generated token certs. `0`/omitted = leave unchanged. |
| `-RolloverTokenCerts` | `switch` | No | **Disruptive, opt-in.** Immediately regenerate the token-signing/decryption certs (`Update-AdfsCertificate -Urgent`) so a new duration takes effect now. Every relying party must re-consume ADFS metadata afterward. Warns and confirms first. |
| `-Version` / `-v` | `switch` | No | Print the script version and exit (no Administrator or `-PfxPath` needed). |
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

**Stage 4 — Previous-host cleanup (hostname-only changes):**
The thumbprint sweeps above only catch bindings on the *old certificate*. When the **federation hostname** changes but the cert does **not** (for example `-Site` coding `auth.adfs` → `auth-<site>.adfs` on the same cert), the old host's binding sits on the current thumbprint and would otherwise linger. The script records the federation hostname before changing it and, if it changed (and Federation Service Properties were updated), removes the previous host's `:443`/`:49443` bindings.

After the ADFS service restarts, `openssl s_client` should show the new certificate.

### Private key permissions

A common cause of `Set-AdfsSslCertificate` appearing to succeed but the old certificate remaining in use is that the ADFS service account (`NT SERVICE\adfssrv`) lacks read access to the imported private key. The script grants this permission automatically immediately after the PFX is imported.

---

## Auto-Detection Behavior

### New host suffix

1. Checks for a wildcard SAN (e.g. `*.newdomain.com` → `newdomain.com`). If the cert has **several wildcards** (e.g. `*.newdomain.com` and `*.adfs.newdomain.com`), the **shortest (base) domain wins** — so app hosts migrate to `app.newdomain.com`, not `app.adfs.newdomain.com`. The deeper `*.adfs.*` level is used for the ADFS host via `-TargetAdfsHostname`.
2. If no wildcard exists, finds the longest domain suffix shared by **all** SANs (e.g. every explicit SAN ends in `.newdomain.com`).
3. Fails with an error if neither approach yields a result — provide `-NewHostSuffix` explicitly.

### Old host suffix

Reads the existing ADFS CORS trusted origins and extracts the domain suffix from the first well-formed origin. Fails if none are found — provide `-OldHostSuffix` explicitly.

---

## Important Notes

- **The redirect URI set is replaced, not merged.** Each native app's redirect URIs are set to exactly the migrated list. Any existing URI that does not match the old suffix is not carried over. Review current registrations before running.
- **CORS origins are a clean replace.** The trusted-origin set becomes *exactly* the freshly-resolved list (ADFS host + app hosts from SANs/redirect-URI discovery + `-Site` variants + `-CorsExtraOrigins`); existing origins are not merged back, so old/stale ones are removed. The list is shown in an interactive editor (`add <url>`, `rm <n>`, `y`/`n`) before being written; under `-NonInteractive` it is applied as-is. Add anything not auto-resolved via `-CorsExtraOrigins` or the editor.
- **Redirect URIs are also a full replace** (per app): old-suffix hosts are migrated and the result overwrites the set, so old-domain redirects are dropped. Note: on a wildcard cert the script can't distinguish a *prior* `-Site` host (e.g. `admin-home`) from a base host, so switching site codes across runs may leave the previous site's redirect hosts — same-site re-runs and domain migrations stay clean.
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

---

# New-BastilleAdUsers.ps1

Provisions the Bastille Active Directory structure — organizational units, role-based security groups, and sample user accounts — then binds the Bastille ADFS Web API applications to those groups using "Permit specific group" access control policies.

This script implements a finer-grained, per-product RBAC model (admin / operator / viewer) and is distinct from the simpler `Bastille Admins` / `Bastille Users` scheme created by `Install-ADFS-pfx-From_Scratch.ps1`.

## Requirements

- Must be run **as Administrator** on a **domain controller** (or a host with both modules available) — the script enforces the privilege check and exits if it fails
- The **Active Directory** PowerShell module (`RSAT-AD-PowerShell`) — for OU, group, and user creation (required; the script exits if absent)
- The **ADFS** module — for the `Set-AdfsWebApiApplication` access control steps (optional; the ADFS step is skipped with a warning if the module is unavailable)
- The three target ADFS Web API applications must already be registered (see [Prerequisites and dependencies](#prerequisites-and-dependencies))

---

## What It Does

> **Scope:** This script sets up the **identity half** of Bastille RBAC — Active Directory and ADFS. The **application half** (granting each role its privileges inside the Fusion Center / ADAM) is done afterward in the **Bastille Tools web app** (`bastille-tool.html`, "RBAC Manager" tab). The script does **not** contact the Fusion Center or ADAM; after a restructure it prints step-by-step guidance for that follow-up. The AD group names it creates (`DVROps`, `DVRViewer`, `ADAMOps`, `ADAMViewer`, `BNAdmin`) match the web tool's personas on purpose, so the ADFS role claims line up.

The script is **interactive by default** and starts by asking which of two operations to run:

| Mode | What it does |
|---|---|
| **RBAC restructuring** (`-Mode Restructure`) | Creates/verifies the full OU tree, security groups, sample users, and ADFS Web API access-control policies. This is the original behavior. |
| **Add a user** (`-Mode AddUser`) | Adds a single user to an **already-built** structure — prompts for the person's details and a role (Admin / Operator / Viewer), creates them in the matching OU, and adds them to that role's groups. No OUs/groups/policies are changed. |

In both modes it prints the current state, walks you through the choices with the standard behavior shown as the `[default]` for each prompt (**Enter accepts, typed input overrides**), shows a plan, and confirms before making any change. Pass **`-NonInteractive`** to accept all defaults with no prompts (automation), or **`-ReportOnly`** to print the current state and exit.

In **RBAC restructuring** you can change, per run: the base OU name, the list of security groups, the admin account added to `BNAdmin` (or skip it), whether to create the sample users (and their password), and whether to apply the ADFS policies. The sample-user details, the ADFS app→group mappings, and the role definitions live in editable arrays (`$SampleUsers`, `$AppPolicies`, `$Roles`) at the top of the script.

The script is **idempotent** — every object is checked before creation and skipped if it already exists, so it is safe to re-run — and **additive**: it never removes a user from a group or deletes a renamed/removed object, so it will not reconcile drift. It is also **resilient**: each change is attempted independently, and any failures are collected and reported in a summary at the end rather than aborting the run.

It prints a **"current state" report before making any changes and a "final state" report after**, listing the Bastille OUs, each group and its members, each user with its OU and group memberships, and the ADFS Web API access control policies — so it is easy to see exactly what existed and what changed. It supports the standard **`-WhatIf`** / **`-Confirm`** parameters (preview or confirm each change), and writes a **transcript log** of each run (see `-LogPath`).

1. **Reads the domain context** — `$DomainDN` (distinguished name) and `$DomainForest` (forest root DNS name) from `Get-ADDomain`.
2. **Creates the OU tree:**
   ```
   OU=Bastille,<DomainDN>
   ├─ OU=Groups
   └─ OU=Users
      ├─ OU=Admins
      ├─ OU=Operators
      └─ OU=Viewers
   ```
3. **Creates five global security groups** in `OU=Groups,OU=Bastille`: `BNAdmin`, `DVROps`, `DVRViewer`, `ADAMOps`, `ADAMViewer`.
4. **Adds the existing `BN Test` account** to `BNAdmin` (matched by display name, so it works whether the SAM account is `bntest` or `BN Test`; warns and continues if absent) and **moves it into the `Admins` OU** for tidiness. The OU move is cosmetic — ADFS access is governed by group membership, not OU placement.
5. **Creates two enabled user accounts** (skippable with `-SkipUsers`) with explicit SAM account names and non-expiring passwords (controllable via `-PasswordNeverExpires`):
   - `BN Viewer` — SAM `bn-viewer`, UPN `bn-viewer@<forest>`, in `OU=Viewers`
   - `BN Ops` — SAM `bn-ops`, UPN `bn-ops@<forest>`, in `OU=Operators`
6. **Assigns group memberships:**
   - `bn-viewer` → `DVRViewer`, `ADAMViewer`
   - `bn-ops` → `DVROps`, `ADAMOps`
7. **Binds three ADFS Web API applications** to "Permit specific group" policies, resolving each group to its **SID** first (skippable with `-SkipAdfs`). Apps that are not registered under the expected name are skipped with a warning.

### Groups and roles

| Group | Scope | Members (as assigned here) |
|---|---|---|
| `BNAdmin` | Global | `BN Test` (must pre-exist) |
| `DVROps` | Global | `bn-ops` |
| `DVRViewer` | Global | `bn-viewer` |
| `ADAMOps` | Global | `bn-ops` |
| `ADAMViewer` | Global | `bn-viewer` |

### ADFS application access control

| Web API `TargetName` | Permitted groups |
|---|---|
| `Bastille Admin - Web application` | `BNAdmin` |
| `Bastille DVR and Device - Web application` | `BNAdmin`, `DVROps`, `DVRViewer` |
| `Bastille Lighthouse - Web application` | `BNAdmin`, `ADAMOps`, `ADAMViewer` |

---

## Usage

Run from an elevated prompt on a domain controller. With no parameters it runs the **interactive interview** — Enter accepts each default, and it confirms a plan before making changes:

```powershell
.\New-BastilleAdUsers.ps1
```

### Show usage help

```powershell
.\New-BastilleAdUsers.ps1 -Help
```

### Inventory the current state without changing anything (dry run)

```powershell
.\New-BastilleAdUsers.ps1 -ReportOnly
```

### Accept all defaults with no prompts (automation)

```powershell
.\New-BastilleAdUsers.ps1 -NonInteractive
```

### Preview the whole restructuring without making changes

```powershell
.\New-BastilleAdUsers.ps1 -NonInteractive -WhatIf
```

### Add a single user to the existing structure (interactive)

```powershell
.\New-BastilleAdUsers.ps1 -Mode AddUser
```

Prompts for the name, account details, and a role (Admin / Operator / Viewer), then creates the user in the matching OU and adds them to that role's groups.

### Add a user non-interactively (automation)

```powershell
.\New-BastilleAdUsers.ps1 -Mode AddUser -NonInteractive `
    -NewUserName "Jane Smith" -NewUserRole Operator
```

`SamAccountName`, `UPN`, given/surname are derived from the name if not supplied; `-NewUserGroups` overrides the role's default groups.

### Add a user who must change their password at next logon

```powershell
.\New-BastilleAdUsers.ps1 -Mode AddUser -NonInteractive `
    -NewUserName "Jane Smith" -NewUserRole Operator -ForcePasswordChange
```

Also works on an **existing** account — running AddUser for a SAM that already exists with `-ForcePasswordChange` just flags it to change at next logon (and clears `PasswordNeverExpires`).

### Supply the sample-user password securely (instead of the default)

```powershell
.\New-BastilleAdUsers.ps1 -UserPassword (Read-Host "Sample user password" -AsSecureString)
```

### Create the AD objects only, without touching ADFS

```powershell
.\New-BastilleAdUsers.ps1 -SkipAdfs
```

### Bind ADFS policies against pre-existing groups, without creating sample users

```powershell
.\New-BastilleAdUsers.ps1 -SkipUsers
```

---

## Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Help` | `switch` | No | Show usage help and exit. Works without Administrator rights or the AD/ADFS modules. |
| `-BaseOuName` | `string` | No | Name of the base OU under the domain root. Default: `Bastille`. Used by all modes and by `-ReportOnly`. |
| `-UserPassword` | `string` or `SecureString` | No | Password for created users. Accepts a `SecureString` (recommended) or a plain string. Seeds the password used when prompted; applied as-is under `-NonInteractive`. Defaults to the historical lab value if omitted. |
| `-PasswordNeverExpires` | `bool` | No | Whether created accounts have non-expiring passwords. Default: `$true` (lab convenience). Use `-PasswordNeverExpires:$false` to honor the domain password policy. |
| `-ForcePasswordChange` | `switch` | No | Require the user to change their password at next logon. Applies to created users and also flags an existing account. Forces `PasswordNeverExpires` off (AD does not allow both). Prompted interactively in both modes; the switch sets the default. |
| `-SkipUsers` | `switch` | No | Seed the "create sample users?" prompt default to **No** (and skip them outright under `-NonInteractive`). |
| `-SkipAdfs` | `switch` | No | Seed the "apply ADFS policies?" prompt default to **No** (and skip the step outright under `-NonInteractive`). |
| `-NonInteractive` | `switch` | No | Accept all defaults with no prompts. Use for scripted/automated runs. |
| `-ReportOnly` | `switch` | No | Print the current Bastille AD/ADFS state and exit without making any changes. |
| `-Mode` | `string` | No | `Restructure` (full structure + ADFS policies) or `AddUser` (add one user to the existing structure). Prompted at startup if omitted; defaults to `Restructure` under `-NonInteractive`. |
| `-NewUserName` | `string` | No | *(AddUser)* Full display name of the user to add, e.g. `"Jane Smith"`. Required for AddUser under `-NonInteractive`. |
| `-NewUserGivenName` | `string` | No | *(AddUser)* First name. Derived from `-NewUserName` if omitted. |
| `-NewUserSurname` | `string` | No | *(AddUser)* Last name. Derived from `-NewUserName` if omitted. |
| `-NewUserSam` | `string` | No | *(AddUser)* SAM account name. Derived from the name (spaces → hyphens, lowercased) if omitted. |
| `-NewUserUpn` | `string` | No | *(AddUser)* UPN. Defaults to `<sam>@<forest>` if omitted. |
| `-NewUserRole` | `string` | No | *(AddUser)* `Admin`, `Operator`, or `Viewer` — sets the target OU and default groups. Required for AddUser under `-NonInteractive`. |
| `-NewUserGroups` | `string[]` | No | *(AddUser)* Override the role's default group list. |
| `-LogPath` | `string` | No | Transcript log file path. Defaults to a timestamped file beside the script. Skipped under `-WhatIf`. |
| `-WhatIf` / `-Confirm` | `switch` | No | Standard PowerShell risk-mitigation parameters. `-WhatIf` previews every change without making it; `-Confirm` prompts before each one. |

---

## Prerequisites and dependencies

- **`bntest` must already exist.** The script adds `bntest` to `BNAdmin` but does not create it — that account is created by `Install-ADFS-pfx-From_Scratch.ps1 -CreateTestUsers`. If it is absent, the membership step warns and continues; the rest of the script is unaffected.
- **The three Web API applications must already be registered** in ADFS under the exact `TargetName` values above. Note the `" - Web application"` suffix — this matches application groups created through the **ADFS management console wizard** (web-application template). It does **not** match the `" - Web API"` names that `Install-ADFS-pfx-From_Scratch.ps1` registers, nor does `Bastille Lighthouse` correspond to any application group created by that script (which registers `Bastille ADAM` and `Bastille ADAM API`). The script checks each application by name and skips any it cannot find with a warning — confirm the targets exist under these names before relying on the binding.

---

## Important Notes

- **Idempotent, additive, and resilient.** Objects are checked before creation, so re-running does not throw "already exists" errors. The script never removes memberships or deletes objects (no drift reconciliation). Individual failures are collected and printed in an end-of-run summary instead of aborting the run.
- **Dry-run and audit.** Use `-ReportOnly` (state only) or `-WhatIf` (preview every change) before a real run. Each real run writes a transcript log (`-LogPath`, default a timestamped file beside the script).
- **Default password is a lab value.** If `-UserPassword` is omitted, accounts use a built-in default; passwords are non-expiring unless you pass `-PasswordNeverExpires:$false`. Pass a `SecureString` via `-UserPassword` for anything beyond a throwaway lab, and change it after first logon.
- **Access groups are bound by SID.** The script resolves each group name to its SID and applies the `"Permit specific group"` policy as `@{ GroupParameter = $sids }` — the form ADFS expects — mirroring `Install-ADFS-pfx-From_Scratch.ps1`.
- **The `Admins` OU** holds the `BN Test` admin account, which the script moves there once it exists (and adds to `BNAdmin`). If `BN Test` is absent, the OU is left empty for manual admin-account placement.
- **UPNs use the forest root DNS name** (`@<forest>`). In a multi-domain forest, or where a custom UPN suffix is in use, edit the `-UserPrincipalName` values in the script to the intended suffix.
