# Testing suite

Regression tests for the deployment scripts. Each test loads the shipped functions
from the target script and exercises them directly, so the tests verify the
*actual* shipped logic rather than a copy. Tests auto-locate the target script one
directory up; override with `-ScriptPath` if needed.

## Tests

> `Test-CertScenarios.ps1` and `Test-SiteFeature.ps1` target `Install-ADFS-pfx-Redirects.ps1`; `Test-FromScratch.ps1` targets `Install-ADFS-pfx-From_Scratch.ps1`.

### `Test-FromScratch.ps1` (offline, safe anywhere)
Validates the SAN-resolution helpers in `Install-ADFS-pfx-From_Scratch.ps1` — the
functions that pick the federation service name, the per-app hostnames (redirect
URIs), and the CORS origins from a cert's SANs. Asserts all three resolve correctly
for **wildcard** (`<d>`, `*.<d>`, `*.adfs.<d>`), **flat per-host**, and **dotted
literal** (`auth.adfs.<d>`) certs, including the multi-wildcard rule (a deeper
`*.adfs.<d>` must not splice into app hosts). Makes no changes.

```powershell
cd testing_suite
.\Test-FromScratch.ps1
```

### `Test-CertScenarios.ps1` (offline, safe anywhere)
Drives the SAN-based hostname rewriting against two fixture certificates that
mirror the two conventions seen in the field, starting from a simulated fresh
`bn.internal` deployment. Makes **no** changes and does **not** require a live
ADFS node. It also **reads the fixture PFXs and asserts their SANs match** — via
`Get-PfxData` on Windows (the same path the migration script uses) or `openssl` as
a fallback on macOS/Linux/CI. Only if neither reader is present are those two
cert-read checks skipped (the rewriting logic still runs against the known SAN sets).

```powershell
cd testing_suite
.\Test-CertScenarios.ps1
```

It asserts, per convention: wildcard / common-suffix detection, per-app host
rewriting (`admin`, `dvr`, `device`, `explorer`, `lighthouse`, `wtiapi`, `wti`,
`api`), that `wti` and `wtiapi` never cross-match, federation-host handling, that
the cert covers the federation host, and that `Build-ReplacedRedirectList`
full-replaces old hosts and adds `-Site` variants without double-coding.

### `Test-SiteFeature.ps1` (live, self-restoring)
Applies a `-Site` code to the **live** ADFS redirect URIs and CORS origins, prints
before/after, asserts every app host gains a `<label>-<site>` variant (ADFS host
stays un-coded), then restores the exact prior state in a `finally` block. Run as
Administrator on an ADFS node. Touches no certificates, Federation Service
properties, and does not restart ADFS.

```powershell
cd testing_suite
.\Test-SiteFeature.ps1
```

## Fixture certificates (`certs/`)

Throwaway **self-signed** PFXs (2048-bit RSA, legacy 3DES/SHA1 PKCS#12 so Windows
PowerShell 5.1 / `Get-PfxData` can import them). Fake, RFC-reserved domains
(`.example`, `.test`) so they can never resolve to anything real. **Test data
only - never deploy these.**

Password for both: `Bastille-Test-Pfx!`

| File | Convention | SANs |
|---|---|---|
| `test-flat-oraphys.pfx` | **Flat compound, no wildcard** - every host listed explicitly as `wids-<app>-<site>.<domain>`, federation host *flattened* to `wids-auth-adfs-<site>.<domain>`. (Mirrors the Phosphorus/Building2 style.) | `wids-lab16.oraphys-lab.example`, `wids-admin-lab16...`, `wids-dvr-lab16...`, `wids-device-lab16...`, `wids-explorer-lab16...`, `wids-lighthouse-lab16...`, `wids-wtiapi-lab16...`, `wids-wti-lab16...`, `wids-api-lab16...`, `wids-auth-adfs-lab16...`, plus infra (`wids-elastic/-kafka/-redis-lab16...`) |
| `test-wildcard-acme.pfx` | **Standard wildcard** - base domain, `*.<domain>`, and a dotted federation host `auth.adfs.<domain>`. (Mirrors the `bn.internal` style.) | `acme-secure.test`, `*.acme-secure.test`, `auth.adfs.acme-secure.test` |

### Why these two
They cover the two ways the resolver has to behave:

- **Flat compound** has no wildcard, so app hosts are matched by hyphen-segment
  (`admin` -> `wids-admin-lab16...`), `wtiapi` must not match the `wti` host, and
  the flattened federation host **cannot** be derived from a dotted old host - it
  must be passed via `-TargetAdfsHostname`.
- **Wildcard** matches app hosts via the wildcard fallback (`admin` ->
  `admin.acme-secure.test`) and preserves the dotted federation host structurally
  (`auth.adfs.<old>` -> `auth.adfs.<new>`).

### Regenerating the fixtures
With OpenSSL (legacy flags are required for Windows import):

```bash
PW='Bastille-Test-Pfx!'
SUBJ='/C=US/ST=California/L=San Francisco/O=Bastille Networks, Inc./CN='

# Flat compound (no wildcard)
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes -keyout flat.key -out flat.crt \
  -subj "${SUBJ}wids-lab16.oraphys-lab.example" \
  -addext "subjectAltName=DNS:wids-lab16.oraphys-lab.example,DNS:wids-admin-lab16.oraphys-lab.example,DNS:wids-dvr-lab16.oraphys-lab.example,DNS:wids-device-lab16.oraphys-lab.example,DNS:wids-explorer-lab16.oraphys-lab.example,DNS:wids-lighthouse-lab16.oraphys-lab.example,DNS:wids-wtiapi-lab16.oraphys-lab.example,DNS:wids-wti-lab16.oraphys-lab.example,DNS:wids-api-lab16.oraphys-lab.example,DNS:wids-auth-adfs-lab16.oraphys-lab.example,DNS:wids-elastic-lab16.oraphys-lab.example,DNS:wids-kafka-lab16.oraphys-lab.example,DNS:wids-redis-lab16.oraphys-lab.example"
openssl pkcs12 -export -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -inkey flat.key -in flat.crt -name "wids-lab16.oraphys-lab.example" -out certs/test-flat-oraphys.pfx -passout pass:"$PW"

# Standard wildcard
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes -keyout wild.key -out wild.crt \
  -subj "${SUBJ}acme-secure.test" \
  -addext "subjectAltName=DNS:acme-secure.test,DNS:*.acme-secure.test,DNS:auth.adfs.acme-secure.test"
openssl pkcs12 -export -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -inkey wild.key -in wild.crt -name "acme-secure.test" -out certs/test-wildcard-acme.pfx -passout pass:"$PW"

rm -f flat.key flat.crt wild.key wild.crt
```
