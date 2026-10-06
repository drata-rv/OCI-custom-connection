# OCI-to-Drata Custom Connection

Read-only OCI configuration-evidence collector. Upserts records into a Drata Custom Connection.

## Contents

1. [Setup](#1-setup)
2. [Configuration](#2-configuration)
3. [Secrets](#3-secrets)
4. [OCI IAM policy](#4-oci-iam-policy)
5. [Run](#5-run)
6. [Validate output](#6-validate-output)
7. [Troubleshooting](#7-troubleshooting)
8. [Deployment checklist](#8-deployment-checklist)
9. [Custom Tests](#9-custom-tests)

## 1. Setup

Requires Python 3.12+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Pinned install (reproducible, matches `requirements-lock.txt`):

```bash
pip install -r requirements-lock.txt
pip install -e . --no-deps
```

## 2. Configuration

```bash
cp config.example.yaml config.yaml
```

`config.yaml` is git-ignored. Never commit it once it has real `connectionId`/`resourceId`/`expectedTenancyOcid` values. Field reference: [config.example.yaml](config.example.yaml).

Required before first run:

- `oci.expectedTenancyOcid` — the OCI tenancy OCID.
- `oci.regions.allow` — regions to scan.
- `oci.compartments.roots` — `["tenancy"]` or specific compartment OCIDs.
- `drata.connectionId` / `drata.resourceId` — the Drata Custom Connection's IDs.
- `drata.apiTokenSecretRef` — see §3.

One record per collected resource, upserted to the Custom Connection resource registered
with `src/oci_drata/schemas/flat-record.schema.json` (`drata.resourceId`). Records carry raw OCI facts
only, no precomputed compliance verdict -- the Drata Custom Test evaluates compliance
against these facts.

`oci.services.*` toggles control which evidence gets collected:

| `evidenceType` | `oci.services` toggle | Default |
|---|---|---|
| `instance` | `compute` + `networkExposure` | on |
| `boot_volume`, `block_volume` | `blockStorage` | on |
| `db_system`, `database` | `baseDatabase` | on |
| `autonomous_database` | `autonomousDatabase` | on |
| `ipsec_connection` | `siteToSiteVpn` | on |
| `iam_user`, `api_key`, `iam_policy` | `identity` | off |
| `bucket` | `objectStorage` | off |
| `cloud_guard_configuration` | `cloudGuard` | off |
| `monitoring_alarm` | `monitoring` | off |
| `load_balancer`, `load_balancer_backend_set` | `loadBalancer` | off |
| `waf` | `waf` | off |
| `kms_key` | `kmsVault` | off |

A domain that fails to collect completely in a given run withholds only the evidenceTypes
that depend on it (`instance` needs both `compute` and `networking`; everything else needs
just its own domain) -- see `collection-report.json`'s `domainsWithheld`. It never blocks
delivery for domains that succeeded.

**Before the first real run:** run with `--test` (§5), then check `collection-report.json`'s `accessSummary.compartmentsWithAuthGap`. Set `compartments.roots` to match what the OCI policy in §4 actually grants.

## 3. Secrets

**OCI private key** — the file `oci.authentication.configFile` → `key_file` points at:

```bash
chmod 600 /path/to/oci_api_key.pem
```

**Drata API token** — set via `drata.apiTokenSecretRef`, never inline in `config.yaml`:

```yaml
apiTokenSecretRef:
  provider: env   # or: provider: file, path: /run/secrets/drata_api_token
  name: DRATA_API_TOKEN
```

```bash
export DRATA_API_TOKEN="$(cat /path/to/token)"
# file provider:
install -m 600 /path/to/token /run/secrets/drata_api_token
```

Non-secret runtime overrides: `OCI_DRATA__` env prefix, e.g. `OCI_DRATA__OCI__REGIONS__ALLOW=us-ashburn-1,eu-frankfurt-1`.

## 4. OCI IAM policy

Validate against Oracle's current [Core Services IAM policy reference](https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/corepolicyreference.htm) before granting in production.

Create a dedicated group and API-signing user, then:

```text
Allow group oci-drata-collector to inspect tenancies in tenancy
Allow group oci-drata-collector to inspect compartments in tenancy
Allow group oci-drata-collector to inspect instance-family in tenancy
Allow group oci-drata-collector to read instance-family in tenancy
Allow group oci-drata-collector to inspect virtual-network-family in tenancy
Allow group oci-drata-collector to read virtual-network-family in tenancy
Allow group oci-drata-collector to use network-security-groups in tenancy
Allow group oci-drata-collector to inspect volume-family in tenancy
Allow group oci-drata-collector to read volume-family in tenancy
Allow group oci-drata-collector to inspect database-family in tenancy
Allow group oci-drata-collector to read database-family in tenancy
Allow group oci-drata-collector to inspect autonomous-database-family in tenancy
Allow group oci-drata-collector to read autonomous-database-family in tenancy
```

`virtual-network-family` above (already required for `networkExposure`) also covers IPSec
connections/tunnels -- Site-to-Site VPN (`siteToSiteVpn`) needs no separate grant.

Never grant `manage`, `all-resources`, any secret-family/Vault secret-content permission, or any IPSec shared-secret permission.

Optional grants, one block per `oci.services.*` toggle enabled in `config.yaml`:

**`identity`**
```text
Allow group oci-drata-collector to inspect users in tenancy
Allow group oci-drata-collector to read users in tenancy
Allow group oci-drata-collector to inspect policies in tenancy
Allow group oci-drata-collector to read policies in tenancy
```

**`objectStorage`**
```text
Allow group oci-drata-collector to inspect buckets in tenancy
Allow group oci-drata-collector to read buckets in tenancy
```

**`cloudGuard`**
```text
Allow group oci-drata-collector to inspect cloud-guard-config in tenancy
Allow group oci-drata-collector to read cloud-guard-config in tenancy
```

**`monitoring`**
```text
Allow group oci-drata-collector to inspect alarms in tenancy
Allow group oci-drata-collector to read alarms in tenancy
```

**`loadBalancer`**
```text
Allow group oci-drata-collector to inspect load-balancers in tenancy
Allow group oci-drata-collector to read load-balancers in tenancy
```

**`waf`**
```text
Allow group oci-drata-collector to inspect web-app-firewalls in tenancy
Allow group oci-drata-collector to read web-app-firewalls in tenancy
```

**`kmsVault`**
```text
Allow group oci-drata-collector to inspect vaults in tenancy
Allow group oci-drata-collector to read vaults in tenancy
Allow group oci-drata-collector to inspect keys in tenancy
Allow group oci-drata-collector to read keys in tenancy
```

## 5. Run

```bash
# Dry run: never contacts Drata. Every run writes out/flat-records.json + out/collection-report.json.
oci-drata --config config.yaml --dry-run

# Live run.
oci-drata --config config.yaml

# Sample mode: stops after 30s instead of scanning the whole tenancy. Records still
# upload (each is standalone evidence, honest at any sample size); stale-record cleanup
# is skipped, since a sampled run's absences aren't confirmed deletions.
oci-drata --config config.yaml --test
```

`runtime.dryRun` in `config.yaml` sets the default; `--dry-run` on the command line always wins.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Success — uploaded (in full or in part; see `domainsWithheld`), or a dry run |
| `1` | Blocked — nothing uploaded. Check `collection-report.json`: `blockedReasons`, or `deliveryErrorClasses` for a failed Drata call |
| `2` | Configuration/auth error |
| `3` | Unexpected failure |

## 6. Validate output

```bash
python3 -c "
import json
from oci_drata.validation.schema import load_flat_schema, validate_record
records = json.load(open('out/flat-records.json'))
for record in records:
    result = validate_record(record, load_flat_schema())
    if not result.valid:
        print(record['id'], result.errors)
"
```

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `configuration error: ... field name suggests a credential` | Move the literal secret in `config.yaml` to a `secretRef` (env var or mounted file). |
| `configuration error: ... expected true or false (unquoted), got ...` | Remove quotes around a boolean field (e.g. `compute: "false"` → `compute: false`). |
| `configuration error: ... must be >= 1, got 0` | Replace the placeholder `0` in `drata.connectionId`/`resourceId` with the real IDs. |
| `configuration error: ... is not a valid CIDR` | Fix the malformed entry in `decisions.publicSourceCidrs`. |
| `configuration error: drata.baseUrl ...` | `drata.baseUrl` must be `https`, no embedded credentials/query/fragment, hostname `public-api.drata.com` (or set `drata.allowAlternateHost: true`). |
| `configuration error: $: unrecognized field(s) ...` | Check spelling against `config.example.yaml`. |
| `AuthError: OCI private key file must not be group/world accessible` | `chmod 600` the key file. |
| `AuthError: OCI SDK config tenancy does not match configured oci.expectedTenancyOcid` | Point `~/.oci/config`'s profile at the tenancy `config.yaml` expects, or fix `expectedTenancyOcid`. |
| `domainsWithheld` includes a domain, reasons mention `not subscribed/READY` | Remove the unsubscribed region from `oci.regions.allow`. |
| `domainsWithheld` includes a domain | Check `collection-report.json`'s operations for `status: failed` and `errorCode` in that domain. Usually a missing policy grant (§4). |
| Large `operationsFailed` count, mostly `NotAuthorizedOrNotFound` | Check `accessSummary` in `collection-report.json`. Narrow `compartments.roots` to `compartmentsWithRealData`. |
| `uploadDecision: blocked` | Check `blockedReasons` in `collection-report.json` -- usually discovery incomplete, or every enabled domain withheld. |
| `schemaValid: false` | Check `collection-report.json`'s `schemaInvalidCount`; validate `out/flat-records.json` per §6 to see which records and why. |
| Drata upload returns `error_class: auth` | Check the bearer token and `connectionId`/`resourceId`. |
| Drata upload returns `error_class: validation` | Check the connection's registered schema matches `src/oci_drata/schemas/flat-record.schema.json`. |
| `staleRecordDeleteFailures > 0` in `collection-report.json` | Best-effort cleanup of terminated/deleted resources' old records; a failure here doesn't block the run and is retried next run. |

## 8. Deployment checklist

- [ ] API-signing user authenticates; policy in §4 grants no mutation permission.
- [ ] Collector verifies tenancy and every configured region.
- [ ] Approved compartments fully enumerated (`accessSummary.compartmentsSeen` in `collection-report.json` matches the OCI Console).
- [ ] Enabled services show zero `failed` operations in `collection-report.json`.
- [ ] Resource counts reconcile against the OCI Console for a sample of compartments.
- [ ] `out/flat-records.json` validates against the Drata connection's actual schema.
- [ ] First upload creates each record (`201`); second run updates the same records (`200`), same `id`.
- [ ] No secret-bearing field appears in `out/flat-records.json`, `collection-report.json`, or logs.
- [ ] `out/` and its contents are owner-only (`0700`/`0600`).
- [ ] Deployment technical and compliance owners have reviewed `out/flat-records.json` before any Custom Test is published against it.

## 9. Custom Tests

`custom-tests/` holds two files per test, one per Advanced Editor field, ready to paste as-is:

- `<name>.evaluator.json` → paste into the Condition Group's Advanced editor box.
- `<name>.filtering-criteria.json` → click "Exclusion" in the Filtering Criteria section, then paste into its Advanced editor box.

Both files are a bare `{"all": [...]}`. Do not wrap either in `{"mode", "evaluator"}` — the UI rejects that shape. Exclusion/Inclusion is a UI button, not a JSON field.

Evaluation threshold for every test: "All results must pass" (`assertion: "nofail"`).

| Test | evidenceType | Checks |
|---|---|---|
| `instance-not-publicly-exposed` | `instance` | Fails an instance with any public IP address. |
| `instance-no-exposed-admin-ports` | `instance` | Fails an instance with SSH (22) or RDP (3389) reachable from a public source. |
| `instance-no-unenumerable-public-ingress` | `instance` | Fails an instance whose public-source ingress rule is port-unrestricted or a multi-port range. |
| `iam-user-mfa-enabled` | `iam_user` | Fails a user with MFA not activated. |
| `api-key-rotated-recently` | `api_key` | Fails an API signing key created more than 90 days ago. Adjust the `value` to your rotation policy. |
| `bucket-no-public-access` | `bucket` | Fails a bucket whose `publicAccessType` isn't `NoPublicAccess`. |
| `bucket-versioning-enabled` | `bucket` | Fails a bucket whose `versioning` isn't `Enabled`. |
| `autonomous-database-no-public-endpoint` | `autonomous_database` | Fails a database with a public endpoint hostname present. |
| `autonomous-database-customer-managed-key` | `autonomous_database` | Fails a database with no customer-managed KMS key. Skip it if Oracle-managed keys are acceptable. |
| `cloud-guard-enabled` | `cloud_guard_configuration` | Fails if the tenancy's Cloud Guard status isn't `ENABLED`. |
| `load-balancer-backend-set-healthy` | `load_balancer_backend_set` | Fails a backend set whose health status isn't `OK`. |
| `kms-key-auto-rotation-enabled` | `kms_key` | Fails a KMS key with auto-rotation disabled. |
