# OCI-to-Drata Custom Connection

Read-only Oracle Cloud Infrastructure configuration-evidence collector that
normalizes findings into one schema-valid JSON record and upserts it into
an existing Drata Custom Connection.

Requirement/API traceability: [TRACEABILITY.md](TRACEABILITY.md).

**Status: MVP, functionally complete, not yet run against a live tenancy.**
Every module is covered by mocked unit/integration tests; nothing here has
been exercised against real OCI or Drata APIs. Run the acceptance checklist
in [§8](#8-deployment-acceptance-checklist) against a real tenancy before
relying on this for evidence.

## Contents

1. [Architecture](#1-architecture)
2. [Setup](#2-setup)
3. [Secret provisioning](#3-secret-provisioning)
4. [Least-privilege OCI policy](#4-least-privilege-oci-policy)
5. [Execution](#5-execution)
6. [Validating output](#6-validating-output)
7. [Troubleshooting](#7-troubleshooting)
8. [Deployment acceptance checklist](#8-deployment-acceptance-checklist)
9. [Known MVP limitations](#9-known-mvp-limitations)

## 1. Architecture

```text
OCI API → collectors (raw SDK objects) → normalize → relationships →
exposure/vpn_posture → findings → aggregate (one record) →
schema + size validation → completeness decision → Drata upsert
```

| Layer | Module(s) |
|---|---|
| Config/secrets | `src/oci_drata/config.py`, `redaction.py` |
| Auth | `src/oci_drata/oci_auth.py` |
| Pagination/retry | `src/oci_drata/pagination.py` |
| Collectors | `src/oci_drata/collection/*.py` (one per spec §5.x section) |
| Transform | `src/oci_drata/transform/*.py` |
| Validation | `src/oci_drata/validation/*.py` |
| Delivery | `src/oci_drata/delivery/drata.py` |
| Entry point | `src/oci_drata/cli.py` |
| Security allowlist | `src/oci_drata/security.py`, enforced by `tests/unit/test_operation_allowlist.py` |

Every OCI SDK call goes through `pagination.paginate()` (`list_*`) or
`pagination.call_once()` (`get_*`) — pagination, bounded retry with
full-jitter exponential backoff, and `opc-request-id` capture happen
exactly once, not per collector. Collectors return raw OCI SDK objects;
`transform/normalize.py` is the only place raw fields get allowlisted into
the schema's shape.

## 2. Setup

Requires Python 3.12+ and the official OCI Python SDK.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Copy the sample config and fill in deployment-specific values (regions,
compartments, tenancy OCID, Drata connection/resource IDs — none of this
is secret):

```bash
cp config.example.yaml config.yaml
```

`config.yaml` is git-ignored; never commit it once it has real
`connectionId`/`resourceId`/`expectedTenancyOcid` values. See
[config.example.yaml](config.example.yaml) for every field.

## 3. Secret provisioning

Two secrets exist outside `config.yaml` entirely:

1. **OCI private key** — the standard OCI SDK config file
   (`oci.authentication.configFile`, default `~/.oci/config`) points at a
   private key file (`key_file`). That key file must be owner-readable only
   (`chmod 600`) — `oci_auth.py` refuses to run otherwise.
2. **Drata API token** — referenced via `drata.apiTokenSecretRef`, resolved
   at the point of use, never read into `config.yaml`:

   ```yaml
   apiTokenSecretRef:
     provider: env   # or: provider: file, path: /run/secrets/drata_api_token
     name: DRATA_API_TOKEN
   ```

   ```bash
   export DRATA_API_TOKEN="$(cat /path/to/token)"   # env provider
   # or, for the file provider:
   install -m 600 /path/to/token /run/secrets/drata_api_token
   ```

`config.py` rejects the file at load time if any field looks like an
inline credential — a PEM block, a bearer-token-shaped string, or a
literal value under a `token`/`password`/`passphrase`/`private_key`-named
key that isn't itself a `secretRef` object. Secrets are never accepted as
CLI arguments and are redacted from logs and exceptions
(`redaction.py`, `logging.py`'s `RedactingFilter`).

Non-secret runtime overrides use the `OCI_DRATA__` env prefix, e.g.
`OCI_DRATA__OCI__REGIONS__ALLOW=us-ashburn-1,eu-frankfurt-1`. Overrides
cannot target a credential-shaped field.

## 4. Least-privilege OCI policy

**Validate every statement below against Oracle's current [Core Services
IAM policy reference](https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/corepolicyreference.htm)
and the Database service's policy reference before granting in
production.** This list is derived from the collectors' actual OCI SDK
calls (see [TRACEABILITY.md](TRACEABILITY.md)) and general OCI policy
conventions — not from a live check against Oracle's policy verb tables.

Create a dedicated group (e.g. `oci-drata-collector`) and a dedicated
API-signing user with no other access, then:

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
```

Notes:

* `use network-security-groups` is required — Oracle's policy mapping
  requires it for `list_network_security_group_security_rules` and
  `list_network_security_group_vnics`, though this collector performs no
  mutation. Spec §5.4 calls this out; do not widen it beyond
  `network-security-groups`.
* `instance-family`/`virtual-network-family`/`volume-family`/
  `database-family` are OCI's own policy aggregate groupings; confirm they
  cover every specific resource type this collector reads (full list in
  [TRACEABILITY.md](TRACEABILITY.md)) and narrow to individual resource
  types (e.g. `instance`, `vnic`, `subnet`) if your organization's policy
  standard requires it instead of family-level grants.
* Never grant `manage`, `all-resources`, any secret-family / Vault
  secret-content permission, or any IPSec shared-secret permission. This
  collector never calls a mutating, wallet, credential, or shared-secret
  operation, enforced by `security.py`'s allowlist and
  `test_operation_allowlist.py`.

## 5. Execution

```bash
# Dry run: writes out/snapshot.json (sanitized) and out/collection-report.json,
# never contacts Drata, regardless of the completeness decision.
oci-drata --config config.yaml --dry-run

# Live run: uploads only if the snapshot is complete, schema-valid, and
# within the payload budget.
oci-drata --config config.yaml
```

Exit codes: `0` success (uploaded, or a dry run that wasn't a schema
failure) · `1` blocked — a **valid** outcome meaning nothing was uploaded
because the snapshot wasn't complete (see `collection-report.json` for
why) · `2` configuration/auth error · `3` unexpected failure.

`runtime.dryRun` in `config.yaml` sets the default; `--dry-run` on the
command line always wins.

## 6. Validating output

```bash
python3 -c "
import json
from oci_drata.validation.schema import load_schema, validate_record
record = json.load(open('out/snapshot.json'))
result = validate_record(record, load_schema())
print('valid' if result.valid else result.errors)
"
```

`tests/integration/test_end_to_end.py` runs the identical
`build_snapshot → validate_record → check_payload_size →
decide_completeness` pipeline against fully mocked collector output. It is
a worked example of a schema-valid record, including a publicly exposed
Windows VM scenario.

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `configuration error: ... field name suggests a credential` | A literal secret in `config.yaml` instead of a `secretRef`. Move it to an env var or mounted file. |
| `AuthError: OCI private key file must not be group/world accessible` | `chmod 600` the key file `oci.authentication.configFile` points at. |
| `AuthError: OCI SDK config tenancy does not match configured oci.expectedTenancyOcid` | The `~/.oci/config` profile points at a different tenancy than `config.yaml` expects — a fail-closed guard against pointing the collector at the wrong tenancy. |
| `snapshotStatus: incomplete`, reasons mention `not subscribed/READY` | A region in `oci.regions.allow` isn't actually subscribed in this tenancy, or `list_region_subscriptions` itself failed. |
| `snapshotStatus: incomplete`, reasons mention a collector by name | That domain had a failed operation after retry exhaustion — check `collection-report.json`'s operations for `status: failed` and `errorCode`. Common cause: the policy in §4 doesn't cover a resource type this deployment actually uses. |
| `snapshotStatus: incomplete`, reason mentions Exadata | Exadata (or Exadata-backed dedicated Autonomous) was detected. Per spec, this MVP never claims complete database coverage when Exadata is present — see [§9](#9-known-mvp-limitations). |
| `snapshotStatus: failed`, reason mentions schema | The record itself didn't validate — this should not happen against unmodified collector code; check `collection-report.json`'s `schemaErrors` and file an issue rather than working around it. |
| Drata upload returns `error_class: auth` | Bearer token invalid/expired, or wrong `connectionId`/`resourceId`. The local snapshot is still `complete`; only delivery failed — nothing was overwritten in Drata. |
| Drata upload returns `error_class: validation` | Drata rejected the payload (400/404/409/422) — check the connection's own schema still matches `src/oci_drata/schemas/oci-snapshot-1.0.0.json`. |

## 8. Deployment acceptance checklist

From spec §13, adapted as a literal checklist:

- [ ] API-signing user authenticates; policy in §4 confirmed to grant no
      mutation permission.
- [ ] Collector verifies tenancy and every configured region.
- [ ] Approved compartments fully enumerated (check `scope.compartmentIds`
      against the OCI Console).
- [ ] Compute, storage, network, Base DB, Autonomous DB, and VPN
      operations complete without hidden failures (`collection-report.json`
      shows zero `failed` operations for enabled services).
- [ ] Exadata detection behavior demonstrated against a tenancy that
      actually has Exadata, if applicable.
- [ ] Resource counts reconcile against the OCI Console for a sample of
      compartments.
- [ ] A known Windows instance, database, and VPN connection appear with
      correct OCIDs and relationships.
- [ ] Known pass/fail/unknown conditions appear as expected in `findings`.
- [ ] `out/snapshot.json` validates against the Drata connection's actual
      schema (not just this repo's copy).
- [ ] Serialized snapshot stays below 4.5 MB.
- [ ] First upload creates a record (`201`); second run updates the same
      record (`200`), same `id`.
- [ ] Revoking one policy grant to force a failed run leaves the last
      known-good Drata record untouched.
- [ ] No secret-bearing field appears in `out/snapshot.json`,
      `collection-report.json`, or logs.
- [ ] Deployment technical and compliance owners have reviewed
      `out/snapshot.json` for readability before any manual Custom Test is
      published against it.

## 9. Known MVP limitations

See the cited module docstrings for detail.

* **Exposure CIDR matching is exact-string, not real CIDR-superset
  containment** (`transform/exposure.py`). A permissive rule for
  `0.0.0.0/1` would not be flagged even though it covers half the public
  internet.
* **`findings[]` is a small, spec-anchored set** (`transform/findings.py`)
  — public exposure, customer-managed-key (when required by config),
  database public endpoint, VPN redundancy — not an exhaustive control
  catalog. Custom Tests remain manually authored in the Drata UI per spec.
* **No noncritical-relationship classification**
  (`validation/completeness.py`) — every unresolved relationship blocks
  upload by default, matching spec §10's stated default, but the spec's
  "unless explicitly noncritical" escape hatch isn't implemented.
* **Exadata detection is existence-only, no drill-down**, per spec §5.7 —
  a tenancy with Exadata will show `snapshotStatus: incomplete`
  indefinitely for the database domain until a phase-two decision is made
  (spec §15).
* **This MVP has not been run against a live OCI tenancy or Drata
  connection.** Every scenario in this repo is a mocked unit/integration
  test. Complete the checklist in §8 before treating its output as
  compliance evidence.
