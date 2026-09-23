# OCI-to-Drata Custom Connection

Read-only Oracle Cloud Infrastructure configuration-evidence collector that
lightly normalizes OCI's raw API data into small, per-resource JSON records
and upserts them into an existing Drata Custom Connection. Compliance
verdicts are computed by Drata's own Custom Tests against these raw facts —
never precomputed by this collector (see [§1](#1-architecture)).

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
10. [Example Custom Tests](#10-example-custom-tests)

## 1. Architecture

Two delivery paths currently coexist against the same OCI collectors and the
same shared layers (config, auth, pagination, security allowlist — see the
table below). **New collector work lands on the flat-record path only.**

### 1.1 Flat-record path (current direction, opt-in via `drata.flatResourceId`)

```text
OCI API → collectors (raw SDK objects) → light normalize/relationships
(raw facts only, never a computed pass/fail) →
transform/aggregate.py::build_flat_records() →
schemas/flat-record.schema.json → delivery/drata.py::upsert_records()
```

Records never carry a precomputed compliance verdict. Drata's own Custom
Test `evaluator` decides what counts as compliant against the raw facts
below (e.g. `publicIngressPorts intersectsAny [22, 3389]`). See `PLAN.md`'s
"Correction" section for the rationale and how it applies to any future
evidenceType.

| `evidenceType` | Collector | `oci.services` toggle | Raw facts |
|---|---|---|---|
| `instance` | `collection/compute.py` + `transform/exposure.py::derive_public_ingress_facts()` | `compute` + `networkExposure` | `hasPublicAddress`, `publicIngressPorts`, `hasRangedPublicIngress` |
| `autonomous_database` | `collection/database_autonomous.py` | `autonomousDatabase` | `kmsKeyId`, `publicEndpointHostname` |
| `iam_user` | `collection/identity.py` | `identity` (opt-in — broader trust footprint, §4.1) | `mfaActivated` |
| `api_key` | `collection/identity.py` | `identity` (opt-in) | `userId`, `keyCreatedAt` |
| `iam_policy` | `collection/identity.py` | `identity` (opt-in) | `statements` (raw text — evidence, not a confirmed single-operator test) |
| `bucket` | `collection/object_storage.py` | `objectStorage` (opt-in, §4.2) | `kmsKeyId`, `publicAccessType`, `versioning` |
| `cloud_guard_configuration` | `collection/cloud_guard.py` | `cloudGuard` (opt-in, §4.3) | `cloudGuardStatus` |
| `monitoring_alarm` | `collection/monitoring.py` | `monitoring` (opt-in, §4.4) | `alarmEnabled`, `alarmNamespace`, `alarmQuery` (evidence only) |
| `load_balancer` | `collection/load_balancer.py` | `loadBalancer` (opt-in, §4.5) | `isPrivate` |
| `load_balancer_backend_set` | `collection/load_balancer.py` | `loadBalancer` (opt-in) | `loadBalancerId`, `backendSetHealthStatus` |
| `waf` | `collection/waf.py` | `waf` (opt-in, §4.6) | `loadBalancerId` (joins to `load_balancer`) |
| `kms_key` | `collection/kms_vault.py` | `kmsVault` (opt-in, §4.7) | `vaultId`, `autoRotationEnabled`, `lastRotationAt` |

`instance`/`autonomous_database` need no extra opt-in beyond the base
services already enabled by default. Every other evidenceType is off
unless its `oci.services.*` flag is explicitly set — see §4 for what each
one reads and why it's not on by default. "Evidence only" fields
(`iam_policy.statements`, `monitoring_alarm.alarmQuery`) are raw strings a
Custom Test would need to pattern-match; they're shipped as real data a
reviewer or test author can use, not as a fully clean single-operator
check the way every other field in this table is.

`PLAN.md` (working doc, not permanent documentation) has the full
rationale for this path, including the AWS/Azure native-connector
coverage-gap analysis driving which evidenceType gets added next.

### 1.2 Nested-schema path (original design, still the default, superseded)

```text
OCI API → collectors (raw SDK objects) → normalize → relationships →
exposure/vpn_posture → findings → aggregate (one record) →
schema + size validation → completeness decision → Drata upsert
```

One aggregate JSON record per tenancy (`schemas/oci-snapshot-1.0.0.json`),
uploaded via `delivery/drata.py::upsert_record()` — a single object, not a
batch. This runs unconditionally today (no opt-in), independently of the
flat-record path above; the two don't share a resourceId or interfere with
each other. Left in place until the flat-record path is proven out further
and this one is deliberately retired — see `PLAN.md`.

### 1.3 Shared layers (both paths)

| Layer | Module(s) |
|---|---|
| Config/secrets | `src/oci_drata/config.py`, `redaction.py` |
| Auth | `src/oci_drata/oci_auth.py` — `regional_client()` for a plain regional endpoint, `endpoint_client()` for a client needing an explicit per-resource endpoint (e.g. KMS's per-vault `management_endpoint`) |
| Pagination/retry | `src/oci_drata/pagination.py` |
| Collectors | `src/oci_drata/collection/*.py` (one per OCI resource domain) |
| Transform | `src/oci_drata/transform/*.py` |
| Validation | `src/oci_drata/validation/*.py` |
| Delivery | `src/oci_drata/delivery/drata.py` |
| Entry point | `src/oci_drata/cli.py` |
| Security allowlist | `src/oci_drata/security.py`, enforced twice: statically by `tests/unit/test_operation_allowlist.py` (AST scan at build time) and at runtime by `GuardedOciClient` (every OCI client `regional_client()`/`endpoint_client()` returns is wrapped; an operation outside the allowlist raises the moment it's called, not just when the static scan sees it) |

Every `list_*`/`get_*` call goes through `pagination.paginate()` or
`pagination.call_once()`, with one exception —
`collection/compute.py::_lookup_public_ip` implements its own retry loop to
treat a 404 (no public IP assigned) as a synthetic success rather than a
domain failure. Pagination, bounded retry with full-jitter exponential
backoff, and `opc-request-id` capture happen in one place, not per
collector. Collectors return raw OCI SDK objects; `transform/normalize.py`
(nested path) or each collector-specific `_flatten_*` function in
`transform/aggregate.py` (flat path) is the only place raw fields get
allowlisted into a schema's shape.

## 2. Setup

Requires Python 3.12+ and the official OCI Python SDK.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

For a reproducible install pinned to exactly what CI runs against, use
`requirements-lock.txt` instead (see that file's header for how to
regenerate it after changing `pyproject.toml`):

```bash
pip install -r requirements-lock.txt
pip install -e . --no-deps
```

CI (`.github/workflows/ci.yml`) runs Ruff, mypy, and the full test suite
across a Python 3.12/3.13 matrix, plus a separate job that installs from
the locked requirements and runs `pip-audit` against them.

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
calls and general OCI policy conventions — not from a live check against
Oracle's policy verb tables.

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
  mutation. Do not widen it beyond `network-security-groups`.
* `instance-family`/`virtual-network-family`/`volume-family`/
  `database-family` are OCI's own policy aggregate groupings; confirm they
  cover every specific resource type this collector reads (full list in
  `security.py::ALLOWED_OCI_OPERATIONS`) and narrow to individual resource
  types (e.g. `instance`, `vnic`, `subnet`) if your organization's policy
  standard requires it instead of family-level grants.
* Never grant `manage`, `all-resources`, any secret-family / Vault
  secret-content permission, or any IPSec shared-secret permission. This
  collector never calls a mutating, wallet, credential, or shared-secret
  operation, enforced both statically (`test_operation_allowlist.py`) and
  at runtime (`security.py::GuardedOciClient` — every OCI client is
  wrapped, and blocks any such operation the moment it's called, even if
  resolved dynamically or through an alias the static scan wouldn't see).

### 4.1 Optional: Identity (`oci.services.identity`)

**Off by default** (`identity: false` unless set otherwise in
`config.yaml`) — a materially broader trust footprint than everything
above. It reads every user's MFA-enabled status, every API signing key's
fingerprint and creation date (never the key material itself), and every
IAM policy's raw statement text tenancy-wide. Decide deliberately before
enabling it; it is not required for the compute/storage/networking/
database evidence this connector otherwise collects.

```text
Allow group oci-drata-collector to inspect users in tenancy
Allow group oci-drata-collector to read users in tenancy
Allow group oci-drata-collector to inspect policies in tenancy
Allow group oci-drata-collector to read policies in tenancy
```

* `list_api_keys` returns each key's `fingerprint`/`time_created`/
  `lifecycle_state` — never `key_value` (the key's own public-key PEM
  content) is read by anything this collector does with it; nothing about
  a private key ever leaves the customer's tenancy regardless, since OCI
  API signing keys are asymmetric and only the public key is ever
  registered with OCI in the first place.
* No credential, session token, or password is ever read — enforced the
  same way as the rest of this policy, statically and at runtime (see
  above). `get_windows_instance_initial_credentials` and similar remain
  denylisted regardless of what's granted here.

### 4.2 Optional: Object Storage (`oci.services.objectStorage`)

**Off by default** (`objectStorage: false` unless set otherwise). Reads
bucket-level metadata only — public access setting, encryption key
presence, versioning state. Never lists or reads object (file) contents.

```text
Allow group oci-drata-collector to inspect buckets in tenancy
Allow group oci-drata-collector to read buckets in tenancy
```

* Deliberately `buckets`, not `object-family` — the latter also covers
  object (file) contents and object-level operations this collector has
  no use for and never calls.
* `get_namespace`/`list_buckets`/`get_bucket` are the only three
  operations this domain calls (`security.py::ALLOWED_OCI_OPERATIONS`);
  none reads or lists object contents.

### 4.3 Optional: Cloud Guard (`oci.services.cloudGuard`)

**Off by default** (`cloudGuard: false` unless set otherwise). Reads only
whether Cloud Guard itself is enabled/disabled for the tenancy — never
findings, detector recipes, or target configuration detail.

```text
Allow group oci-drata-collector to inspect cloud-guard-config in tenancy
Allow group oci-drata-collector to read cloud-guard-config in tenancy
```

* `get_configuration` is the only operation this domain calls.

### 4.4 Optional: Monitoring (`oci.services.monitoring`)

**Off by default** (`monitoring: false` unless set otherwise). Reads alarm
*definitions* — whether an alarm exists, is enabled, and what metric query
it watches. Never reads metric data points or alarm firing history.

```text
Allow group oci-drata-collector to inspect alarms in tenancy
Allow group oci-drata-collector to read alarms in tenancy
```

* `list_alarms` is the only operation this domain calls.
* An alarm's raw `query` (MQL string) is surfaced as evidence, not
  evaluated — a Custom Test would need to pattern-match it (e.g. `contains
  "CpuUtilization"`) to check for a specific monitored metric, since this
  collector doesn't parse or classify alarm queries by metric type.

### 4.5 Optional: Load Balancer (`oci.services.loadBalancer`)

**Off by default** (`loadBalancer: false` unless set otherwise). Reads
whether a load balancer is public or private, and backend-set health
status — never listener/certificate configuration or traffic data.

```text
Allow group oci-drata-collector to inspect load-balancers in tenancy
Allow group oci-drata-collector to read load-balancers in tenancy
```

* `list_load_balancers` already returns full detail (no separate
  `get_load_balancer` needed) and includes each load balancer's backend
  set names directly — `get_backend_set_health` is then one call per
  (load balancer, backend set) pair, fanned out concurrently.

### 4.6 Optional: Web Application Firewall (`oci.services.waf`)

**Off by default** (`waf: false` unless set otherwise). Reads whether a
Web App Firewall is attached to a load balancer — never firewall rule or
policy detail.

```text
Allow group oci-drata-collector to inspect web-app-firewalls in tenancy
Allow group oci-drata-collector to read web-app-firewalls in tenancy
```

* Deliberately the current `oci.waf` service (API version 2021), not the
  older `oci.waas` (Web Application Acceleration and Security, API
  version 2018) — `WaasPolicySummary` is keyed by DNS domain with no OCID
  link to any load balancer, so it can't answer "does load balancer X
  have a WAF attached" the way `oci.waf`'s `load_balancer_id` field can.
* `list_web_app_firewalls` is the only operation this domain calls.

### 4.7 Optional: KMS Vault (`oci.services.kmsVault`)

**Off by default** (`kmsVault: false` unless set otherwise). Reads
whether a KMS key has auto-rotation enabled and when it last rotated —
never key material, never a wrapping/unwrapping operation.

```text
Allow group oci-drata-collector to inspect vaults in tenancy
Allow group oci-drata-collector to read vaults in tenancy
Allow group oci-drata-collector to inspect keys in tenancy
Allow group oci-drata-collector to read keys in tenancy
```

* Confirmed against Oracle's own Key Management policy reference (not
  just SDK introspection, unlike most of this section) — `vaults` covers
  `ListVaults`/`GetVault`, `keys` covers `ListKeys`/`GetKey`.
* Structurally different from every other collector in this project:
  `KmsManagementClient` (the client that actually lists/reads keys) must
  be constructed with the specific vault's own `management_endpoint` —
  resolved from that vault's own `list_vaults` response field, not a
  plain regional endpoint. See `oci_auth.py::endpoint_client` and
  `collection/kms_vault.py`.
* Rotation timing (`auto_key_rotation_details.time_of_last_rotation`) is
  only present on the full `Key` model, not the lighter `KeySummary`
  `list_keys` returns — `get_key` per key is a genuine per-item fan-out,
  not an optional enrichment step.

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

```bash
# Sample mode: stops collecting after 30s instead of scanning the whole
# tenancy, keeping whatever real data was gathered by then -- fast,
# low-volume, for building/testing a Custom Test against real data. Every
# OCI call shares one retry policy (pagination.py::RetryPolicy.deadline),
# so this bounds every domain at once. Never uploads the original/nested
# snapshot (a partial scan can't honestly claim tenancy-wide
# completeness) -- but the flat-record path uploads normally if
# runtime.dryRun is false, since each record is standalone evidence.
oci-drata --config config.yaml --test
```

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
| `configuration error: ... expected true or false (unquoted), got ...` | A boolean field was quoted in YAML (e.g. `compute: "false"`) — YAML parses that as the string `"false"`, and `bool("false")` is `True` in Python, so this is rejected rather than silently flipped. Remove the quotes. |
| `configuration error: ... must be >= 1, got 0` | `drata.connectionId`/`resourceId` are still the example file's placeholder `0`. Replace with the real IDs from the Drata Custom Connection. |
| `configuration error: ... is not a valid CIDR` | `decisions.publicSourceCidrs` has a malformed entry. This is checked at config-load time specifically so a typo here can't silently make every exposure finding resolve to `not_exposed` (an empty/broken reference set has nothing to compare against). |
| `configuration error: drata.baseUrl ...` | `drata.baseUrl` must be `https`, have no embedded credentials/query/fragment, and its hostname must be `public-api.drata.com` unless `drata.allowAlternateHost: true` is set explicitly — a deliberate allowlist so a tampered or typo'd URL can't send the bearer token to an unintended host. |
| `configuration error: $: unrecognized field(s) ...` | A typo'd or unexpected top-level/nested config key. Check spelling against `config.example.yaml`. |
| `AuthError: OCI private key file must not be group/world accessible` | `chmod 600` the key file `oci.authentication.configFile` points at. |
| `AuthError: OCI SDK config tenancy does not match configured oci.expectedTenancyOcid` | The `~/.oci/config` profile points at a different tenancy than `config.yaml` expects — a fail-closed guard against pointing the collector at the wrong tenancy. |
| `snapshotStatus: incomplete`, reasons mention `not subscribed/READY` | A region in `oci.regions.allow` isn't actually subscribed in this tenancy, or `list_region_subscriptions` itself failed. |
| `snapshotStatus: incomplete`, reasons mention a collector by name | That domain had a failed operation after retry exhaustion — check `collection-report.json`'s operations for `status: failed` and `errorCode`. Common cause: the policy in §4 doesn't cover a resource type this deployment actually uses. |
| `snapshotStatus: incomplete`, reason mentions Exadata | Exadata (or Exadata-backed dedicated Autonomous) was detected. This tool never claims complete database coverage when Exadata is present — see [§9](#9-known-mvp-limitations). |
| `snapshotStatus: failed`, reason mentions schema | The record itself didn't validate — this should not happen against unmodified collector code; check `collection-report.json`'s `schemaErrors` and file an issue rather than working around it. |
| Drata upload returns `error_class: auth` | Bearer token invalid/expired, or wrong `connectionId`/`resourceId`. The local snapshot is still `complete`; only delivery failed — nothing was overwritten in Drata. |
| Drata upload returns `error_class: validation` | Drata rejected the payload (400/404/409/422) — check the connection's own schema still matches `src/oci_drata/schemas/oci-snapshot-1.0.0.json`. |
| Log line `payload approaching size budget`, `collection-report.json`'s `payloadNearBudget: true` | Serialized record is at/above 80% of `runtime.maxPayloadBytes` but still under it — upload still proceeds. Early warning before this tenancy's resource count hits the hard ceiling and uploads start failing; see `PayloadSizeResult`'s docstring (`validation/size.py`) for the migration path if that happens. |

## 8. Deployment acceptance checklist

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
- [ ] `out/` and everything written to it are owner-only (`0700`/`0600`) —
      the CLI enforces this itself; this step just confirms the host's
      filesystem didn't override it (e.g. an unusual mount option).
- [ ] Deployment technical and compliance owners have reviewed
      `out/snapshot.json` for readability before any manual Custom Test is
      published against it.

## 9. Known MVP limitations

See the cited module docstrings for detail.

* **Exposure NSG-to-NSG source chains are not resolved** (`transform/exposure.py`).
  A rule whose source is another network security group (not a CIDR) marks
  that VNIC's ingress evidence `unknown` rather than resolving the
  referenced NSG's membership. CIDR sources are evaluated by real
  containment/overlap (`ipaddress`), not string equality.
* **`findings[]` is a small, spec-anchored set** (`transform/findings.py`)
  — public exposure, customer-managed-key (when required by config),
  database public endpoint, VPN redundancy — not an exhaustive control
  catalog. Custom Tests remain manually authored in the Drata UI.
  Each assertion name states its exact predicate
  (`OCI-COMPUTE-ADMIN-PORT-EXPOSURE` checks the *configured administrative
  ports* only, not general exposure; `OCI-ADB-PUBLIC-ENDPOINT-PRESENT`
  checks endpoint *presence*, not effective reachability through an
  ACL/private endpoint/NSGs) — a Custom Test author should read the
  assertion name as that literal predicate, not a broader guarantee.
  Effective ADB reachability derivation is not implemented.
* **No noncritical-relationship classification**
  (`validation/completeness.py`) — every unresolved relationship blocks
  upload by default; an "unless explicitly noncritical" escape hatch isn't
  implemented.
* **Lifecycle-state exclusion (TERMINATED/TERMINATING)** covers compute
  instances, boot/block volumes, the full base DB chain (db system → db
  home → database → backup/Data Guard association), the autonomous DB
  chain (autonomous database → backup/Data Guard association), and VPN
  (IPSec connection → tunnel, DRG → DRG attachment) — see
  `transform/lifecycle.py::exclude_lifecycle_cascade`. Exclusion is
  cascading: a terminated parent's children go with it even when the
  child's own lifecycle state looks fine, so a resource never surfaces
  as an unresolved relationship (parent not found) instead of correctly
  reflecting that its whole lineage is gone. Excluded resources are
  never silently dropped: a `LIFECYCLE_EXCLUDED` entry in `warnings`
  reports the count and ids per resource type.
* **Operations within an enabled domain have no required/optional
  distinction** (`pagination.py::operations_complete`) — any operation
  failure (even a non-essential enrichment call) blocks that entire
  domain's upload; there's no per-operation criticality registry that
  would let a genuinely optional lookup degrade to an `unknown` finding
  instead. `unsupported` is treated as a blocking gap, the same as
  `failed`.
* **This record cannot self-report current freshness.** `collectedAt`
  and `freshnessThresholdHours` (from `decisions.freshnessHours`) are
  written at collection time; nothing re-evaluates them afterward. If
  the collector stops running, the last successfully uploaded record
  stays in Drata untouched (upsert-on-success preserves last known-good
  evidence by design) — it does not become visibly stale on its own.
  Evaluate `now - collectedAt > freshnessThresholdHours` yourself: in a
  Custom Test authored in the Drata UI (this tool creates none), or in
  separate monitoring on the collector's own run cadence.
* **Exadata detection is existence-only, no drill-down** — a tenancy with
  Exadata will show `snapshotStatus: incomplete` indefinitely for the
  database domain until deeper detection is built.
* **Every scenario in this repo's test suite is mocked.** Complete the
  checklist in §8 against a real tenancy and Drata connection before
  treating a deployment's output as compliance evidence.

The limitations above are specific to the nested-schema path (§1.2). The
flat-record path (§1.1) has its own, currently more significant, gaps:

* **Only `instance` and `autonomous_database` have been proven against a
  real, live Drata Custom Test** — pushed real records, built a test in
  the UI, confirmed correct per-record pass/fail evaluation. Every other
  evidenceType in the §1.1 table is schema-valid and unit-tested but not
  yet confirmed against a live Drata evaluator.
* **`iam_policy` and `monitoring_alarm` are evidence, not a clean
  automated check** — their raw string fields (`statements`, `alarmQuery`)
  would need Drata operator pattern-matching a Custom Test author sets
  up, not a simple `equal`/`exist` check the way every other field in the
  table is.
* **OKE (Kubernetes) audit-logging evidence does not exist.** Checked
  before writing anything: it's not a field on the cluster object, it's a
  separate OCI Logging-service resource attached to the cluster — a
  cross-service lookup this collector doesn't do.
* **The AWS/Azure native-connector coverage target this path is being
  built against (`PLAN.md`) is stated as "60%" without a locatable
  original source** in git history or `PLAN.md` itself.

## 10. Example Custom Tests

**`custom-tests/`'s 8 JSON files are stale — do not paste them in as-is.**
They target the nested-schema path's shape (`resources.instances[]`,
`snapshotStatus`, etc. — §1.2, still what the default upload path
produces), and their operator names/nesting pattern were validated
against Drata's engine *source code*, not against this connection's own
live Advanced Editor. Real production use found the gap that source-level
validation missed: Drata's Advanced Editor **rejected the array-quantifier
JSON pattern several of these files use, live, for this connection's
actual registered schema.** `custom-tests/README.md` documents this in
detail; treat every file in that directory as a historical record, not
a working example, until it's rewritten (tracked in `PLAN.md`).

For a test format that **is** confirmed against a live Custom Test build
(captured directly from Drata's own UI, not source code — see `PLAN.md`'s
"Real Custom Test authoring reference"), and against the current
flat-record path (§1.1): build a Custom Test in the UI with a raw-fact
`evaluator` condition, e.g. for `evidenceType: "instance"`:

```json
{ "all": [ { "fact": "hasPublicAddress", "operator": "equal", "value": false } ] }
```

Evaluation threshold "All results must pass" (`assertion: "nofail"`).
This exact shape was pushed live and confirmed to correctly flag
noncompliant vs. compliant records — see `PLAN.md` for the full trace.
