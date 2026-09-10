# Requirement / API Traceability Matrix

Maps every build requirement, OCI API operation, and engineering behavior
to the module and test that implement/verify it. Status legend: ✅ done and
tested · ⚠️ done, documented simplification (see note) · — not applicable
to MVP scope.

## 1. Build requirements (spec "Build requirements" list)

| # | Requirement | Module | Test |
|---|---|---|---|
| 1-4 | Read spec, assess repo, plan, identify contradictions | — (initial assessment, no blocking contradictions found) | — |
| 5 | Configuration and secret resolution | `config.py`, `redaction.py` | `tests/unit/test_config.py`, `test_redaction.py` |
| 6 | OCI auth + pagination/retry layer | `oci_auth.py`, `pagination.py` | `tests/unit/test_pagination.py` |
| 7 | Service collectors, independent | `collection/*.py` (7 files) | `tests/unit/test_operation_allowlist.py` |
| 8 | Normalize into allowlisted source models | `transform/normalize.py` | `tests/unit/test_normalize_and_relationships.py` |
| 9 | Resolve relationships using OCIDs | `transform/relationships.py` | `tests/unit/test_normalize_and_relationships.py` |
| 10 | Versioned derived facts | `transform/exposure.py`, `vpn_posture.py` (`derivation_version`/`DERIVATION_VERSION` on every `Finding`) | `tests/unit/test_exposure.py` |
| 11 | Exactly one aggregate record | `transform/aggregate.py::build_snapshot` | `tests/integration/test_end_to_end.py` |
| 12 | Validate against JSON Schema | `validation/schema.py` | `tests/unit/test_schema_validation.py` |
| 13 | Payload budget enforcement | `validation/size.py` | `tests/unit/test_size.py` |
| 14 | Upload only complete snapshots | `validation/completeness.py`, `cli.py::run` | `tests/integration/test_end_to_end.py`, `test_cli.py` |
| 15 | Preserve last known-good record | `cli.py::run` (upload gated on `decision.should_upload`; no call means Drata's existing record is untouched by construction) | `tests/integration/test_cli.py::test_incomplete_run_blocks_upload` |
| 16 | Dry-run mode + sanitized collection report | `cli.py` | `tests/integration/test_cli.py::test_dry_run_writes_sanitized_snapshot_and_report` |
| 17 | Unit + mocked integration tests, no live credentials | `tests/unit/*`, `tests/integration/*` | 221 tests, all mocked, `pytest` runs with no OCI/Drata credentials present |
| 18 | Documentation | `README.md`, this file | — |

## 2. OCI API operations

Every operation below is enforced twice: at build time by
`tests/unit/test_operation_allowlist.py`, which AST-scans every file under
`src/oci_drata/collection/` and fails if any OCI client method referenced
is not in `security.ALLOWED_OCI_OPERATIONS`, or matches
`FORBIDDEN_OPERATION_PREFIXES`/`FORBIDDEN_OPERATIONS`; and at runtime by
`security.GuardedOciClient`, which every client `oci_auth.regional_client()`
returns is wrapped in — an operation outside the allowlist raises the
moment it's actually called, catching a dynamically resolved or aliased
name the static scan can't see.

### 5.1 Discovery — `collection/discovery.py`

| Operation | Client | Test |
|---|---|---|
| `get_tenancy` | `IdentityClient` | `tests/unit/test_pagination.py` (via `call_once`) |
| `list_region_subscriptions` | `IdentityClient` | same |
| `list_compartments` | `IdentityClient` | same |
| `list_availability_domains` | `IdentityClient` | same |

### 5.2 Compute — `collection/compute.py`

| Operation | Client | Notes |
|---|---|---|
| `list_instances` | `ComputeClient` | Returns full `Instance` objects; `get_instance` enrichment not needed in practice |
| `get_image` | `ComputeClient` | Deduplicated across the whole run, not per compartment/region |
| `list_vnic_attachments` | `ComputeClient` | |
| `get_vnic` | `VirtualNetworkClient` | Deduplicated |
| `list_private_ips` | `VirtualNetworkClient` | Does not accept `compartment_id` — filtered by `vnic_id` |
| `get_public_ip_by_private_ip_id` | `VirtualNetworkClient` | 404 (no public IP) handled as a synthetic success, not a domain failure — see `compute.py::_lookup_public_ip` |

### 5.3 Storage — `collection/storage.py`

| Operation | Client |
|---|---|
| `list_boot_volumes` | `BlockstorageClient` |
| `list_boot_volume_attachments` | `ComputeClient` (requires `availability_domain`, unlike the other three) |
| `list_volumes` | `BlockstorageClient` |
| `list_volume_attachments` | `ComputeClient` |

### 5.4 Network exposure — `collection/networking.py`

`list_vcns`, `list_subnets`, `list_route_tables`, `list_internet_gateways`,
`list_security_lists`, `list_network_security_groups`,
`list_network_security_group_security_rules`,
`list_network_security_group_vnics` — all `VirtualNetworkClient`. The last
two do not accept `compartment_id`.

### 5.5 Base Database Service — `collection/database_base.py`

| Operation | Notes |
|---|---|
| `list_db_systems` | |
| `list_db_homes` | Scoped by `db_system_id`; `compartment_id` still required positionally |
| `list_databases` | Scoped by `db_home_id` |
| `list_backups` | Scoped by `database_id` |
| `list_data_guard_associations` | Does **not** accept `compartment_id` at all |

All `DatabaseClient`. `get_db_system`/`get_db_home`/`get_database`/
`get_backup` enrichment not needed — `list_*` results already carry every
field the schema requires (`kms_key_id`, `nsg_ids`, backup config, etc.).

### 5.6 Autonomous Database — `collection/database_autonomous.py`

| Operation | Notes |
|---|---|
| `list_autonomous_databases` | |
| `list_autonomous_database_backups` | |
| `list_autonomous_database_dataguard_associations` | Deprecated in the SDK's own docstring (points at `get_autonomous_container_database`) but still present and called as specified |
| `list_autonomous_database_peers` | Returns a wrapped `AutonomousDatabasePeerCollection`, not a bare list — adapted via `_unwrap_peers`. Peer objects carry only `id`+`region`, no back-reference to the owning ADB — collected into `autonomous_database_peers_by_adb_id`, keyed at collection time |

All `DatabaseClient`. Explicitly never called:
`get_autonomous_database_wallet`, `get_autonomous_database_regional_wallet`
(both denylisted by exact name in `security.py`).

### 5.7 Exadata detection — `collection/exadata_detection.py`

`list_cloud_vm_clusters`, `list_exadata_infrastructures`,
`list_cloud_exadata_infrastructures`,
`list_autonomous_exadata_infrastructures` (all `DatabaseClient`, minimal
existence-only, no drill-down) plus `db_system.shape` prefix check and
`autonomous_database.is_dedicated`, both computed from the already-
collected Base/Autonomous results (no extra API calls).

### 5.8 Site-to-Site VPN — `collection/vpn.py`

| Operation | Notes |
|---|---|
| `list_ip_sec_connections` | |
| `list_ip_sec_connection_tunnels` | Keyed by `ipsc_id`, not `compartment_id` |
| `get_ip_sec_connection_tunnel` | Conditional — only when a listed tunnel is missing a required field |
| `list_cpes`, `list_drgs` | |
| `list_drg_attachments` | `attachment_type="ALL"` is a valid accepted value |
| `list_drg_route_tables`, `list_drg_route_rules` | Scoped to DRGs with an `IPSEC_TUNNEL` attachment only, not every DRG in the tenancy |

All `VirtualNetworkClient`. **Never called**: `get_ip_sec_connection_tunnel_shared_secret`,
`update_ip_sec_connection_tunnel_shared_secret`, any `*device_config*`
operation — verified by `test_operation_allowlist.py::test_no_secret_or_credential_operation_referenced`.

## 3. Required engineering behaviors

| Behavior | Module | Test |
|---|---|---|
| Exhaust every `opc-next-page` | `pagination.py::paginate` | `test_pagination.py::test_paginate_exhausts_multiple_pages_including_empty_page_with_token` |
| Dynamic regional client construction | `oci_auth.py::regional_client` | exercised by every collector test |
| Verify regions subscribed + READY | `collection/discovery.py::_resolve_regions`, `_discovery_region` (bootstraps from the OCI SDK config file's own validated region, not `oci.regions.allow[0]`, so an invalid/unsubscribed first entry fails with a clean diagnostic instead of a raw connection error) | `tests/unit/test_discovery.py` |
| Compartment allow/deny, deterministic, subtree-exclusion (`collection/discovery.py::_expand_to_subtrees` -- excluding a compartment excludes its whole subtree, not just the exact configured OCID; overlapping configured roots dedupe by id instead of producing duplicate entries) | `collection/discovery.py` | `tests/unit/test_discovery.py` |
| Bounded concurrency + retry w/ jitter, OCI-aware retryability | `pagination.py::RetryPolicy` (per-call), `is_retryable_service_error` (mirrors the OCI SDK's own `TimeoutConnectionAndServiceErrorRetryChecker` defaults: 409 retried only for `IncorrectState`/`LockConflict`, 429 always, 5xx except 501 always — not a blanket status-code list), `cli.py::_run_independent_collectors` (`ThreadPoolExecutor`, cross-collector). Backoff delays actually slept are recorded per operation (`retryDelaysSeconds` in `manifest.operations[]`), not just applied silently. `collection/compute.py::_lookup_public_ip` shares the same classification for its 404-as-success special case. | `test_pagination.py` (retryability classification, backoff-delay capture), `test_cli.py` (concurrency wiring) |
| Never crash/drop a resource over an unrecognized enum value | `models.py` (all enum-shaped fields typed `str`, never a closed Python `Enum` — but this only preserves whatever the OCI SDK hands us: the SDK's own enum-typed property setters silently coerce any value outside their known set to the sentinel `"UNKNOWN_ENUM_VALUE"` before our code sees it, so a genuinely novel state's real name is already lost one layer down, not recoverable here) | `test_normalize_and_relationships.py::test_normalize_common_does_not_crash_on_unrecognized_lifecycle_state` |
| Bounded per-item concurrency within one collector (P2-1) | `pagination.py::run_concurrently` (generic bounded map; each worker is self-contained and returns its own data, the caller merges sequentially -- no lock needed). Applied to `collection/compute.py`'s per-VNIC-attachment enrichment (`get_vnic`/`list_private_ips`/`get_public_ip_by_private_ip_id`), the collector explicitly named in the review's N+1 example. `cli.py::_run_independent_collectors`'s `ThreadPoolExecutor` bounds concurrency *between* compute/storage/networking/database/vpn; it doesn't touch the serial per-item loop *within* one of them -- that's what `run_concurrently` is for. Not yet applied to `networking.py` (per-NSG `list_network_security_group_security_rules`/`_vnics`), `database_base.py`/`database_autonomous.py` (per-db-system/per-database/per-ADB backup/DataGuard/peer calls), or `vpn.py` (per-connection tunnel listing) -- same pattern, not done here. | `tests/unit/test_compute_collector.py` |
| Exclude terminated/terminating resources from evidence, never silently, with cascading parent/child exclusion | `transform/lifecycle.py::split_by_lifecycle`/`exclude_referencing`/`exclude_lifecycle_cascade` — covers instances, boot/block volumes, the full base DB chain (db_system → db_home → database → backup/data_guard), the autonomous DB chain (autonomous_database → backup/data_guard), and VPN (ipsec_connection → tunnel, drg → drg_attachment); excluded counts/ids reported per resource type via a `LIFECYCLE_EXCLUDED` warning, never dropped without a trace | `tests/unit/test_lifecycle.py`, `test_end_to_end.py::test_complete_collection_produces_one_schema_valid_record` (terminated instance + its own attachment, terminated db_system + its orphaned db_home, terminated ipsec_connection + its own tunnel — none trip a false unresolved-relationship) |
| Normalize timestamps to UTC RFC3339 | `transform/normalize.py::normalize_timestamp` | `test_normalize_and_relationships.py` (4 cases incl. non-UTC conversion, naive-datetime rejection) |
| Deterministic output ordering | `transform/aggregate.py::_sorted_dicts` (every array sorted by id/assertionId) | `test_end_to_end.py::test_complete_collection_produces_one_schema_valid_record` (same-input-same-output assertion) |
| Block upload on failure/unsupported/unresolved/schema/oversize/Exadata | `validation/completeness.py`, `pagination.py::operations_complete` (`unsupported` blocks like `failed`; `skipped` — a disabled service — does not) | `test_end_to_end.py` (3 blocking scenarios), `test_cli.py`, `test_pagination.py::test_operations_complete_ignores_skipped_but_blocks_on_unsupported` |
| Distinguish empty inventory from failure | `pagination.py::OperationResult.status` (`success` + 0 items ≠ `failed`) | `test_end_to_end.py::test_complete_collection_produces_one_schema_valid_record` (empty `dbSystems`/`databases` arrays, still `snapshotStatus: complete`) |
| Mock OCI + Drata in tests, no live credentials | all of `tests/` | `pytest` run with no `~/.oci/config` or `DRATA_API_TOKEN` required |
| Do not create Drata Custom Tests | — (no code path exists that could) | — |
| CI: lint, type-check, wheel-install test, Python version matrix, dependency lock + vulnerability audit | `.github/workflows/ci.yml` (Ruff + mypy + pytest across Python 3.12/3.13; separate job installs from `requirements-lock.txt` and runs `pip-audit --strict`) | `tests/integration/test_wheel_packaging.py` runs inside the matrix job; the lock-file install itself is verified by the `reproducible-install` job |

## 4. Security requirements

| Requirement | Enforcement |
|---|---|
| No inline credentials in config | `config.py::_scan_for_inline_secrets`, checked on load and after env overrides |
| OCI private key file permissions | `oci_auth.py::build_signer` rejects group/world-readable key files |
| Secrets never via CLI args | `cli.py` has no argument that accepts one |
| Redact secrets from logs/exceptions | `logging.py::RedactingFilter`, `redaction.py` |
| Never call OCI mutation ops | `security.py::FORBIDDEN_OPERATION_PREFIXES`, enforced statically by `test_operation_allowlist.py` and at runtime by `GuardedOciClient` (`tests/unit/test_security.py`) |
| Never retrieve secrets/wallets/shared secrets | `security.py::FORBIDDEN_OPERATIONS` (exact-name denylist), same static + runtime enforcement |
| Fail closed on an OCI operation outside the allowlist, even if dynamically resolved | `security.py::GuardedOciClient` — wraps every client `oci_auth.regional_client()` returns; blocks any `list_*`/`get_*` name not in `ALLOWED_OCI_OPERATIONS` and any forbidden-prefixed/exact-named call regardless of name shape, at the moment of the call | `tests/unit/test_security.py`, `tests/unit/test_oci_auth.py::test_regional_client_returns_a_guarded_client` |
| Never retrieve unrestricted instance metadata | No `get_windows_instance_initial_credentials` or metadata-service call anywhere in `collection/` |
| Signer repr never leaks account metadata | `oci_auth.py::TenancySigner.__repr__` allowlists `authentication_type`/`region` only (previously blocklisted only `pass_phrase`, leaking tenancy/user OCIDs, key fingerprint, and the private key's filesystem path into any log line or exception traceback that formatted the object) | `tests/unit/test_oci_auth.py` |
| Config fields fail closed on the wrong type/range, not a loose coercion | `config.py::_require_bool`/`_require_int`/`_require_port_list`/`_require_cidr_list`/`_check_known_keys` — a quoted `"false"` (`bool("false") is True`), a zero/negative id, an out-of-range port, a malformed CIDR, or an unrecognized/typo'd key now fails at config-load time with a field path, instead of silently coercing or being ignored | `tests/unit/test_config.py` |
| Drata `baseUrl` is allowlisted, not arbitrary | `config.py::_validate_drata_base_url` requires `https`, no embedded credentials/query/fragment/`..`, and hostname `public-api.drata.com` unless `drata.allowAlternateHost: true` is set explicitly (logs a warning when used) — the bearer token can't be sent to an unintended host via a tampered or typo'd config | `tests/unit/test_config.py` |
| Drata delivery honors `Retry-After`, closes its own session, captures a request id | `delivery/drata.py::_retry_after_seconds` (seconds or HTTP-date form, capped at `max_delay_seconds` regardless of what the server asked for), `_request_id` (`X-Request-Id`/`X-Request-ID`/`Request-Id`/`X-Correlation-Id`, whichever is present, on every non-transport-failure `DeliveryResult`), and `upsert_record` only calls `.close()` on a `requests.Session` it created itself, never one the caller passed in. `timeout_seconds` is now a parameter (was hardcoded to 30). | `tests/unit/test_drata_delivery.py` |
| Output files restricted to the process owner | `cli.py::_prepare_restricted_output_dir`/`_write_restricted` — the output directory is `0700` (tightened even if it pre-exists with looser permissions) and every written file is `0600` from the moment it's created (`os.open` with the mode set at creation, not a write-then-chmod window); both refuse a pre-existing symlink at that path rather than following it | `tests/integration/test_cli.py` |

## 5. Assumptions and simplifications

See `README.md §9` for the user-facing version. Implementation-level detail:

* Every resource definition in `schemas/oci-snapshot-1.0.0.json` (`instance`,
  `vnic`, `volume`, `routeTable`, `securityList`, `networkSecurityGroup`,
  `internetGateway`, `databaseResource`, `ipsecConnection`, `ipsecTunnel`) is
  a single flat object with its own `additionalProperties: false`, not an
  `allOf`/`$ref` composition over `commonResource`. `additionalProperties`
  only reliably rejects unexpected fields within one schema's own local
  `properties` — a type-specific branch composed via `allOf` can accept a
  field outside its own declared set regardless of a sibling branch's
  restriction, and `commonResource` itself had to stay
  `additionalProperties: true` for the composition to validate at all,
  making every resource type permissive to drift/typo'd fields. `commonResource`
  is still `additionalProperties: false` and still used directly (not via
  `allOf`) for resource types with no fields beyond it (compartments, images,
  private/public IPs, VCNs, subnets, attachments, CPEs, DRGs, DRG
  attachments).
* `paginate()`/`call_once()` are the single point where `compartment_id` is
  forwarded into the actual OCI call — several operations
  (`list_data_guard_associations`, `list_autonomous_database_peers`,
  `list_network_security_group_security_rules`/`_vnics`,
  `list_ip_sec_connection_tunnels`, `list_drg_route_tables`/`_rules`)
  reject it outright; each collector omits it explicitly for those calls.
* Region is stamped onto every raw resource at collection time
  (`pagination.py::stamp_region`) because only `Instance` among all OCI
  models carries its own `region` field. Compartments are stamped with the
  discovery-region as a deliberate choice (they're tenancy-global, not
  actually regional). `AutonomousDatabasePeerSummary` is the one exemption
  — its own `region` field is the peer's real, different region.
* `resources.backups` and `resources.dataGuardAssociations` are shared
  between Base DB and Autonomous DB — the schema has no separate
  `autonomousDatabaseBackups` array, and `databaseType`'s enum has no
  distinct `autonomous_*` values for these two.
* Autonomous Database `backupStatus` is always `not_applicable`
  (`transform/normalize.py::normalize_autonomous_database_posture`).
  Unlike Base DB's `DbBackupConfig.auto_backup_enabled`, ADB has no
  enabled/disabled boolean on `AutonomousDatabaseSummary` —
  `backup_retention_period_in_days` is a retention window, not a toggle.
  Posture is instead exposed as separate raw/derived fields
  (`backupRetentionDays`, `backupRetentionLocked`,
  `longTermBackupScheduleConfigured`, `publicEndpointPresent`,
  `privateEndpointConfigured`, `accessControlEnabled`,
  `allowedSourceCount`, `mtlsRequired`, `networkSecurityGroupIds`) rather
  than compressed into one guessed verdict. `OCI-ADB-PUBLIC-ENDPOINT-PRESENT`
  findings key off `publicEndpointPresent` only, not effective
  reachability — an ADB with a public endpoint can still be access-
  restricted by an ACL or a private endpoint; this MVP surfaces that
  context in the finding's `reason` but doesn't fold it into the verdict.
* Route tables, security lists, NSGs, and internet gateways carry their
  full rule/state detail (`routeRules`, `ingressRules`/`egressRules`,
  `securityRules`, `isEnabled`/`vcnId`) instead of the generic
  `commonResource` shape — see `models.py::RouteTable`/`SecurityList`/
  `NetworkSecurityGroup`/`InternetGateway` and
  `normalize.py::normalize_route_table`/`normalize_security_list`/
  `normalize_network_security_group`/`normalize_internet_gateway`. NSG
  rules are joined at normalize time from
  `networking.nsg_security_rules_by_nsg_id` (a separate
  `list_network_security_group_security_rules` call per NSG, not embedded
  on the NSG object itself).
* `base_db_system`/`base_database`/`data_guard` rows carry the same
  kind of detail beyond the generic identity fields — shape/version/
  node count/redundancy/subnet/NSGs for db systems
  (`normalize.py::normalize_db_system_detail`), backup/patch/management
  status for databases (`normalize_database_detail`), and role/peer
  role/protection mode/transport type for Data Guard associations
  (`normalize_data_guard_detail`). `networkSecurityGroupIds` is shared
  with the Autonomous Database posture fields above (same meaning:
  attached NSG ids), populated for whichever `databaseType` it applies to.
* `Volume.customer_managed_key_present` is always a definite `bool`, never
  `None` (`normalize.py::normalize_volume`) — `list_volumes`/
  `list_boot_volumes` return the full `Volume`/`BootVolume` type (there
  is no separate lighter-weight summary shape in the OCI SDK for either),
  so `kms_key_id` is authoritative; a null `kms_key_id` is a known fact
  (no customer-managed key), not an unresolvable unknown.

## 6. Single-record scaling ceiling (P2-2)

This MVP upserts exactly one aggregate record per tenancy (spec
requirement 11) — a deliberate constraint, not an oversight. It has a
hard ceiling: `runtime.maxPayloadBytes` (default in
`config.example.yaml`), enforced by `validation/size.py::check_payload_size`
after the full record is built. `PayloadSizeResult.near_budget` (default
80% of the budget) surfaces an early warning in `collection-report.json`
(`payloadNearBudget`) and the logs *before* it becomes a hard
`snapshotStatus: failed` — it is not baked into the uploaded record
itself, since that would change the record's own measured size.

If a tenancy's resource count outgrows the ceiling, the migration path
is:

1. **Per-resource-type records** — one Drata Custom Connection record
   per top-level `resources.*` array (e.g. a separate record for
   instances, another for databases) instead of one record nesting all
   of them. Requires: a distinct `recordId` per resource type
   (`aggregate.py::derive_record_id` would need a type discriminant),
   splitting `schemas/oci-snapshot-1.0.0.json`'s `resources`/`metrics`
   sections into per-type schemas, and re-deriving cross-type findings
   (e.g. `OCI-COMPUTE-ADMIN-PORT-EXPOSURE`, which joins instances against
   VNICs/subnets/security lists) from data that would now live in
   separate records — Custom Tests that currently read one record would
   need to read several.
2. **Multiple domain records** — a coarser split (e.g. one record for
   compute+storage+networking, one for database, one for VPN) trading
   less schema churn for a less granular ceiling fix; still requires
   distinct `recordId`s and updating any Custom Test that spans domains.

Neither is implemented — this MVP keeps the single-record constraint per
spec and only adds the early-warning signal above. Revisit if a real
deployment's resource count approaches `payloadBudgetBytes` in practice.
