# Custom Tests

**STALE — do not paste these in as-is.** Built for the nested-schema
path's shape (`resources.instances[]`, `snapshotStatus`, etc. — main
README §1.2), and validated against Drata's engine *source code*, not a
live build in this connection's own Advanced Editor. Real production use
found what source-level validation missed: several files here use an
array-quantifier (`operator: all` over a `path` into an array) that
**Drata's Advanced Editor rejected live**, for this connection's actual
registered schema — see "Operator and format notes" below for the
source-level reasoning that turned out to be insufficient, and the main
README §10 for a test shape that **is** confirmed live. Kept here as a
historical record, not a working example, until rewritten (tracked in
`PLAN.md`).

Example Drata Advanced Test Builder JSON for this OCI Custom Connection.
Paste into Monitoring > Create test > Advanced editor, after selecting
this connection's uploaded record as the data source.

- `admin-port-exposure.json` -- fails if any `resources.instances[].effectiveIngressExposure != not_exposed`. Mirrors `OCI-COMPUTE-ADMIN-PORT-EXPOSURE`.
- `autonomous-db-public-endpoint.json` -- fails if any `resources.autonomousDatabases[].publicEndpointPresent != false`. Mirrors `OCI-ADB-PUBLIC-ENDPOINT-PRESENT`.
- `customer-managed-key-volumes.json` -- fails if any *attached* `resources.bootVolumes[]`/`blockVolumes[].customerManagedKeyPresent != true`. Unattached volumes (`attachedInstanceIds` empty) are exempted in-JSON via a nested `any`, matching the real collector's own scoping (`aggregate.py`: `[v for v in (*boot_volumes, *block_volumes) if v.attached_instance_ids]`). Mirrors `OCI-STORAGE-CUSTOMER-MANAGED-KEY`; only meaningful when `decisions.requireCustomerManagedVolumeKeys` is enabled for this deployment.
- `customer-managed-key-databases.json` -- fails if any `resources.databases[]`/`autonomousDatabases[].kmsKeyId` is null. Mirrors `OCI-DATABASE-CUSTOMER-MANAGED-KEY`; only meaningful when `decisions.requireCustomerManagedDatabaseKeys` is enabled.
- `vpn-tunnel-redundancy.json` -- fails if any `resources.ipsecConnections[].redundancyStatus != redundant`. Mirrors `OCI-VPN-TUNNEL-REDUNDANCY`.
- `snapshot-completeness.json` -- fails unless top-level `snapshotStatus == complete`.
- `snapshot-freshness.json` -- genuinely dynamic rolling check: `collectedAt` `withinLastHours` the record's own `freshnessThresholdHours` (fact-to-fact comparison), re-evaluated against "now" on every test run.
- `inaccessible-compartments.json` -- fails if any top-level `warnings[].code == "COMPARTMENT_INACCESSIBLE"`. Catches compartments OCI marked not-accessible during discovery (`discovery.py`: `is_accessible` on the `list_compartments` response) -- a scope gap that does not flip `snapshotStatus` away from `complete` and is not surfaced by any other test in this set.

## Operator and format notes

**`equal` and `notEqual`.** Both are real, customer-selectable Advanced Editor operators; their wire value is the singular string `"equal"`/`"notEqual"`. `notEqual` against a literal `null` is a valid, supported comparison (plain strict inequality, no special-cased null handling) -- the pattern `customer-managed-key-databases.json` relies on for `kmsKeyId != null`. All files in this repo use `equal`/`notEqual` correctly as-is.

**`fact` + `path` onto an array, quantified with `all`/`any`.** This is a real, shipped pattern, not a guess: a `{fact, path, operator: all|any, value}` condition where `path` points at a nested array property is used in Drata's own Test Library. This confirms the `{"fact": "resources", "path": "<array>", "operator": "all", "value": {...}}` shape used across most of the files above.

**`withinLastHours`.** Drata's engine has real relative-date operators anchored to the current time -- `withinLastDays`, `withinNextDays`, `withinLastHours`, `olderThanDays` -- shipped to the customer-facing Advanced Editor. `snapshot-freshness.json` uses `{"fact": "collectedAt", "operator": "withinLastHours", "value": {"fact": "freshnessThresholdHours"}}` so the threshold always tracks this record's own configured value instead of a second, hardcoded number.

**Open caveat -- the fact-to-fact `value` in `snapshot-freshness.json`.** That `value` is a fact reference, not a literal. The engine supports resolving a `value` that is itself a fact reference (`{fact: ...}`) rather than a literal, and this is reachable from the customer-facing save path, not just declared in source -- confirmed via existing shipped Test Library recipes that use this form, and via observed runtime validation behavior that treats `fact` as one of the supported `value` types. What's still missing: a byte-identical example of a same-record self-reference the way `{"fact": "freshnessThresholdHours"}` does -- known working examples reference a separate custom fact with params, not a plain sibling field on the same record. If the Advanced Editor UI ever rejects this on save, the fallback is a plain literal, e.g. `"value": 24`, matching this deployment's configured `decisions.freshnessHours` -- still a genuinely dynamic (relative-to-now) check, just with the threshold duplicated instead of linked.

**Filtering Criteria.** Filtering Criteria is JSON-expressible, using the same `all`/`any`/`fact`/`path`/`operator`/`value` grammar, but it lives in a separate "Add Filtering Criteria" payload per condition group and filters which *top-level resource records* a condition group evaluates against -- it has no way to reach into and filter individual items of a nested array like `bootVolumes`/`blockVolumes`, and this connection publishes one snapshot record per run. `customer-managed-key-volumes.json` instead scopes attached-only volumes directly inside its existing per-item quantifier (see the bullet above), the same `path`-to-a-scalar mechanic (`path: 'length'` + `operator: equal`) used elsewhere for scoping by array length.

## Coverage notes

`metrics.exadataDetectedCount` and `manifest.unresolvedRelationships` are already folded into `decide_completeness()` (`src/oci_drata/validation/completeness.py`): Exadata detection or any unresolved relationship unconditionally forces `snapshotStatus` to `incomplete`. A Custom Test on either would only restate `snapshot-completeness.json`, so neither has its own file. `metrics.collectionErrorCount` is redundant the same way -- it counts operations with `status == "failed"`, and `operations_complete()` (`src/oci_drata/pagination.py`) already turns any such failure into an incomplete domain, which `decide_completeness()` also turns into `incomplete`.

`warnings[].code == "LIFECYCLE_EXCLUDED"` (severity `info`, `src/oci_drata/transform/lifecycle.py`) reflects expected, deliberate exclusion of terminated/terminating resources, not a coverage gap -- a test that failed on its presence would false-positive on ordinary infrastructure churn, so it isn't a test candidate. `warnings[].code == "COMPARTMENT_INACCESSIBLE"` (severity `warning`, `src/oci_drata/collection/discovery.py`) is the one gap none of the other seven tests catch: it never marks an operation `failed` and is never read by `decide_completeness()`, so a tenancy can have IAM-inaccessible compartments and still get `snapshotStatus == complete`. `inaccessible-compartments.json` exists for that case.
