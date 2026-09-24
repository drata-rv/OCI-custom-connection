# Custom Tests for the flat-record schema

Advanced Editor JSON for `schemas/flat-record.schema.json` -- the current
architecture (main README §1.1), one shared schema/resource across every
evidenceType. Supersedes the parent directory's stale nested-schema files
(§1.2, see that directory's own README).

## Every test here needs `filteringCriteria`, and here's why

The one test proven live earlier in this project (`hasPublicAddress equal
false`) never needed scoping, because at the time the resource held only
`instance` records. This resource now holds `instance`, `iam_user`,
`api_key`, `iam_policy`, and `bucket` records side by side (more
evidenceTypes as more collectors are enabled), and every record carries
all 27 schema fields -- null where a field doesn't apply to that
evidenceType (Drata's importer auto-requires every top-level property; see
main README §9). An unscoped test on, say, `mfaActivated equal true` would
therefore evaluate against every bucket and api_key record too, where
`mfaActivated` is `null`, and fail every one of them. Each file's
`filteringCriteria` (mode `exclusion`, confirmed real -- see the parent
README's "Filtering Criteria" section) drops every record whose
`evidenceType` doesn't match before the main evaluator ever runs.

Paste the two into the Advanced Editor's two separate inputs: `evaluator`
into the main condition, `filteringCriteria` into "Add Filtering Criteria".

## Status per file

Live-confirmed (2026-09-24, real records in a real tenancy, read back
after upload -- see `PLAN.md`/README §9 for the incident this was
verified against):

- `instance-not-publicly-exposed.json`
- `iam-user-mfa-enabled.json`
- `bucket-no-public-access.json`
- `bucket-versioning-enabled.json`

Schema-valid and unit-tested, not yet pushed through the Advanced Editor
live (say so in each file's own `description`, don't assume otherwise):

- `instance-no-exposed-admin-ports.json`
- `instance-no-unenumerable-public-ingress.json`
- `api-key-rotated-recently.json` (real data exists for this one --
  two real api_key records are live -- only the Advanced Editor
  evaluation itself hasn't been confirmed)
- `autonomous-database-no-public-endpoint.json`
- `autonomous-database-customer-managed-key.json`
- `cloud-guard-enabled.json`
- `load-balancer-backend-set-healthy.json`
- `kms-key-auto-rotation-enabled.json`

## Evidence, not a clean automated check -- no file provided

- **`iam_policy`**: `statements` is raw OCI policy text. A real check
  needs pattern-matching against unstructured policy language (e.g. does
  a statement grant `manage all-resources`) -- evidence for manual review
  or a Custom Test author to build against directly, not a
  single-operator condition this project can hand you pre-built.
- **`monitoring_alarm`**: same shape of problem -- checking for a specific
  monitored metric means pattern-matching the raw MQL `query` string.
  `alarmEnabled equal true` alone answers "does at least one alarm exist
  and is it on," not "is the metric I care about actually alarmed."
- **`load_balancer`** (existence) / **`waf`** (existence): the concept
  each answers (AWS "Load Balancer Used" / "WAF in Place") is mere
  *existence* of a record, not a value on it -- Custom Tests evaluate
  per-record, so there's no single-record condition that expresses "at
  least one record of this evidenceType exists." Build this the way the
  Drata UI's own presence/threshold checks do, if it supports one; not a
  plain `{fact, operator, value}` evaluator.
