"""CLI entry point: ``oci-drata [--config PATH] [--dry-run]``.

Never accepts secrets as CLI arguments. Independent collectors run
concurrently (bounded by ``runtime.maxConcurrency``); Exadata detection
runs after, since it consumes the database collectors' output.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import logging
import os
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from oci_drata.collection.cloud_guard import CloudGuardCollectionResult, collect_cloud_guard
from oci_drata.collection.compute import ComputeCollectionResult, collect_compute
from oci_drata.collection.database_autonomous import (
    AutonomousDatabaseCollectionResult,
    collect_autonomous_database,
)
from oci_drata.collection.database_base import DatabaseBaseCollectionResult, collect_database_base
from oci_drata.collection.discovery import DiscoveryResult, discover
from oci_drata.collection.exadata_detection import detect_exadata
from oci_drata.collection.identity import IdentityCollectionResult, collect_identity
from oci_drata.collection.kms_vault import KmsVaultCollectionResult, collect_kms_vault
from oci_drata.collection.load_balancer import LoadBalancerCollectionResult, collect_load_balancer
from oci_drata.collection.monitoring import MonitoringCollectionResult, collect_monitoring
from oci_drata.collection.networking import NetworkingCollectionResult, collect_networking
from oci_drata.collection.object_storage import ObjectStorageCollectionResult, collect_object_storage
from oci_drata.collection.storage import StorageCollectionResult, collect_storage
from oci_drata.collection.vpn import VpnCollectionResult, collect_vpn
from oci_drata.collection.waf import WafCollectionResult, collect_waf
from oci_drata.config import AppConfig, ConfigError, load_config, redact_config_for_display
from oci_drata.delivery.drata import upsert_record, upsert_records
from oci_drata.logging import configure_logging
from oci_drata.oci_auth import AuthError, TenancySigner, build_signer
from oci_drata.pagination import OperationResult, RetryPolicy
from oci_drata.transform.aggregate import build_flat_records, build_snapshot
from oci_drata.validation.completeness import decide_completeness
from oci_drata.validation.schema import load_flat_schema, load_schema, validate_record
from oci_drata.validation.size import check_payload_size, serialize_deterministic

logger = logging.getLogger(__name__)

# --test bounds wall-clock time instead of resource count -- see RetryPolicy.deadline
# (pagination.py). Which compartments actually have data isn't knowable up front, so
# a time budget lets collection cover as much real ground as it can within it, rather
# than gambling on a fixed number of compartments that could all turn out empty.
TEST_MODE_TIME_BUDGET_SECONDS = 30

# OCI SDK error codes meaning "this API user has no access here", as opposed to a
# transient failure (429/5xx, already retried) or a --test deadline cutoff (a distinct,
# non-auth error_code -- see pagination.py). A tenancy whose configured scope
# (oci.compartments.roots/regions.allow) reaches further than this API user's OCI
# policy grants produces a flood of these; grouping them by compartment turns that
# flood into the one fact an operator actually needs.
_AUTH_GAP_ERROR_CODES = frozenset({"NotAuthorizedOrNotFound", "NotAuthenticated"})


def _domain_all_skipped(operations: list[OperationResult]) -> bool:
    """True only when every operation this domain recorded is the synthetic
    status="skipped" marker a disabled collector emits (see e.g. identity.py's
    _skip_result()) -- i.e. this service was turned off by config, not attempted and
    found empty. An empty operations list (no compartments were ever in scope) is
    not the same claim, so it's not treated as skipped here."""

    return bool(operations) and all(op.status == "skipped" for op in operations)


def _access_summary(operations: list[OperationResult]) -> dict[str, Any]:
    """``operations`` is every OperationResult (pagination.py) from every collector
    this run actually invoked -- not just the ones a particular delivery path
    consumes. Groups them by compartment: which ones this API user's policy doesn't
    cover, and which ones actually had real data -- the two things that matter after
    a run this noisy, instead of scrolling thousands of per-operation log lines."""

    auth_gap: set[str] = set()
    has_data: set[str] = set()
    all_seen: set[str] = set()
    for op in operations:
        compartment_id = op.compartment_id
        if compartment_id is None:
            continue
        all_seen.add(compartment_id)
        if op.error_code in _AUTH_GAP_ERROR_CODES:
            auth_gap.add(compartment_id)
        if op.status == "success" and op.item_count > 0:
            has_data.add(compartment_id)
    return {
        "compartmentsSeen": len(all_seen),
        "compartmentsWithAuthGap": sorted(auth_gap),
        "compartmentsWithRealData": sorted(has_data),
    }

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_CONFIG_ERROR = 2
EXIT_UNEXPECTED = 3


def _prepare_restricted_output_dir(out_dir: Path) -> None:
    """Output holds OCI inventory -- OCIDs, topology, IP addressing, security rules,
    findings. Not secret, but operationally sensitive; owner-only by default rather than
    left at the process umask's default (typically group/world-readable).

    Refuses a pre-existing symlink at this path rather than silently following it and
    writing wherever it points."""

    if out_dir.is_symlink():
        raise RuntimeError(f"refusing to use {out_dir} as an output directory: it is a symlink")
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out_dir, 0o700)  # mkdir's mode is only applied on creation, not to a pre-existing dir


def _write_restricted(path: Path, data: bytes) -> None:
    """Creates the file with owner-only permissions from the moment it exists -- no
    write-then-chmod window where it's briefly at the process umask's default -- and
    refuses to follow a pre-existing symlink at this path."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="oci-drata",
        description="Collect read-only OCI configuration evidence and upsert it to a Drata "
        "Custom Connection.",
    )
    parser.add_argument(
        "--config", default="config.yaml", help="deployment configuration YAML (default: config.yaml)"
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=None,
        help="write sanitized aggregate JSON locally and never contact Drata, overriding "
        "runtime.dryRun",
    )
    parser.add_argument(
        "--out-dir",
        default="out",
        help="directory for dry-run output and the collection report (default: out)",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help=f"sample mode: stop collecting after {TEST_MODE_TIME_BUDGET_SECONDS}s instead of "
        "scanning the whole tenancy, keeping whatever real data was gathered by then. Never "
        "uploads the original/nested snapshot (a partial scan can't honestly claim "
        "tenancy-wide completeness), but the flat-record path uploads normally if "
        "runtime.dryRun is false -- real evidence, for building/testing a Custom Test "
        "against live data.",
    )
    return parser.parse_args(argv)


def _run_independent_collectors(
    signer: TenancySigner, discovery: DiscoveryResult, app_config: AppConfig, retry_policy: RetryPolicy
) -> tuple[
    ComputeCollectionResult,
    StorageCollectionResult,
    NetworkingCollectionResult,
    DatabaseBaseCollectionResult,
    AutonomousDatabaseCollectionResult,
    VpnCollectionResult,
    IdentityCollectionResult,
    ObjectStorageCollectionResult,
    CloudGuardCollectionResult,
    MonitoringCollectionResult,
    LoadBalancerCollectionResult,
    WafCollectionResult,
    KmsVaultCollectionResult,
]:
    services = app_config.oci.services
    jobs: dict[str, Callable[[], Any]] = {
        "compute": lambda: collect_compute(signer, discovery, services, retry_policy=retry_policy),
        "storage": lambda: collect_storage(signer, discovery, services, retry_policy=retry_policy),
        "networking": lambda: collect_networking(signer, discovery, services, retry_policy=retry_policy),
        "database_base": lambda: collect_database_base(signer, discovery, services, retry_policy=retry_policy),
        "autonomous_database": lambda: collect_autonomous_database(
            signer, discovery, services, retry_policy=retry_policy
        ),
        "vpn": lambda: collect_vpn(signer, discovery, services, retry_policy=retry_policy),
        "identity": lambda: collect_identity(signer, discovery, services, retry_policy=retry_policy),
        "object_storage": lambda: collect_object_storage(
            signer, discovery, services, retry_policy=retry_policy
        ),
        "cloud_guard": lambda: collect_cloud_guard(signer, discovery, services, retry_policy=retry_policy),
        "monitoring": lambda: collect_monitoring(signer, discovery, services, retry_policy=retry_policy),
        "load_balancer": lambda: collect_load_balancer(signer, discovery, services, retry_policy=retry_policy),
        "waf": lambda: collect_waf(signer, discovery, services, retry_policy=retry_policy),
        "kms_vault": lambda: collect_kms_vault(signer, discovery, services, retry_policy=retry_policy),
    }
    max_workers = max(1, min(len(jobs), app_config.runtime.max_concurrency))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {name: pool.submit(job) for name, job in jobs.items()}
        results = {name: future.result() for name, future in futures.items()}

    return (
        results["compute"],
        results["storage"],
        results["networking"],
        results["database_base"],
        results["autonomous_database"],
        results["vpn"],
        results["identity"],
        results["object_storage"],
        results["cloud_guard"],
        results["monitoring"],
        results["load_balancer"],
        results["waf"],
        results["kms_vault"],
    )


@dataclasses.dataclass(frozen=True)
class RunResult:
    exit_code: int
    record: dict[str, Any] | None
    snapshot_status: str | None
    uploaded: bool
    report: dict[str, Any]
    # Populated only when drata.flatResourceId is configured; None otherwise.
    flat_records: list[dict[str, Any]] | None = None


def run(app_config: AppConfig, *, dry_run: bool, test_mode: bool = False) -> RunResult:
    started_at = datetime.datetime.now(tz=datetime.UTC)
    logger.info(
        "starting collection run",
        extra={"deployment": app_config.deployment.name, "dryRun": dry_run, "testMode": test_mode},
    )
    logger.info(
        "effective configuration",
        extra={"config": redact_config_for_display(dataclasses.asdict(app_config))},
    )

    signer = build_signer(app_config)
    retry_policy = RetryPolicy()
    if test_mode:
        # Bounding wall-clock time, not compartment count: which compartments actually
        # have data isn't knowable up front, and a small fixed compartment cap can land
        # entirely on empty ones in a large tenancy. Every OCI call goes through
        # paginate()/call_once() (pagination.py), so one deadline on this shared policy
        # bounds discovery and every collector uniformly -- each stops where it is,
        # keeping whatever it already collected, instead of guessing scope up front.
        retry_policy = dataclasses.replace(
            retry_policy, deadline=time.monotonic() + TEST_MODE_TIME_BUDGET_SECONDS
        )

    discovery = discover(signer, app_config, retry_policy=retry_policy)
    (
        compute_result, storage_result, networking_result, database_base_result,
        autonomous_result, vpn_result, identity_result, object_storage_result,
        cloud_guard_result, monitoring_result, load_balancer_result, waf_result,
        kms_vault_result,
    ) = _run_independent_collectors(signer, discovery, app_config, retry_policy)
    exadata_result = detect_exadata(
        signer, discovery, app_config.oci.services,
        database_base_result.db_systems, autonomous_result.autonomous_databases,
        retry_policy=retry_policy,
    )

    completed_at = datetime.datetime.now(tz=datetime.UTC)
    aggregate = build_snapshot(
        app_config,
        discovery=discovery, compute=compute_result, storage=storage_result,
        networking=networking_result, database_base=database_base_result,
        autonomous_database=autonomous_result, exadata=exadata_result, vpn=vpn_result,
        started_at=started_at, completed_at=completed_at,
    )

    schema_result = validate_record(aggregate.record, load_schema())
    size_result = check_payload_size(aggregate.record, app_config.runtime.max_payload_bytes)
    decision = decide_completeness(
        discovery_complete=aggregate.discovery_complete,
        unready_regions=discovery.unready_regions,
        domain_complete=aggregate.domain_complete,
        exadata_detected=aggregate.exadata_detected,
        unresolved_relationship_count=aggregate.unresolved_relationship_count,
        schema_valid=schema_result.valid,
        within_payload_budget=size_result.within_budget,
    )
    aggregate.record["snapshotStatus"] = decision.snapshot_status

    # aggregate.record["manifest"]["operations"] only covers the 7 collectors
    # build_snapshot() consumes -- correct for the nested record's own manifest, but
    # this report describes the whole run: every one of the 13 collectors
    # _run_independent_collectors() actually invokes every time, whether or not
    # build_snapshot() uses its output. Missing 7/13 here would make accessSummary
    # (and every operationsFailed/totalItems counter below) silently blind to
    # whichever opt-in services are enabled.
    all_operations: list[OperationResult] = [
        *discovery.operations,
        *compute_result.operations, *storage_result.operations, *networking_result.operations,
        *database_base_result.operations, *autonomous_result.operations, *vpn_result.operations,
        *exadata_result.operations,
        *identity_result.operations, *object_storage_result.operations,
        *cloud_guard_result.operations, *monitoring_result.operations,
        *load_balancer_result.operations, *waf_result.operations, *kms_vault_result.operations,
    ]
    access_summary = _access_summary(all_operations)
    if access_summary["compartmentsWithAuthGap"]:
        logger.warning(
            "access gap: some compartments returned an auth-shaped failure for at "
            "least one operation -- this API user's OCI policy may not cover this "
            "run's configured scope (oci.compartments.roots/regions.allow). See "
            "collection-report.json's accessSummary for the exact compartment ids.",
            extra={
                "compartmentsSeen": access_summary["compartmentsSeen"],
                "compartmentsWithAuthGap": len(access_summary["compartmentsWithAuthGap"]),
                "compartmentsWithRealData": len(access_summary["compartmentsWithRealData"]),
            },
        )
    report = {
        "deployment": app_config.deployment.name,
        "startedAt": aggregate.record["manifest"]["startedAt"],
        "completedAt": aggregate.record["manifest"]["completedAt"],
        "operationsAttempted": len(all_operations),
        "operationsSucceeded": sum(1 for o in all_operations if o.status == "success"),
        "operationsFailed": sum(1 for o in all_operations if o.status == "failed"),
        "operationsSkipped": sum(1 for o in all_operations if o.status == "skipped"),
        "totalPages": sum(o.page_count for o in all_operations),
        "totalItems": sum(o.item_count for o in all_operations),
        "unresolvedRelationships": aggregate.unresolved_relationship_count,
        "exadataDetected": aggregate.exadata_detected,
        "schemaValid": schema_result.valid,
        "schemaErrors": [e.to_dict() for e in schema_result.errors],
        "payloadBytes": size_result.byte_size,
        "payloadBudgetBytes": size_result.max_bytes,
        "withinPayloadBudget": size_result.within_budget,
        "payloadNearBudget": size_result.near_budget,
        "accessSummary": access_summary,
        "snapshotStatus": decision.snapshot_status,
        "completenessReasons": list(decision.reasons),
        "dryRun": dry_run,
    }

    if not schema_result.valid:
        logger.error("schema validation failed", extra={"errors": report["schemaErrors"]})

    if size_result.near_budget:
        # Early warning before the hard payload ceiling blocks upload outright -- see
        # PayloadSizeResult's docstring for the migration path.
        logger.warning(
            "payload approaching size budget",
            extra={"payloadBytes": size_result.byte_size, "payloadBudgetBytes": size_result.max_bytes},
        )

    uploaded = False
    if dry_run:
        report["uploadDecision"] = "skipped_dry_run"
        logger.info("dry run: skipping Drata upload", extra={"snapshotStatus": decision.snapshot_status})
    elif test_mode:
        # decision.should_upload has no idea only a handful of compartments were ever
        # in scope -- it would happily call this "complete" from what it saw. Uploading
        # that here would claim tenancy-wide coverage on a sample. The flat-record path
        # below is unaffected: each record is standalone evidence, honest regardless of
        # sample size, so --test still uploads real flat records for real testing.
        report["uploadDecision"] = "skipped_test_mode"
        logger.info(
            "test mode: skipping the nested-path upload (sampled compartments, not "
            "tenancy-complete) -- flat records are unaffected",
            extra={"snapshotStatus": decision.snapshot_status},
        )
    elif not decision.should_upload:
        report["uploadDecision"] = "blocked"
        logger.warning(
            "upload blocked: snapshot is not complete",
            extra={"snapshotStatus": decision.snapshot_status, "reasons": decision.reasons},
        )
    else:
        delivery_result = upsert_record(app_config.drata, aggregate.record)
        uploaded = delivery_result.uploaded
        report["uploadDecision"] = "uploaded" if uploaded else "delivery_failed"
        report["deliveryErrorClass"] = delivery_result.error_class
        if uploaded:
            logger.info(
                "drata upload succeeded",
                # "created" is a reserved LogRecord attribute (record creation timestamp) --
                # extra={"created": ...} raises KeyError in logging internals whenever this
                # log call is actually enabled, so it's named recordCreated here instead.
                extra={"recordCreated": delivery_result.created, "attempts": delivery_result.attempts},
            )
        else:
            logger.error(
                "drata upload failed; last known-good record left untouched",
                extra={"errorClass": delivery_result.error_class, "attempts": delivery_result.attempts},
            )

    flat_records: list[dict[str, Any]] | None = None
    if app_config.drata.flat_resource_id is not None:
        flat_records = _run_flat_records(
            app_config, flat_resource_id=app_config.drata.flat_resource_id,
            discovery=discovery, compute=compute_result,
            networking=networking_result, autonomous_database=autonomous_result,
            identity=identity_result, object_storage=object_storage_result,
            cloud_guard=cloud_guard_result, monitoring=monitoring_result,
            load_balancer=load_balancer_result, waf=waf_result,
            kms_vault=kms_vault_result,
            completed_at=completed_at,
            dry_run=dry_run, report=report,
        )

    exit_code = EXIT_OK if (dry_run and decision.snapshot_status != "failed") or uploaded else EXIT_BLOCKED
    return RunResult(
        exit_code=exit_code,
        record=aggregate.record,
        snapshot_status=decision.snapshot_status,
        uploaded=uploaded,
        report=report,
        flat_records=flat_records,
    )


def _run_flat_records(
    app_config: AppConfig,
    *,
    flat_resource_id: int,
    discovery: DiscoveryResult,
    compute: ComputeCollectionResult,
    networking: NetworkingCollectionResult,
    autonomous_database: AutonomousDatabaseCollectionResult,
    identity: IdentityCollectionResult,
    object_storage: ObjectStorageCollectionResult,
    cloud_guard: CloudGuardCollectionResult,
    monitoring: MonitoringCollectionResult,
    load_balancer: LoadBalancerCollectionResult,
    waf: WafCollectionResult,
    kms_vault: KmsVaultCollectionResult,
    completed_at: datetime.datetime,
    dry_run: bool,
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Builds and (outside dry-run) uploads flat records to drata.flatResourceId,
    additive alongside the nested-schema path above. Mutates ``report`` in place
    with a "flatRecords" key; never affects the nested path's own
    uploadDecision/exit_code."""

    flat_result = build_flat_records(
        decisions=app_config.decisions, discovery=discovery, compute=compute,
        autonomous_database=autonomous_database, identity=identity,
        object_storage=object_storage, cloud_guard=cloud_guard, monitoring=monitoring,
        load_balancer=load_balancer, waf=waf, kms_vault=kms_vault,
        networking=networking, completed_at=completed_at,
    )
    flat_schema = load_flat_schema()
    flat_schema_valid = all(validate_record(r, flat_schema).valid for r in flat_result.records)
    flat_complete = (
        flat_result.discovery_complete
        and all(flat_result.domain_complete.values())
        and flat_result.unresolved_relationship_count == 0
    )

    # A domain reporting domainComplete=true tells you nothing failed -- it looks
    # identical whether the service is disabled by config (services.identity: false)
    # or ran and genuinely found zero resources. domainSkipped answers the first
    # question directly, so recordCount:0 doesn't read as a mystery: check this before
    # suspecting a collector bug (see the incident this was added from, README §7).
    domain_skipped = {
        "compute": _domain_all_skipped(compute.operations),
        "networking": _domain_all_skipped(networking.operations),
        "autonomousDatabase": _domain_all_skipped(autonomous_database.operations),
        "identity": _domain_all_skipped(identity.operations),
        "objectStorage": _domain_all_skipped(object_storage.operations),
        "cloudGuard": _domain_all_skipped(cloud_guard.operations),
        "monitoring": _domain_all_skipped(monitoring.operations),
        "loadBalancer": _domain_all_skipped(load_balancer.operations),
        "waf": _domain_all_skipped(waf.operations),
        "kmsVault": _domain_all_skipped(kms_vault.operations),
    }

    flat_report: dict[str, Any] = {
        "recordCount": len(flat_result.records),
        "schemaValid": flat_schema_valid,
        "domainComplete": flat_result.domain_complete,
        "domainSkipped": domain_skipped,
        "discoveryComplete": flat_result.discovery_complete,
        "excludedByLifecycle": flat_result.excluded_counts,
        "unresolvedRelationships": flat_result.unresolved_relationship_count,
    }
    if not flat_schema_valid:
        logger.error("flat-record schema validation failed")
    if flat_result.records == [] and not all(domain_skipped.values()):
        logger.warning(
            "flat-record path collected zero records from at least one enabled "
            "domain -- check domainSkipped/excludedByLifecycle in the report before "
            "assuming a collector bug: this can legitimately mean every resource in "
            "scope is terminated/deleted, or the configured compartment scope "
            "genuinely has nothing of these types (see accessSummary for where this "
            "API user's policy actually has access).",
            extra={"domainSkipped": domain_skipped, "excludedByLifecycle": flat_result.excluded_counts},
        )

    if dry_run:
        flat_report["uploadDecision"] = "skipped_dry_run"
    elif not (flat_schema_valid and flat_complete):
        reasons = []
        if not flat_schema_valid:
            reasons.append("schema validation failed")
        if not (flat_result.discovery_complete and all(flat_result.domain_complete.values())):
            reasons.append("compute/networking collection incomplete")
        if flat_result.unresolved_relationship_count:
            reasons.append("unresolved relationships")
        flat_report["uploadDecision"] = "blocked"
        flat_report["blockedReasons"] = reasons
        logger.warning("flat-record upload blocked", extra={"reasons": reasons})
    else:
        flat_drata_config = dataclasses.replace(app_config.drata, resource_id=flat_resource_id)
        delivery_results = upsert_records(flat_drata_config, flat_result.records)
        flat_uploaded = bool(delivery_results) and all(r.uploaded for r in delivery_results)
        flat_report["uploadDecision"] = "uploaded" if flat_uploaded else "delivery_failed"
        flat_report["batchesAttempted"] = len(delivery_results)
        flat_report["batchesSucceeded"] = sum(1 for r in delivery_results if r.uploaded)
        if flat_uploaded:
            logger.info("flat-record upload succeeded", extra={"records": len(flat_result.records)})
        else:
            logger.error("flat-record upload failed", extra={"records": len(flat_result.records)})

    report["flatRecords"] = flat_report
    return flat_result.records


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        app_config = load_config(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    configure_logging(app_config.runtime.log_level)
    dry_run = app_config.runtime.dry_run if args.dry_run is None else args.dry_run

    try:
        result = run(app_config, dry_run=dry_run, test_mode=args.test)
    except AuthError as exc:
        logger.error("authentication failed", extra={"error": str(exc)})
        return EXIT_CONFIG_ERROR
    except ConfigError as exc:
        logger.error("configuration error", extra={"error": str(exc)})
        return EXIT_CONFIG_ERROR
    except Exception:
        logger.exception("unexpected failure during collection run")
        return EXIT_UNEXPECTED

    out_dir = Path(args.out_dir)
    _prepare_restricted_output_dir(out_dir)
    _write_restricted(
        out_dir / "collection-report.json",
        json.dumps(result.report, indent=2, sort_keys=True).encode("utf-8"),
    )
    if dry_run and result.record is not None:
        _write_restricted(out_dir / "snapshot.json", serialize_deterministic(result.record))
    if dry_run and result.flat_records is not None:
        _write_restricted(
            out_dir / "flat-records.json",
            json.dumps(result.flat_records, indent=2, sort_keys=True).encode("utf-8"),
        )

    print(json.dumps(result.report, indent=2, sort_keys=True))
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
