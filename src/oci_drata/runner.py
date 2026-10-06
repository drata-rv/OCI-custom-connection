"""One collection run: discover -> collect -> build flat records -> gate per domain -> deliver.

No argument parsing, exit handling, or local files: cli.py wraps this, and any other entry
point can too -- ``run()`` needs only an ``AppConfig``. Independent collectors run
concurrently (bounded by ``runtime.maxConcurrency``).
"""

from __future__ import annotations

import dataclasses
import datetime
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from oci_drata.collection.cloud_guard import collect_cloud_guard
from oci_drata.collection.compute import collect_compute
from oci_drata.collection.database_autonomous import collect_autonomous_database
from oci_drata.collection.database_base import collect_database_base
from oci_drata.collection.discovery import DiscoveryResult, discover
from oci_drata.collection.identity import collect_identity
from oci_drata.collection.kms_vault import collect_kms_vault
from oci_drata.collection.load_balancer import collect_load_balancer
from oci_drata.collection.monitoring import collect_monitoring
from oci_drata.collection.networking import collect_networking
from oci_drata.collection.object_storage import collect_object_storage
from oci_drata.collection.storage import collect_storage
from oci_drata.collection.vpn import collect_vpn
from oci_drata.collection.waf import collect_waf
from oci_drata.config import AppConfig, redact_config_for_display
from oci_drata.delivery.drata import delete_records, upsert_records
from oci_drata.oci_auth import TenancySigner, build_signer
from oci_drata.pagination import DEADLINE_EXCEEDED_ERROR_CODE, OperationResult, RetryPolicy
from oci_drata.transform import normalize
from oci_drata.transform.aggregate import (
    EVIDENCE_TYPE_REQUIRED_DOMAINS,
    FlatRecordsResult,
    build_flat_records,
)
from oci_drata.validation.schema import load_flat_schema, validate_record
from oci_drata.validation.size import serialize_deterministic

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_CONFIG_ERROR = 2
EXIT_UNEXPECTED = 3

# --test bounds wall-clock time, not compartment count (RetryPolicy.deadline, pagination.py):
# data distribution across compartments is unknowable up front, so a fixed cap could land
# entirely on empty ones.
TEST_MODE_TIME_BUDGET_SECONDS = 30

# Services with a documented per-tenancy rate limit (10 requests/s for Monitoring alarm reads
# and KMS reads) get a small in-flight cap of their own, on top of runtime.maxConcurrency.
_RATE_LIMITED_SERVICE_SLOTS = {"monitoring": 2, "kms_vault": 2, "kms_management": 2}

# Largest number of threads one fan-out stage starts (13 collectors can each run a stage).
_MAX_FANOUT = 32

# OCI error codes meaning "no access here", distinct from a retried transient failure or
# a --test deadline cutoff (pagination.py). Grouped by compartment to surface where
# configured scope (oci.compartments.roots/regions.allow) exceeds this API user's policy.
_AUTH_GAP_ERROR_CODES = frozenset({"NotAuthorizedOrNotFound", "NotAuthenticated"})

# Collector result name (also build_flat_records' keyword) -> the domain name used in the
# report and in EVIDENCE_TYPE_REQUIRED_DOMAINS.
_DOMAIN_BY_COLLECTOR = {
    "compute": "compute",
    "storage": "blockStorage",
    "networking": "networking",
    "database_base": "baseDatabase",
    "autonomous_database": "autonomousDatabase",
    "vpn": "vpn",
    "identity": "identity",
    "object_storage": "objectStorage",
    "cloud_guard": "cloudGuard",
    "monitoring": "monitoring",
    "load_balancer": "loadBalancer",
    "waf": "waf",
    "kms_vault": "kmsVault",
}


@dataclasses.dataclass(frozen=True)
class RunResult:
    exit_code: int
    uploaded: bool
    report: dict[str, Any]
    records: list[dict[str, Any]]


def _domain_all_skipped(operations: list[OperationResult]) -> bool:
    """True only when every recorded operation is the synthetic status="skipped" marker
    a disabled collector emits -- config-disabled, not merely empty. An empty operations
    list doesn't count as skipped."""

    return bool(operations) and all(op.status == "skipped" for op in operations)


def _log_operation_failure_summary(operations: list[OperationResult]) -> None:
    """One aggregated WARNING per distinct (service, operation, error_code), instead of
    the per-call DEBUG log in pagination.py repeating once per compartment/region -- a
    tenancy with many compartments would otherwise flood the log with dozens of
    identical lines for the same underlying gap."""

    counts: dict[tuple[str, str, str | None], int] = {}
    for op in operations:
        if op.status not in ("failed", "unsupported"):
            continue
        key = (op.service, op.operation, op.error_code)
        counts[key] = counts.get(key, 0) + 1
    for (service, operation, error_code), occurrences in sorted(counts.items()):
        logger.warning(
            "operation failed after retry exhaustion",
            extra={
                "service": service, "operation": operation,
                "error_code": error_code, "occurrences": occurrences,
            },
        )


def _access_summary(operations: list[OperationResult]) -> dict[str, Any]:
    """``operations`` must be every OperationResult from every collector this run invoked.
    Groups them by compartment into auth gaps vs. real data."""

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


def _build_policy(app_config: AppConfig, deadline: float | None) -> RetryPolicy:
    """The one retry/concurrency/deadline policy every OCI call of the run shares."""

    max_in_flight = app_config.runtime.max_concurrency
    return RetryPolicy(
        deadline=deadline,
        call_slots=threading.BoundedSemaphore(max_in_flight),
        service_slots={name: threading.BoundedSemaphore(n) for name, n in _RATE_LIMITED_SERVICE_SLOTS.items()},
        fanout=min(max_in_flight, _MAX_FANOUT),
    )


def _run_collectors(
    signer: TenancySigner, discovery: DiscoveryResult, app_config: AppConfig, retry_policy: RetryPolicy
) -> dict[str, Any]:
    """Every collector, concurrently. Result keys match build_flat_records' keyword names."""

    services = app_config.oci.services
    collectors: dict[str, Callable[..., Any]] = {
        "compute": collect_compute,
        "storage": collect_storage,
        "networking": collect_networking,
        "database_base": collect_database_base,
        "autonomous_database": collect_autonomous_database,
        "vpn": collect_vpn,
        "identity": collect_identity,
        "object_storage": collect_object_storage,
        "cloud_guard": collect_cloud_guard,
        "monitoring": collect_monitoring,
        "load_balancer": collect_load_balancer,
        "waf": collect_waf,
        "kms_vault": collect_kms_vault,
    }
    # One thread per collector: they only orchestrate; the shared policy's request slots are
    # what bound the actual OCI concurrency.
    with ThreadPoolExecutor(max_workers=len(collectors)) as pool:
        futures = {
            name: pool.submit(collect, signer, discovery, services, retry_policy=retry_policy)
            for name, collect in collectors.items()
        }
        return {name: future.result() for name, future in futures.items()}


@dataclasses.dataclass(frozen=True)
class _Gate:
    deliverable_records: list[dict[str, Any]]
    deliverable_domains: set[str]
    domains_withheld: list[str]
    schema_invalid_count: int
    records_withheld_count: int


def _gate(flat_result: FlatRecordsResult) -> _Gate:
    """Per-domain gate, not tenancy-wide all-or-nothing: a domain that failed to collect
    this run withholds only its own evidenceTypes (see EVIDENCE_TYPE_REQUIRED_DOMAINS), so
    one bad compartment/region doesn't zero out every other domain's delivery. A dangling
    vnic/storage join only affects instance evidence, so it's folded into compute's own
    completeness rather than a separate blanket gate. Discovery failing is more
    fundamental than any one domain -- nothing is trusted deliverable then."""

    effective_domain_complete = dict(flat_result.domain_complete)
    if flat_result.unresolved_relationship_count:
        effective_domain_complete["compute"] = False
    deliverable_domains = (
        {d for d, ok in effective_domain_complete.items() if ok} if flat_result.discovery_complete else set()
    )

    flat_schema = load_flat_schema()
    deliverable_records: list[dict[str, Any]] = []
    schema_invalid_count = 0
    records_withheld_count = 0
    for record in flat_result.records:
        if not validate_record(record, flat_schema).valid:
            schema_invalid_count += 1
            continue
        required_domains = EVIDENCE_TYPE_REQUIRED_DOMAINS[record["evidenceType"]]
        if all(domain in deliverable_domains for domain in required_domains):
            deliverable_records.append(record)
        else:
            records_withheld_count += 1

    return _Gate(
        deliverable_records=deliverable_records,
        deliverable_domains=deliverable_domains,
        domains_withheld=sorted(set(effective_domain_complete) - deliverable_domains),
        schema_invalid_count=schema_invalid_count,
        records_withheld_count=records_withheld_count,
    )


def _deliver(
    app_config: AppConfig,
    gate: _Gate,
    flat_result: FlatRecordsResult,
    *,
    test_mode: bool,
    deadline: float | None,
) -> tuple[bool, dict[str, Any]]:
    """Upserts the deliverable records, then deletes stale ones. Returns (uploaded, report
    fields to merge).

    Collection has already succeeded and produced real records by this point -- possibly
    after a long, expensive run across many compartments/regions. An unexpected failure
    anywhere in delivery/cleanup (a bad secret, a network surprise, a bug) must not
    un-return that work: caught broadly and folded into the report instead of raised."""

    report: dict[str, Any] = {}
    try:
        delivery_results = upsert_records(
            app_config.drata,
            gate.deliverable_records,
            max_payload_bytes=app_config.runtime.max_payload_bytes,
            deadline=deadline,
        )
        uploaded = bool(delivery_results) and all(r.uploaded for r in delivery_results)
        report["batchesAttempted"] = len(delivery_results)
        report["batchesSucceeded"] = sum(1 for r in delivery_results if r.uploaded)
        error_classes = sorted({r.error_class for r in delivery_results if r.error_class})
        if error_classes:
            report["deliveryErrorClasses"] = error_classes
        if not uploaded:
            report["uploadDecision"] = "delivery_failed"
            logger.error("upload failed", extra={"errorClasses": error_classes})
            return False, report

        report["uploadDecision"] = "uploaded_partial" if gate.domains_withheld else "uploaded"
        logger.info(
            "upload succeeded",
            extra={"records": len(gate.deliverable_records), "domainsWithheld": gate.domains_withheld},
        )
        if gate.domains_withheld:
            logger.warning(
                "some domains withheld this run -- their prior records were left "
                "untouched, not deleted or overwritten",
                extra={"domainsWithheld": gate.domains_withheld},
            )

        # Cleanup only runs for domains that actually delivered this run -- deleting a stale
        # id from a withheld domain would be a guess, not a confirmed absence. Skipped in
        # --test: a sampled run's absences aren't confirmed deletions.
        if not test_mode:
            delete_ids = [
                record_id
                for evidence_type, ids in flat_result.excluded_ids.items()
                for record_id in ids
                if all(d in gate.deliverable_domains for d in EVIDENCE_TYPE_REQUIRED_DOMAINS[evidence_type])
            ]
            if delete_ids:
                delete_results = delete_records(app_config.drata, delete_ids, deadline=deadline)
                failed_deletes = [r for r in delete_results if not r.uploaded]
                report["staleRecordsDeleted"] = len(delete_results) - len(failed_deletes)
                report["staleRecordDeleteFailures"] = len(failed_deletes)
                if failed_deletes:
                    logger.warning(
                        "some stale-record deletes failed -- will retry next run",
                        extra={"failures": len(failed_deletes)},
                    )
        return True, report
    except Exception as exc:
        report["uploadDecision"] = "delivery_failed"
        report["deliveryError"] = f"{type(exc).__name__}: {exc}"
        logger.exception("upload/cleanup failed unexpectedly -- collected data is not lost")
        return False, report


def run(
    app_config: AppConfig,
    *,
    dry_run: bool,
    test_mode: bool = False,
    deadline: float | None = None,
    delivery_deadline: float | None = None,
) -> RunResult:
    """``deadline`` / ``delivery_deadline`` are ``time.monotonic()`` timestamps. Collection
    stops starting new OCI calls at ``deadline`` -- a domain it cut short is withheld, not
    delivered partial -- and delivery stops sending at ``delivery_deadline``. A host with a
    hard time limit (AWS Lambda) sets both so the run ends by itself, with a report."""

    started_at = datetime.datetime.now(tz=datetime.UTC)
    started_monotonic = time.monotonic()
    logger.info(
        "starting collection run",
        extra={"deployment": app_config.deployment.name, "dryRun": dry_run, "testMode": test_mode},
    )
    logger.info(
        "effective configuration",
        extra={"config": redact_config_for_display(dataclasses.asdict(app_config))},
    )

    signer = build_signer(app_config)
    if test_mode:
        test_deadline = time.monotonic() + TEST_MODE_TIME_BUDGET_SECONDS
        deadline = test_deadline if deadline is None else min(deadline, test_deadline)
    # Every OCI call routes through paginate()/call_once() (pagination.py), so one deadline on
    # this shared policy bounds wall-clock time uniformly across discovery and all collectors.
    retry_policy = _build_policy(app_config, deadline)

    discovery = discover(signer, app_config, retry_policy=retry_policy)
    results = _run_collectors(signer, discovery, app_config, retry_policy)

    completed_at = datetime.datetime.now(tz=datetime.UTC)
    flat_result = build_flat_records(
        decisions=app_config.decisions, discovery=discovery, completed_at=completed_at, **results
    )

    all_operations: list[OperationResult] = [
        *discovery.operations,
        *(op for result in results.values() for op in result.operations),
    ]
    _log_operation_failure_summary(all_operations)
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

    # domainComplete=true doesn't distinguish a config-disabled service
    # (services.identity: false) from one that ran and found zero resources.
    # domainSkipped answers that, so recordCount:0 isn't a mystery (README §7).
    domain_skipped = {
        _DOMAIN_BY_COLLECTOR[name]: _domain_all_skipped(result.operations) for name, result in results.items()
    }

    gate = _gate(flat_result)
    schema_valid = gate.schema_invalid_count == 0
    if not schema_valid:
        logger.error("flat-record schema validation failed", extra={"invalidCount": gate.schema_invalid_count})
    if flat_result.records == [] and not all(domain_skipped.values()):
        logger.warning(
            "collected zero records from at least one enabled domain -- check "
            "domainSkipped/excludedByLifecycle in the report before assuming a collector "
            "bug: this can legitimately mean every resource in scope is "
            "terminated/deleted, or the configured compartment scope genuinely has "
            "nothing of these types (see accessSummary for where this API user's "
            "policy actually has access).",
            extra={"domainSkipped": domain_skipped, "excludedByLifecycle": flat_result.excluded_counts},
        )

    report: dict[str, Any] = {
        "deployment": app_config.deployment.name,
        "startedAt": normalize.normalize_timestamp(started_at),
        "completedAt": normalize.normalize_timestamp(completed_at),
        "operationsAttempted": len(all_operations),
        "operationsSucceeded": sum(1 for o in all_operations if o.status == "success"),
        "operationsFailed": sum(1 for o in all_operations if o.status == "failed"),
        "operationsSkipped": sum(1 for o in all_operations if o.status == "skipped"),
        "totalPages": sum(o.page_count for o in all_operations),
        "totalItems": sum(o.item_count for o in all_operations),
        "accessSummary": access_summary,
        "dryRun": dry_run,
        "recordCount": len(flat_result.records),
        "recordCountDelivered": len(gate.deliverable_records),
        "recordCountWithheld": gate.records_withheld_count,
        "totalRecordBytes": sum(len(serialize_deterministic(r)) for r in flat_result.records),
        "schemaValid": schema_valid,
        "schemaInvalidCount": gate.schema_invalid_count,
        "domainComplete": flat_result.domain_complete,
        "domainsWithheld": gate.domains_withheld,
        "domainSkipped": domain_skipped,
        "discoveryComplete": flat_result.discovery_complete,
        "excludedByLifecycle": flat_result.excluded_counts,
        "unresolvedRelationships": flat_result.unresolved_relationship_count,
        "deadlineExceeded": any(op.error_code == DEADLINE_EXCEEDED_ERROR_CODE for op in all_operations),
    }

    uploaded = False
    if dry_run:
        report["uploadDecision"] = "skipped_dry_run"
        logger.info("dry run: skipping Drata upload")
    elif not gate.deliverable_records:
        report["uploadDecision"] = "blocked"
        reasons = []
        if not schema_valid:
            reasons.append("schema validation failed")
        if not flat_result.discovery_complete:
            reasons.append("discovery incomplete")
        elif gate.domains_withheld:
            reasons.append(f"no domain ready to deliver this run: {gate.domains_withheld}")
        report["blockedReasons"] = reasons
        logger.warning("upload blocked: nothing deliverable this run", extra={"reasons": reasons})
    else:
        uploaded, delivery_report = _deliver(
            app_config, gate, flat_result, test_mode=test_mode, deadline=delivery_deadline
        )
        report.update(delivery_report)
    report["elapsedSeconds"] = round(time.monotonic() - started_monotonic, 1)

    return RunResult(
        exit_code=EXIT_OK if dry_run or uploaded else EXIT_BLOCKED,
        uploaded=uploaded,
        report=report,
        records=flat_result.records,
    )
