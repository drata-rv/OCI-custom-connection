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
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from oci_drata.collection.compute import ComputeCollectionResult, collect_compute
from oci_drata.collection.database_autonomous import (
    AutonomousDatabaseCollectionResult,
    collect_autonomous_database,
)
from oci_drata.collection.database_base import DatabaseBaseCollectionResult, collect_database_base
from oci_drata.collection.discovery import DiscoveryResult, discover
from oci_drata.collection.exadata_detection import detect_exadata
from oci_drata.collection.networking import NetworkingCollectionResult, collect_networking
from oci_drata.collection.storage import StorageCollectionResult, collect_storage
from oci_drata.collection.vpn import VpnCollectionResult, collect_vpn
from oci_drata.config import AppConfig, ConfigError, load_config, redact_config_for_display
from oci_drata.delivery.drata import upsert_record
from oci_drata.logging import configure_logging
from oci_drata.oci_auth import AuthError, TenancySigner, build_signer
from oci_drata.pagination import RetryPolicy
from oci_drata.transform.aggregate import build_snapshot
from oci_drata.validation.completeness import decide_completeness
from oci_drata.validation.schema import load_schema, validate_record
from oci_drata.validation.size import check_payload_size, serialize_deterministic

logger = logging.getLogger(__name__)

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
    )


@dataclasses.dataclass(frozen=True)
class RunResult:
    exit_code: int
    record: dict[str, Any] | None
    snapshot_status: str | None
    uploaded: bool
    report: dict[str, Any]


def run(app_config: AppConfig, *, dry_run: bool) -> RunResult:
    started_at = datetime.datetime.now(tz=datetime.UTC)
    logger.info(
        "starting collection run",
        extra={"deployment": app_config.deployment.name, "dryRun": dry_run},
    )
    logger.info(
        "effective configuration",
        extra={"config": redact_config_for_display(dataclasses.asdict(app_config))},
    )

    signer = build_signer(app_config)
    retry_policy = RetryPolicy()

    discovery = discover(signer, app_config, retry_policy=retry_policy)
    (
        compute_result, storage_result, networking_result, database_base_result,
        autonomous_result, vpn_result,
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

    all_operations = aggregate.record["manifest"]["operations"]
    report = {
        "deployment": app_config.deployment.name,
        "startedAt": aggregate.record["manifest"]["startedAt"],
        "completedAt": aggregate.record["manifest"]["completedAt"],
        "operationsAttempted": len(all_operations),
        "operationsSucceeded": sum(1 for o in all_operations if o["status"] == "success"),
        "operationsFailed": sum(1 for o in all_operations if o["status"] == "failed"),
        "operationsSkipped": sum(1 for o in all_operations if o["status"] == "skipped"),
        "totalPages": sum(o["pageCount"] for o in all_operations),
        "totalItems": sum(o["itemCount"] for o in all_operations),
        "unresolvedRelationships": aggregate.unresolved_relationship_count,
        "exadataDetected": aggregate.exadata_detected,
        "schemaValid": schema_result.valid,
        "schemaErrors": [e.to_dict() for e in schema_result.errors],
        "payloadBytes": size_result.byte_size,
        "payloadBudgetBytes": size_result.max_bytes,
        "withinPayloadBudget": size_result.within_budget,
        "payloadNearBudget": size_result.near_budget,
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
                extra={"created": delivery_result.created, "attempts": delivery_result.attempts},
            )
        else:
            logger.error(
                "drata upload failed; last known-good record left untouched",
                extra={"errorClass": delivery_result.error_class, "attempts": delivery_result.attempts},
            )

    exit_code = EXIT_OK if (dry_run and decision.snapshot_status != "failed") or uploaded else EXIT_BLOCKED
    return RunResult(
        exit_code=exit_code,
        record=aggregate.record,
        snapshot_status=decision.snapshot_status,
        uploaded=uploaded,
        report=report,
    )


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
        result = run(app_config, dry_run=dry_run)
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

    print(json.dumps(result.report, indent=2, sort_keys=True))
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
