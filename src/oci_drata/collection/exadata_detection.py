"""Exadata detection (spec 5.7).

Minimal, no-drill-down existence check: any of a database domain shape
(``DbSystemSummary.shape`` prefixed ``"Exadata"``), a dedicated Autonomous
Database (always Exadata Infrastructure-backed), or any Exadata-family
infrastructure resource existing at all in an approved compartment is enough
to mark the database domain incomplete -- per spec, this module must never
claim complete managed-database coverage once any of these is true.

``db_systems``/``autonomous_databases`` are the already-collected results
from :mod:`database_base`/:mod:`database_autonomous`; this module makes no
``list_db_systems``/``list_autonomous_databases`` calls of its own.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import OperationResult, RetryPolicy, operations_complete, paginate

_EXADATA_SHAPE_PREFIX = "Exadata"


@dataclasses.dataclass
class ExadataDetectionResult:
    detected: bool
    reasons: list[str]
    affected_db_system_ids: tuple[str, ...]
    affected_autonomous_database_ids: tuple[str, ...]
    cloud_vm_clusters: list[Any]
    exadata_infrastructures: list[Any]
    cloud_exadata_infrastructures: list[Any]
    autonomous_exadata_infrastructures: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> ExadataDetectionResult:
    return ExadataDetectionResult(
        detected=False,
        reasons=[],
        affected_db_system_ids=(),
        affected_autonomous_database_ids=(),
        cloud_vm_clusters=[],
        exadata_infrastructures=[],
        cloud_exadata_infrastructures=[],
        autonomous_exadata_infrastructures=[],
        operations=[
            OperationResult(
                service="database",
                operation="collect",
                region=None,
                compartment_id=None,
                status="skipped",
                page_count=0,
                item_count=0,
                request_ids=[],
            )
        ],
    )


def detect_exadata(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    db_systems: list[Any],
    autonomous_databases: list[Any],
    *,
    retry_policy: RetryPolicy | None = None,
) -> ExadataDetectionResult:
    if not services.exadata_detection:
        return _skip_result()

    operations: list[OperationResult] = []
    cloud_vm_clusters: list[Any] = []
    exadata_infrastructures: list[Any] = []
    cloud_exadata_infrastructures: list[Any] = []
    autonomous_exadata_infrastructures: list[Any] = []

    for region in discovery.approved_regions:
        client = regional_client(oci.database.DatabaseClient, signer, region=region)

        for compartment_id in discovery.approved_compartment_ids:
            vm_cluster_op = paginate(
                service="database",
                operation="list_cloud_vm_clusters",
                call=client.list_cloud_vm_clusters,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(vm_cluster_op)
            cloud_vm_clusters.extend(vm_cluster_op.items)

            exadata_infra_op = paginate(
                service="database",
                operation="list_exadata_infrastructures",
                call=client.list_exadata_infrastructures,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(exadata_infra_op)
            exadata_infrastructures.extend(exadata_infra_op.items)

            cloud_exadata_infra_op = paginate(
                service="database",
                operation="list_cloud_exadata_infrastructures",
                call=client.list_cloud_exadata_infrastructures,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(cloud_exadata_infra_op)
            cloud_exadata_infrastructures.extend(cloud_exadata_infra_op.items)

            autonomous_exadata_infra_op = paginate(
                service="database",
                operation="list_autonomous_exadata_infrastructures",
                call=client.list_autonomous_exadata_infrastructures,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(autonomous_exadata_infra_op)
            autonomous_exadata_infrastructures.extend(autonomous_exadata_infra_op.items)

    reasons: list[str] = []
    affected_db_system_ids: list[str] = []
    for db_system in db_systems:
        shape = getattr(db_system, "shape", None)
        if isinstance(shape, str) and shape.startswith(_EXADATA_SHAPE_PREFIX):
            affected_db_system_ids.append(db_system.id)
            reasons.append(f"db_system {db_system.id} has Exadata shape {shape!r}")

    affected_autonomous_database_ids: list[str] = []
    for adb in autonomous_databases:
        if getattr(adb, "is_dedicated", None) is True:
            affected_autonomous_database_ids.append(adb.id)
            reasons.append(
                f"autonomous_database {adb.id} is dedicated (runs on Exadata Infrastructure)"
            )

    if cloud_vm_clusters:
        reasons.append(
            f"{len(cloud_vm_clusters)} cloud VM cluster(s) present (Exadata Cloud Service)"
        )
    if exadata_infrastructures:
        reasons.append(
            f"{len(exadata_infrastructures)} Exadata infrastructure resource(s) present "
            f"(Cloud@Customer/on-premises)"
        )
    if cloud_exadata_infrastructures:
        reasons.append(
            f"{len(cloud_exadata_infrastructures)} cloud Exadata infrastructure resource(s) "
            f"present (Exadata Cloud Service Gen 2)"
        )
    if autonomous_exadata_infrastructures:
        reasons.append(
            f"{len(autonomous_exadata_infrastructures)} autonomous Exadata infrastructure "
            f"resource(s) present (legacy)"
        )

    return ExadataDetectionResult(
        detected=bool(reasons),
        reasons=reasons,
        affected_db_system_ids=tuple(affected_db_system_ids),
        affected_autonomous_database_ids=tuple(affected_autonomous_database_ids),
        cloud_vm_clusters=cloud_vm_clusters,
        exadata_infrastructures=exadata_infrastructures,
        cloud_exadata_infrastructures=cloud_exadata_infrastructures,
        autonomous_exadata_infrastructures=autonomous_exadata_infrastructures,
        operations=operations,
    )
