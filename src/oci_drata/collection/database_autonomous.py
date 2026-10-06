"""Autonomous Database collection. ``AutonomousDatabaseSummary`` is full-fidelity (KMS key,
public endpoint, lifecycle), so no per-database enrichment call is made.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import (
    OperationResult,
    RetryPolicy,
    list_in_scope,
    operations_complete,
    stamp_region,
)


@dataclasses.dataclass
class AutonomousDatabaseCollectionResult:
    autonomous_databases: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> AutonomousDatabaseCollectionResult:
    return AutonomousDatabaseCollectionResult(
        autonomous_databases=[],
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


def collect_autonomous_database(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> AutonomousDatabaseCollectionResult:
    if not services.autonomous_database:
        return _skip_result()

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    clients = {r: regional_client(oci.database.DatabaseClient, signer, region=r) for r in discovery.approved_regions}

    (adb_ops,) = list_in_scope(policy, scope, [("database", "list_autonomous_databases", clients)])
    autonomous_databases: list[Any] = []
    for (region, _), op in zip(scope, adb_ops, strict=True):
        autonomous_databases.extend(stamp_region(op.items, region))

    return AutonomousDatabaseCollectionResult(autonomous_databases=autonomous_databases, operations=list(adb_ops))
