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
    operations_complete,
    paginate,
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

    operations: list[OperationResult] = []
    autonomous_databases: list[Any] = []

    for region in discovery.approved_regions:
        client = regional_client(oci.database.DatabaseClient, signer, region=region)

        for compartment_id in discovery.approved_compartment_ids:
            op = paginate(
                service="database",
                operation="list_autonomous_databases",
                call=client.list_autonomous_databases,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(op)
            autonomous_databases.extend(stamp_region(op.items, region))

    return AutonomousDatabaseCollectionResult(
        autonomous_databases=autonomous_databases,
        operations=operations,
    )
