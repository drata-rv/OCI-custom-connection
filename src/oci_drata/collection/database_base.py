"""Base Database Service collection: list_db_systems -> list_db_homes -> list_databases
-> list_data_guard_associations. Summary objects are full-fidelity; no get_* enrichment
call is made.
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
    run_concurrently,
    stamp_region,
)

# Per-item fan-out concurrency, independent of runtime.maxConcurrency (see
# pagination.run_concurrently).
_PER_ITEM_CONCURRENCY = 8


@dataclasses.dataclass
class DatabaseBaseCollectionResult:
    db_systems: list[Any]
    db_homes: list[Any]
    databases: list[Any]
    data_guard_associations: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> DatabaseBaseCollectionResult:
    return DatabaseBaseCollectionResult(
        db_systems=[],
        db_homes=[],
        databases=[],
        data_guard_associations=[],
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


def collect_database_base(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> DatabaseBaseCollectionResult:
    if not services.base_database:
        return _skip_result()

    operations: list[OperationResult] = []
    db_systems: list[Any] = []
    db_homes: list[Any] = []
    databases: list[Any] = []
    data_guard_associations: list[Any] = []

    for region in discovery.approved_regions:
        client = regional_client(oci.database.DatabaseClient, signer, region=region)

        region_db_systems: list[Any] = []
        for compartment_id in discovery.approved_compartment_ids:
            op = paginate(
                service="database",
                operation="list_db_systems",
                call=client.list_db_systems,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(op)
            region_db_systems.extend(stamp_region(op.items, region))
        db_systems.extend(region_db_systems)

        def _list_db_homes(
            db_system: Any, *, _client: Any = client, _region: str = region
        ) -> tuple[OperationResult, list[Any]]:
            op = paginate(
                service="database",
                operation="list_db_homes",
                call=_client.list_db_homes,
                region=_region,
                compartment_id=db_system.compartment_id,
                db_system_id=db_system.id,
                retry_policy=retry_policy,
            )
            return op, stamp_region(op.items, _region)

        region_db_homes: list[Any] = []
        for op, items in run_concurrently(
            region_db_systems, _list_db_homes, max_workers=_PER_ITEM_CONCURRENCY
        ):
            operations.append(op)
            region_db_homes.extend(items)
        db_homes.extend(region_db_homes)

        def _list_databases(
            db_home: Any, *, _client: Any = client, _region: str = region
        ) -> tuple[OperationResult, list[Any]]:
            op = paginate(
                service="database",
                operation="list_databases",
                call=_client.list_databases,
                region=_region,
                compartment_id=db_home.compartment_id,
                db_home_id=db_home.id,
                retry_policy=retry_policy,
            )
            return op, stamp_region(op.items, _region)

        region_databases: list[Any] = []
        for op, items in run_concurrently(
            region_db_homes, _list_databases, max_workers=_PER_ITEM_CONCURRENCY
        ):
            operations.append(op)
            region_databases.extend(items)
        databases.extend(region_databases)

        def _list_data_guard(
            database: Any, *, _client: Any = client, _region: str = region
        ) -> tuple[OperationResult, list[Any]]:
            # list_data_guard_associations rejects compartment_id (unknown-kwargs ValueError) -- never pass it.
            op = paginate(
                service="database",
                operation="list_data_guard_associations",
                call=_client.list_data_guard_associations,
                region=_region,
                database_id=database.id,
                retry_policy=retry_policy,
            )
            return op, stamp_region(op.items, _region)

        for op, items in run_concurrently(
            region_databases, _list_data_guard, max_workers=_PER_ITEM_CONCURRENCY
        ):
            operations.append(op)
            data_guard_associations.extend(items)

    return DatabaseBaseCollectionResult(
        db_systems=db_systems,
        db_homes=db_homes,
        databases=databases,
        data_guard_associations=data_guard_associations,
        operations=operations,
    )
