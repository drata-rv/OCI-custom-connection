"""Base Database Service collection: list_db_systems -> list_db_homes -> list_databases
-> {list_backups, list_data_guard_associations}. Summary objects are full-fidelity; no
get_* enrichment call is made.
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
class DatabaseBaseCollectionResult:
    db_systems: list[Any]
    db_homes: list[Any]
    databases: list[Any]
    backups: list[Any]
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
        backups=[],
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
    backups: list[Any] = []
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

        region_db_homes: list[Any] = []
        for db_system in region_db_systems:
            # list_db_homes requires compartment_id positionally; db_system_id scopes by DB system.
            op = paginate(
                service="database",
                operation="list_db_homes",
                call=client.list_db_homes,
                region=region,
                compartment_id=db_system.compartment_id,
                db_system_id=db_system.id,
                retry_policy=retry_policy,
            )
            operations.append(op)
            region_db_homes.extend(stamp_region(op.items, region))
        db_homes.extend(region_db_homes)

        region_databases: list[Any] = []
        for db_home in region_db_homes:
            # list_databases requires compartment_id positionally; db_home_id scopes by DB home.
            op = paginate(
                service="database",
                operation="list_databases",
                call=client.list_databases,
                region=region,
                compartment_id=db_home.compartment_id,
                db_home_id=db_home.id,
                retry_policy=retry_policy,
            )
            operations.append(op)
            region_databases.extend(stamp_region(op.items, region))
        databases.extend(region_databases)

        for database in region_databases:
            # list_backups: database_id alone is sufficient scope.
            # list_data_guard_associations rejects compartment_id (unknown-kwargs ValueError) -- never pass it.
            backup_op = paginate(
                service="database",
                operation="list_backups",
                call=client.list_backups,
                region=region,
                database_id=database.id,
                retry_policy=retry_policy,
            )
            operations.append(backup_op)
            backups.extend(stamp_region(backup_op.items, region))

            dg_op = paginate(
                service="database",
                operation="list_data_guard_associations",
                call=client.list_data_guard_associations,
                region=region,
                database_id=database.id,
                retry_policy=retry_policy,
            )
            operations.append(dg_op)
            data_guard_associations.extend(stamp_region(dg_op.items, region))

    return DatabaseBaseCollectionResult(
        db_systems=db_systems,
        db_homes=db_homes,
        databases=databases,
        backups=backups,
        data_guard_associations=data_guard_associations,
        operations=operations,
    )
