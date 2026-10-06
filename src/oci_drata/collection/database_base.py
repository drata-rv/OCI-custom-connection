"""Base Database Service collection: list_db_systems -> list_db_homes -> list_databases
-> list_data_guard_associations. Summary objects are full-fidelity; no get_* enrichment
call is made.
"""

from __future__ import annotations

import dataclasses
import functools
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
    paginate,
    stamp_region,
)


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

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    clients = {r: regional_client(oci.database.DatabaseClient, signer, region=r) for r in discovery.approved_regions}

    # Each stage needs the previous one's ids, so they run one after another; within a
    # stage everything is concurrent.
    (db_system_ops,) = list_in_scope(policy, scope, [("database", "list_db_systems", clients)])
    operations: list[OperationResult] = list(db_system_ops)
    db_systems: list[Any] = []
    for (region, _), op in zip(scope, db_system_ops, strict=True):
        db_systems.extend(stamp_region(op.items, region))

    db_home_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="database",
                operation="list_db_homes",
                call=clients[db_system.region].list_db_homes,
                region=db_system.region,
                compartment_id=db_system.compartment_id,
                db_system_id=db_system.id,
                retry_policy=policy,
            )
            for db_system in db_systems
        ]
    )
    operations.extend(db_home_ops)
    db_homes: list[Any] = []
    for db_system, op in zip(db_systems, db_home_ops, strict=True):
        db_homes.extend(stamp_region(op.items, db_system.region))

    database_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="database",
                operation="list_databases",
                call=clients[db_home.region].list_databases,
                region=db_home.region,
                compartment_id=db_home.compartment_id,
                db_home_id=db_home.id,
                retry_policy=policy,
            )
            for db_home in db_homes
        ]
    )
    operations.extend(database_ops)
    databases: list[Any] = []
    for db_home, op in zip(db_homes, database_ops, strict=True):
        databases.extend(stamp_region(op.items, db_home.region))

    # list_data_guard_associations rejects compartment_id (unknown-kwargs ValueError) -- never pass it.
    data_guard_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="database",
                operation="list_data_guard_associations",
                call=clients[database.region].list_data_guard_associations,
                region=database.region,
                database_id=database.id,
                retry_policy=policy,
            )
            for database in databases
        ]
    )
    operations.extend(data_guard_ops)
    data_guard_associations: list[Any] = []
    for database, op in zip(databases, data_guard_ops, strict=True):
        data_guard_associations.extend(stamp_region(op.items, database.region))

    return DatabaseBaseCollectionResult(
        db_systems=db_systems,
        db_homes=db_homes,
        databases=databases,
        data_guard_associations=data_guard_associations,
        operations=operations,
    )
