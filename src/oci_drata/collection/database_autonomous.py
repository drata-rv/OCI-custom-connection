"""Autonomous Database collection. ``AutonomousDatabaseSummary`` is full-fidelity, so no
``get_autonomous_database`` call is made. ``list_autonomous_database_peers`` returns an
``AutonomousDatabasePeerCollection``, not a bare list; ``_unwrap_peers`` adapts it to the
plain list :func:`pagination.paginate` expects.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable

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
    autonomous_database_backups: list[Any]
    autonomous_database_dataguard_associations: list[Any]
    # Peer summaries carry no back-reference to their owning ADB; keyed by ADB id.
    autonomous_database_peers_by_adb_id: dict[str, list[Any]]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> AutonomousDatabaseCollectionResult:
    return AutonomousDatabaseCollectionResult(
        autonomous_databases=[],
        autonomous_database_backups=[],
        autonomous_database_dataguard_associations=[],
        autonomous_database_peers_by_adb_id={},
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


def _unwrap_peers(client: "oci.database.DatabaseClient") -> Callable[..., Any]:
    def _call(**kwargs: Any) -> Any:
        response = client.list_autonomous_database_peers(**kwargs)
        response.data = response.data.items if response.data is not None else []
        return response

    return _call


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
    autonomous_database_backups: list[Any] = []
    autonomous_database_dataguard_associations: list[Any] = []
    autonomous_database_peers_by_adb_id: dict[str, list[Any]] = {}

    for region in discovery.approved_regions:
        client = regional_client(oci.database.DatabaseClient, signer, region=region)
        peers_call = _unwrap_peers(client)

        region_adbs: list[Any] = []
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
            region_adbs.extend(stamp_region(op.items, region))
        autonomous_databases.extend(region_adbs)

        for adb in region_adbs:
            # list_autonomous_database_backups: autonomous_database_id alone is sufficient scope.
            backup_op = paginate(
                service="database",
                operation="list_autonomous_database_backups",
                call=client.list_autonomous_database_backups,
                region=region,
                autonomous_database_id=adb.id,
                retry_policy=retry_policy,
            )
            operations.append(backup_op)
            autonomous_database_backups.extend(stamp_region(backup_op.items, region))

            dg_op = paginate(
                service="database",
                operation="list_autonomous_database_dataguard_associations",
                call=client.list_autonomous_database_dataguard_associations,
                region=region,
                autonomous_database_id=adb.id,
                retry_policy=retry_policy,
            )
            operations.append(dg_op)
            autonomous_database_dataguard_associations.extend(stamp_region(dg_op.items, region))

            # Not region-stamped: peer's own `region` field may be a real different region
            # (e.g. cross-region Data Guard standby); stamping would overwrite it.
            peers_op = paginate(
                service="database",
                operation="list_autonomous_database_peers",
                call=peers_call,
                region=region,
                autonomous_database_id=adb.id,
                retry_policy=retry_policy,
            )
            operations.append(peers_op)
            autonomous_database_peers_by_adb_id.setdefault(adb.id, []).extend(peers_op.items)

    return AutonomousDatabaseCollectionResult(
        autonomous_databases=autonomous_databases,
        autonomous_database_backups=autonomous_database_backups,
        autonomous_database_dataguard_associations=autonomous_database_dataguard_associations,
        autonomous_database_peers_by_adb_id=autonomous_database_peers_by_adb_id,
        operations=operations,
    )
