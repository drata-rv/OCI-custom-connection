"""Autonomous Database collection. ``AutonomousDatabaseSummary`` is full-fidelity, so no
``get_autonomous_database`` call is made. ``list_autonomous_database_peers`` returns an
``AutonomousDatabasePeerCollection``, not a bare list; ``_unwrap_peers`` adapts it to the
plain list :func:`pagination.paginate` expects.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
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

# P2-1: bounds the per-ADB enrichment fan-out (backups/dataguard/peers per autonomous
# database) within one region iteration. Independent of runtime.maxConcurrency, which
# bounds concurrency *between* collectors.
_PER_ADB_CONCURRENCY = 8


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


def _unwrap_peers(client: oci.database.DatabaseClient) -> Callable[..., Any]:
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

        # P2-1: backups/dataguard/peers per ADB was a fully serial loop. Each ADB's
        # triple of calls is independent and safe to run concurrently -- each worker
        # returns its own data, this thread merges sequentially (pagination.run_concurrently).
        def _process_adb(
            adb: Any, *, _client: Any = client, _peers_call: Any = peers_call, _region: str = region
        ) -> tuple[list[OperationResult], str, list[Any], list[Any], list[Any]]:
            ops: list[OperationResult] = []

            # list_autonomous_database_backups: autonomous_database_id alone is sufficient scope.
            backup_op = paginate(
                service="database",
                operation="list_autonomous_database_backups",
                call=_client.list_autonomous_database_backups,
                region=_region,
                autonomous_database_id=adb.id,
                retry_policy=retry_policy,
            )
            ops.append(backup_op)

            dg_op = paginate(
                service="database",
                operation="list_autonomous_database_dataguard_associations",
                call=_client.list_autonomous_database_dataguard_associations,
                region=_region,
                autonomous_database_id=adb.id,
                retry_policy=retry_policy,
            )
            ops.append(dg_op)

            # Not region-stamped: peer's own `region` field may be a real different region
            # (e.g. cross-region Data Guard standby); stamping would overwrite it.
            peers_op = paginate(
                service="database",
                operation="list_autonomous_database_peers",
                call=_peers_call,
                region=_region,
                autonomous_database_id=adb.id,
                retry_policy=retry_policy,
            )
            ops.append(peers_op)

            return ops, adb.id, stamp_region(backup_op.items, _region), stamp_region(dg_op.items, _region), peers_op.items

        for ops, adb_id, backup_items, dg_items, peer_items in run_concurrently(
            region_adbs, _process_adb, max_workers=_PER_ADB_CONCURRENCY
        ):
            operations.extend(ops)
            autonomous_database_backups.extend(backup_items)
            autonomous_database_dataguard_associations.extend(dg_items)
            autonomous_database_peers_by_adb_id.setdefault(adb_id, []).extend(peer_items)

    return AutonomousDatabaseCollectionResult(
        autonomous_databases=autonomous_databases,
        autonomous_database_backups=autonomous_database_backups,
        autonomous_database_dataguard_associations=autonomous_database_dataguard_associations,
        autonomous_database_peers_by_adb_id=autonomous_database_peers_by_adb_id,
        operations=operations,
    )
