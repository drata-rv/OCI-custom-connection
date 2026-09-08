"""Autonomous Database collection (spec 5.6).

``AutonomousDatabaseSummary`` already carries workload, dedicated/serverless
indicator, compute/storage sizing, subnet/NSGs, private endpoint, ACLs,
mTLS requirement, encryption references, and Data Guard indicators directly,
so no ``get_autonomous_database`` enrichment call is made.

``list_autonomous_database_peers`` is unlike every other ``list_*`` operation
in this module: it returns a single ``AutonomousDatabasePeerCollection``
object (with an ``items`` attribute) rather than a bare list, so
:func:`pagination.paginate` -- which does ``response.data.extend(...)`` --
would try to iterate a non-iterable collection object. ``_unwrap_peers``
adapts the raw client call so ``response.data`` is the plain
``list[AutonomousDatabasePeerSummary]`` paginate expects; headers (and thus
``opc-next-page``/request-id extraction) pass through untouched.

``list_autonomous_database_peers`` is called for every Autonomous Database,
not only ones flagged Data Guard-enabled/with peer ids: it is a plain list
operation with no documented "not applicable" error for a standalone ADB
(unlike, e.g., a documented 404-for-no-public-IP case elsewhere), so an
empty result is expected and any real failure is surfaced the same way as
every other operation in this module -- via ``OperationResult.status``.
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
    # AutonomousDatabasePeerSummary carries only id+region, no back-reference
    # to its owning ADB (unlike every other list_* result in this module) --
    # keyed by the owning ADB's id, same reasoning as vpn.py's
    # tunnels_by_connection_id, rather than losing that association in a
    # flat list.
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
            # compartment_id is accepted by list_autonomous_database_backups
            # but autonomous_database_id alone is sufficient scoping, per
            # "per ADB found".
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

            # Not region-stamped: a peer summary's own `region` field is the
            # peer's real (often different) region, e.g. a cross-region Data
            # Guard standby -- overriding it with the region we queried from
            # would corrupt that fact. Peers are folded into the owning
            # ADB's relatedResourceIds by OCID in the transform layer, never
            # rendered as their own resource row, so this is the only raw
            # list in this module that's exempt from stamp_region.
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
