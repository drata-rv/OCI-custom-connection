"""Site-to-site VPN evidence collection: IPSec connections and their tunnels (tunnel status
feeds the flat record's tunnelCount/upTunnelCount).

The list calls return the full connection/tunnel models; get_ip_sec_connection_tunnel runs
only for a tunnel the list left without a status.
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
    call_once,
    operations_complete,
    paginate,
    run_concurrently,
    stamp_region,
)

_SERVICE = "virtual_network"

# Per-item concurrency; independent of runtime.maxConcurrency (pagination.run_concurrently).
_PER_ITEM_CONCURRENCY = 8


@dataclasses.dataclass
class VpnCollectionResult:
    ip_sec_connections: list[Any]
    # Tunnels carry no back-reference to their connection -- keyed by connection id here.
    tunnels_by_connection_id: dict[str, list[Any]]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def collect_vpn(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> VpnCollectionResult:
    if not services.site_to_site_vpn:
        return VpnCollectionResult(
            ip_sec_connections=[],
            tunnels_by_connection_id={},
            operations=[
                OperationResult(
                    service=_SERVICE,
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

    ip_sec_connections: list[Any] = []
    tunnels_by_connection_id: dict[str, list[Any]] = {}
    operations: list[OperationResult] = []

    for region in discovery.approved_regions:
        client = regional_client(oci.core.VirtualNetworkClient, signer, region=region)

        for compartment_id in discovery.approved_compartment_ids:
            ipsc_op = paginate(
                service=_SERVICE,
                operation="list_ip_sec_connections",
                call=client.list_ip_sec_connections,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(ipsc_op)
            region_connections = stamp_region(ipsc_op.items, region)
            ip_sec_connections.extend(region_connections)

            # Connections run concurrently; per-tunnel enrichment stays sequential within
            # a worker -- typically 1-2 tunnels, real gain is across connections.
            def _process_connection(
                connection: Any, *, _client: Any = client, _region: str = region,
                _compartment_id: str = compartment_id,
            ) -> tuple[list[OperationResult], str, list[Any]]:
                ops: list[OperationResult] = []
                # list_ip_sec_connection_tunnels rejects compartment_id -- omit it.
                tunnels_op = paginate(
                    service=_SERVICE,
                    operation="list_ip_sec_connection_tunnels",
                    call=_client.list_ip_sec_connection_tunnels,
                    region=_region,
                    ipsc_id=connection.id,
                    retry_policy=retry_policy,
                )
                ops.append(tunnels_op)
                tunnels = stamp_region(tunnels_op.items, _region)

                for index, tunnel in enumerate(tunnels):
                    if getattr(tunnel, "status", None) is not None:
                        continue
                    tunnel_op = call_once(
                        service=_SERVICE,
                        operation="get_ip_sec_connection_tunnel",
                        call=_client.get_ip_sec_connection_tunnel,
                        region=_region,
                        compartment_id=_compartment_id,
                        ipsc_id=connection.id,
                        tunnel_id=tunnel.id,
                        retry_policy=retry_policy,
                    )
                    ops.append(tunnel_op)
                    if tunnel_op.ok and tunnel_op.items:
                        tunnels[index] = stamp_region(tunnel_op.items, _region)[0]

                return ops, connection.id, tunnels

            for ops, connection_id, tunnels in run_concurrently(
                region_connections, _process_connection, max_workers=_PER_ITEM_CONCURRENCY
            ):
                operations.extend(ops)
                tunnels_by_connection_id.setdefault(connection_id, []).extend(tunnels)

    return VpnCollectionResult(
        ip_sec_connections=ip_sec_connections,
        tunnels_by_connection_id=tunnels_by_connection_id,
        operations=operations,
    )
