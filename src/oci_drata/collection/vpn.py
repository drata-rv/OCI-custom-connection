"""Site-to-site VPN evidence collection: IPSec connections and their tunnels (tunnel status
feeds the flat record's tunnelCount/upTunnelCount).

The list calls return the full connection/tunnel models; get_ip_sec_connection_tunnel runs
only for a tunnel the list left without a status.
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
    call_once,
    list_in_scope,
    operations_complete,
    paginate,
    stamp_region,
)

_SERVICE = "virtual_network"


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

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    clients = {r: regional_client(oci.core.VirtualNetworkClient, signer, region=r) for r in discovery.approved_regions}

    (connection_ops,) = list_in_scope(policy, scope, [(_SERVICE, "list_ip_sec_connections", clients)])
    operations: list[OperationResult] = list(connection_ops)
    connections: list[tuple[str, str, Any]] = []  # (region, compartment_id, connection)
    ip_sec_connections: list[Any] = []
    for (region, compartment_id), op in zip(scope, connection_ops, strict=True):
        for connection in stamp_region(op.items, region):
            ip_sec_connections.append(connection)
            connections.append((region, compartment_id, connection))

    def tunnels_of(region: str, compartment_id: str, connection: Any) -> tuple[list[OperationResult], list[Any]]:
        client = clients[region]
        # list_ip_sec_connection_tunnels rejects compartment_id -- omit it.
        tunnels_op = paginate(
            service=_SERVICE,
            operation="list_ip_sec_connection_tunnels",
            call=client.list_ip_sec_connection_tunnels,
            region=region,
            ipsc_id=connection.id,
            retry_policy=policy,
        )
        ops = [tunnels_op]
        tunnels = stamp_region(tunnels_op.items, region)
        for index, tunnel in enumerate(tunnels):
            if getattr(tunnel, "status", None) is not None:
                continue
            tunnel_op = call_once(
                service=_SERVICE,
                operation="get_ip_sec_connection_tunnel",
                call=client.get_ip_sec_connection_tunnel,
                region=region,
                compartment_id=compartment_id,
                ipsc_id=connection.id,
                tunnel_id=tunnel.id,
                retry_policy=policy,
            )
            ops.append(tunnel_op)
            if tunnel_op.ok and tunnel_op.items:
                tunnels[index] = stamp_region(tunnel_op.items, region)[0]
        return ops, tunnels

    tunnel_results = policy.run(
        [functools.partial(tunnels_of, region, compartment_id, connection) for region, compartment_id, connection in connections]
    )
    # Tunnels carry no back-reference to their connection -- keyed by connection id here.
    tunnels_by_connection_id: dict[str, list[Any]] = {}
    for (_, _, connection), (ops, tunnels) in zip(connections, tunnel_results, strict=True):
        operations.extend(ops)
        tunnels_by_connection_id.setdefault(connection.id, []).extend(tunnels)

    return VpnCollectionResult(
        ip_sec_connections=ip_sec_connections,
        tunnels_by_connection_id=tunnels_by_connection_id,
        operations=operations,
    )
