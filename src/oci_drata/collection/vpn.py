"""Site-to-site VPN evidence collection (spec 5.8).

Skips get_ip_sec_connection/get_cpe/get_drg -- list calls return the full model.
get_ip_sec_connection_tunnel runs only when a tunnel is missing status/routing/ike_version/bgp_session_info.
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

# Missing any of these on a tunnel triggers a per-tunnel get_ip_sec_connection_tunnel call.
_TUNNEL_REQUIRED_FIELDS: tuple[str, ...] = ("status", "routing", "ike_version", "bgp_session_info")


@dataclasses.dataclass
class VpnCollectionResult:
    ip_sec_connections: list[Any]
    tunnels_by_connection_id: dict[str, list[Any]]
    cpes: list[Any]
    drgs: list[Any]
    drg_attachments: list[Any]
    drg_route_tables_by_drg_id: dict[str, list[Any]]
    drg_route_rules_by_route_table_id: dict[str, list[Any]]
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
            cpes=[],
            drgs=[],
            drg_attachments=[],
            drg_route_tables_by_drg_id={},
            drg_route_rules_by_route_table_id={},
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
    cpes: list[Any] = []
    drgs: list[Any] = []
    drg_attachments: list[Any] = []
    drg_route_tables_by_drg_id: dict[str, list[Any]] = {}
    drg_route_rules_by_route_table_id: dict[str, list[Any]] = {}
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
                    if not _tunnel_needs_enrichment(tunnel):
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
                # Tunnels carry no back-reference to their connection -- keyed by connection id here.
                tunnels_by_connection_id.setdefault(connection_id, []).extend(tunnels)

            cpe_op = paginate(
                service=_SERVICE,
                operation="list_cpes",
                call=client.list_cpes,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(cpe_op)
            cpes.extend(stamp_region(cpe_op.items, region))

            drg_op = paginate(
                service=_SERVICE,
                operation="list_drgs",
                call=client.list_drgs,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(drg_op)
            drgs.extend(stamp_region(drg_op.items, region))

            attachment_op = paginate(
                service=_SERVICE,
                operation="list_drg_attachments",
                call=client.list_drg_attachments,
                region=region,
                compartment_id=compartment_id,
                attachment_type="ALL",
                retry_policy=retry_policy,
            )
            operations.append(attachment_op)
            region_attachments = stamp_region(attachment_op.items, region)
            drg_attachments.extend(region_attachments)

            # Only walk DRGs with an IPSEC_TUNNEL attachment in this compartment.
            vpn_relevant_drg_ids = {
                attachment.drg_id
                for attachment in region_attachments
                if attachment.drg_id and _is_ipsec_tunnel_attachment(attachment)
            }

            # DRGs run concurrently; per-route-table rule listing stays sequential within a worker.
            def _process_drg(
                drg_id: str, *, _client: Any = client, _region: str = region
            ) -> tuple[list[OperationResult], str, list[Any], dict[str, list[Any]]]:
                ops: list[OperationResult] = []
                route_table_op = paginate(
                    service=_SERVICE,
                    operation="list_drg_route_tables",
                    call=_client.list_drg_route_tables,
                    region=_region,
                    drg_id=drg_id,
                    retry_policy=retry_policy,
                )
                ops.append(route_table_op)
                route_tables = route_table_op.items

                rules_by_table_id: dict[str, list[Any]] = {}
                for table in route_tables:
                    rule_op = paginate(
                        service=_SERVICE,
                        operation="list_drg_route_rules",
                        call=_client.list_drg_route_rules,
                        region=_region,
                        drg_route_table_id=table.id,
                        retry_policy=retry_policy,
                    )
                    ops.append(rule_op)
                    rules_by_table_id.setdefault(table.id, []).extend(rule_op.items)

                return ops, drg_id, route_tables, rules_by_table_id

            for ops, drg_id, route_tables, rules_by_table_id in run_concurrently(
                sorted(vpn_relevant_drg_ids), _process_drg, max_workers=_PER_ITEM_CONCURRENCY
            ):
                operations.extend(ops)
                drg_route_tables_by_drg_id.setdefault(drg_id, []).extend(route_tables)
                for table_id, rules in rules_by_table_id.items():
                    drg_route_rules_by_route_table_id.setdefault(table_id, []).extend(rules)

    return VpnCollectionResult(
        ip_sec_connections=ip_sec_connections,
        tunnels_by_connection_id=tunnels_by_connection_id,
        cpes=cpes,
        drgs=drgs,
        drg_attachments=drg_attachments,
        drg_route_tables_by_drg_id=drg_route_tables_by_drg_id,
        drg_route_rules_by_route_table_id=drg_route_rules_by_route_table_id,
        operations=operations,
    )


def _tunnel_needs_enrichment(tunnel: Any) -> bool:
    return any(getattr(tunnel, field, None) is None for field in _TUNNEL_REQUIRED_FIELDS)


def _is_ipsec_tunnel_attachment(attachment: Any) -> bool:
    network_details = getattr(attachment, "network_details", None)
    return getattr(network_details, "type", None) == "IPSEC_TUNNEL"
