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
    stamp_region,
)

_SERVICE = "virtual_network"

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

            for connection in region_connections:
                # list_ip_sec_connection_tunnels rejects compartment_id -- omit it.
                tunnels_op = paginate(
                    service=_SERVICE,
                    operation="list_ip_sec_connection_tunnels",
                    call=client.list_ip_sec_connection_tunnels,
                    region=region,
                    ipsc_id=connection.id,
                    retry_policy=retry_policy,
                )
                operations.append(tunnels_op)
                tunnels = stamp_region(tunnels_op.items, region)

                for index, tunnel in enumerate(tunnels):
                    if not _tunnel_needs_enrichment(tunnel):
                        continue
                    tunnel_op = call_once(
                        service=_SERVICE,
                        operation="get_ip_sec_connection_tunnel",
                        call=client.get_ip_sec_connection_tunnel,
                        region=region,
                        compartment_id=compartment_id,
                        ipsc_id=connection.id,
                        tunnel_id=tunnel.id,
                        retry_policy=retry_policy,
                    )
                    operations.append(tunnel_op)
                    if tunnel_op.ok and tunnel_op.items:
                        tunnels[index] = stamp_region(tunnel_op.items, region)[0]

                # Tunnels carry no back-reference to their connection -- keyed by connection id here.
                tunnels_by_connection_id.setdefault(connection.id, []).extend(tunnels)

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

            for drg_id in sorted(vpn_relevant_drg_ids):
                route_table_op = paginate(
                    service=_SERVICE,
                    operation="list_drg_route_tables",
                    call=client.list_drg_route_tables,
                    region=region,
                    drg_id=drg_id,
                    retry_policy=retry_policy,
                )
                operations.append(route_table_op)
                route_tables = route_table_op.items
                drg_route_tables_by_drg_id.setdefault(drg_id, []).extend(route_tables)

                for table in route_tables:
                    rule_op = paginate(
                        service=_SERVICE,
                        operation="list_drg_route_rules",
                        call=client.list_drg_route_rules,
                        region=region,
                        drg_route_table_id=table.id,
                        retry_policy=retry_policy,
                    )
                    operations.append(rule_op)
                    drg_route_rules_by_route_table_id.setdefault(table.id, []).extend(rule_op.items)

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
