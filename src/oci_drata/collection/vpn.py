"""Site-to-Site VPN evidence collection (spec 5.8).

``VirtualNetworkClient`` list operations already return the same full model
as their ``get_*`` counterparts here (``IPSecConnection``, ``Cpe``, ``Drg``
all carry every field the corresponding ``get_*`` call would add), so this
module skips ``get_ip_sec_connection``/``get_cpe``/``get_drg`` entirely --
same precedent as Database and Compute. ``get_ip_sec_connection_tunnel`` is
the one exception kept conditional: called only if a listed tunnel is
genuinely missing status/routing/ike_version/bgp_session_info, in case a
future SDK revision ever returns a sparser tunnel summary from the list call.
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
)

_SERVICE = "virtual_network"

# Fields IPSecConnectionTunnel is expected to carry off the list call;
# absence of any of these is the only trigger for a per-tunnel get_* call.
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
            ip_sec_connections.extend(ipsc_op.items)

            for connection in ipsc_op.items:
                # list_ip_sec_connection_tunnels rejects any kwarg outside
                # {limit, page, retry_strategy, ...} -- compartment_id must
                # not be forwarded here, unlike the compartment-scoped calls
                # below.
                tunnels_op = paginate(
                    service=_SERVICE,
                    operation="list_ip_sec_connection_tunnels",
                    call=client.list_ip_sec_connection_tunnels,
                    region=region,
                    ipsc_id=connection.id,
                    retry_policy=retry_policy,
                )
                operations.append(tunnels_op)
                tunnels = list(tunnels_op.items)

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
                        tunnels[index] = tunnel_op.items[0]

                # Tunnel objects carry no back-reference to their parent
                # IPSec connection (verified against IPSecConnectionTunnel's
                # swagger_types) -- keyed dict is how that relationship
                # survives for the transform layer.
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
            cpes.extend(cpe_op.items)

            drg_op = paginate(
                service=_SERVICE,
                operation="list_drgs",
                call=client.list_drgs,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(drg_op)
            drgs.extend(drg_op.items)

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
            drg_attachments.extend(attachment_op.items)

            # Scope DRG route-table/rule walks to DRGs that actually carry an
            # IPSEC_TUNNEL attachment in this compartment -- cheap to tell
            # apart since list_drg_attachments(attachment_type="ALL") is
            # already fetched above, so no reason to walk every DRG in the
            # tenancy for routing unrelated to site-to-site VPN.
            vpn_relevant_drg_ids = {
                attachment.drg_id
                for attachment in attachment_op.items
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
