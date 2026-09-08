"""Network exposure evidence collection (spec 5.4).

Returns raw OCI SDK model objects only -- exposure derivation
(hasPublicAddress/hasInternetGatewayRoute/effectiveIngressExposure/etc.)
happens later in :mod:`oci_drata.transform.normalize`, not here.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import OperationResult, RetryPolicy, operations_complete, paginate


@dataclasses.dataclass
class NetworkingCollectionResult:
    vcns: list[Any]
    subnets: list[Any]
    route_tables: list[Any]
    internet_gateways: list[Any]
    security_lists: list[Any]
    network_security_groups: list[Any]
    nsg_security_rules_by_nsg_id: dict[str, list[Any]]
    nsg_vnics_by_nsg_id: dict[str, list[Any]]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def collect_networking(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> NetworkingCollectionResult:
    if not services.network_exposure:
        return NetworkingCollectionResult(
            vcns=[],
            subnets=[],
            route_tables=[],
            internet_gateways=[],
            security_lists=[],
            network_security_groups=[],
            nsg_security_rules_by_nsg_id={},
            nsg_vnics_by_nsg_id={},
            operations=[
                OperationResult(
                    service="virtual_network",
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

    operations: list[OperationResult] = []
    vcns: list[Any] = []
    subnets: list[Any] = []
    route_tables: list[Any] = []
    internet_gateways: list[Any] = []
    security_lists: list[Any] = []
    network_security_groups: list[Any] = []
    nsg_security_rules_by_nsg_id: dict[str, list[Any]] = {}
    nsg_vnics_by_nsg_id: dict[str, list[Any]] = {}

    for region in discovery.approved_regions:
        vnet_client = regional_client(oci.core.VirtualNetworkClient, signer, region=region)

        for compartment_id in discovery.approved_compartment_ids:
            vcns_op = paginate(
                service="virtual_network",
                operation="list_vcns",
                call=vnet_client.list_vcns,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(vcns_op)
            vcns.extend(vcns_op.items)

            subnets_op = paginate(
                service="virtual_network",
                operation="list_subnets",
                call=vnet_client.list_subnets,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(subnets_op)
            subnets.extend(subnets_op.items)

            route_tables_op = paginate(
                service="virtual_network",
                operation="list_route_tables",
                call=vnet_client.list_route_tables,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(route_tables_op)
            route_tables.extend(route_tables_op.items)

            internet_gateways_op = paginate(
                service="virtual_network",
                operation="list_internet_gateways",
                call=vnet_client.list_internet_gateways,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(internet_gateways_op)
            internet_gateways.extend(internet_gateways_op.items)

            security_lists_op = paginate(
                service="virtual_network",
                operation="list_security_lists",
                call=vnet_client.list_security_lists,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(security_lists_op)
            security_lists.extend(security_lists_op.items)

            nsgs_op = paginate(
                service="virtual_network",
                operation="list_network_security_groups",
                call=vnet_client.list_network_security_groups,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(nsgs_op)
            network_security_groups.extend(nsgs_op.items)

            for nsg in nsgs_op.items:
                nsg_id = getattr(nsg, "id", None)
                if not nsg_id:
                    continue

                # Neither of these two operations accepts compartment_id at
                # all (verified via inspect.getsource: their expected_kwargs
                # lists only cover direction/limit/page/sort_by/sort_order),
                # so compartment_id is deliberately omitted here rather than
                # forwarded by paginate() -- passing it would raise
                # ValueError from the SDK's own kwarg validation.
                rules_op = paginate(
                    service="virtual_network",
                    operation="list_network_security_group_security_rules",
                    call=vnet_client.list_network_security_group_security_rules,
                    region=region,
                    network_security_group_id=nsg_id,
                    retry_policy=retry_policy,
                )
                operations.append(rules_op)
                nsg_security_rules_by_nsg_id[nsg_id] = rules_op.items

                nsg_vnics_op = paginate(
                    service="virtual_network",
                    operation="list_network_security_group_vnics",
                    call=vnet_client.list_network_security_group_vnics,
                    region=region,
                    network_security_group_id=nsg_id,
                    retry_policy=retry_policy,
                )
                operations.append(nsg_vnics_op)
                nsg_vnics_by_nsg_id[nsg_id] = nsg_vnics_op.items

    return NetworkingCollectionResult(
        vcns=vcns,
        subnets=subnets,
        route_tables=route_tables,
        internet_gateways=internet_gateways,
        security_lists=security_lists,
        network_security_groups=network_security_groups,
        nsg_security_rules_by_nsg_id=nsg_security_rules_by_nsg_id,
        nsg_vnics_by_nsg_id=nsg_vnics_by_nsg_id,
        operations=operations,
    )
