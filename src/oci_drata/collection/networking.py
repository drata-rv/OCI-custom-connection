"""Network exposure evidence collection: subnets, route tables, internet gateways,
security lists, and NSG security rules -- exactly what
:mod:`oci_drata.transform.exposure` needs to derive an instance's public ingress.
Returns raw OCI SDK model objects.
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
class NetworkingCollectionResult:
    subnets: list[Any]
    route_tables: list[Any]
    internet_gateways: list[Any]
    security_lists: list[Any]
    nsg_security_rules_by_nsg_id: dict[str, list[Any]]
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
            subnets=[],
            route_tables=[],
            internet_gateways=[],
            security_lists=[],
            nsg_security_rules_by_nsg_id={},
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

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    vnet = {r: regional_client(oci.core.VirtualNetworkClient, signer, region=r) for r in discovery.approved_regions}

    subnet_ops, route_table_ops, gateway_ops, security_list_ops, nsg_ops = list_in_scope(
        policy,
        scope,
        [
            ("virtual_network", operation, vnet)
            for operation in (
                "list_subnets",
                "list_route_tables",
                "list_internet_gateways",
                "list_security_lists",
                "list_network_security_groups",
            )
        ],
    )
    operations: list[OperationResult] = [
        *subnet_ops, *route_table_ops, *gateway_ops, *security_list_ops, *nsg_ops
    ]

    subnets: list[Any] = []
    route_tables: list[Any] = []
    internet_gateways: list[Any] = []
    security_lists: list[Any] = []
    nsgs: list[Any] = []
    for index, (region, _) in enumerate(scope):
        subnets.extend(stamp_region(subnet_ops[index].items, region))
        route_tables.extend(stamp_region(route_table_ops[index].items, region))
        internet_gateways.extend(stamp_region(gateway_ops[index].items, region))
        security_lists.extend(stamp_region(security_list_ops[index].items, region))
        nsgs.extend(stamp_region(nsg_ops[index].items, region))

    # list_network_security_group_security_rules rejects compartment_id -- omit it; passing
    # it raises ValueError.
    nsgs_with_id = [nsg for nsg in nsgs if getattr(nsg, "id", None)]
    rule_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="virtual_network",
                operation="list_network_security_group_security_rules",
                call=vnet[nsg.region].list_network_security_group_security_rules,
                region=nsg.region,
                network_security_group_id=nsg.id,
                retry_policy=policy,
            )
            for nsg in nsgs_with_id
        ]
    )
    operations.extend(rule_ops)
    nsg_security_rules_by_nsg_id = {nsg.id: op.items for nsg, op in zip(nsgs_with_id, rule_ops, strict=True)}

    return NetworkingCollectionResult(
        subnets=subnets,
        route_tables=route_tables,
        internet_gateways=internet_gateways,
        security_lists=security_lists,
        nsg_security_rules_by_nsg_id=nsg_security_rules_by_nsg_id,
        operations=operations,
    )
