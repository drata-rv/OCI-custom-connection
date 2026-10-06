"""Load balancer collection: ``list_load_balancers`` returns full ``LoadBalancer``
objects (no LoadBalancerSummary type) with backend set names included, then fans
out per (load balancer, backend set name) for ``get_backend_set_health``.
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
    stamp_region,
)


@dataclasses.dataclass
class LoadBalancerCollectionResult:
    load_balancers: list[Any]
    # Keyed by (load_balancer_id, backend_set_name): backend set names aren't
    # unique tenancy-wide, only within their own load balancer.
    backend_set_health_by_key: dict[tuple[str, str], Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> LoadBalancerCollectionResult:
    return LoadBalancerCollectionResult(
        load_balancers=[],
        backend_set_health_by_key={},
        operations=[
            OperationResult(
                service="load_balancer",
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


def collect_load_balancer(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> LoadBalancerCollectionResult:
    if not services.load_balancer:
        return _skip_result()

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    clients = {r: regional_client(oci.load_balancer.LoadBalancerClient, signer, region=r) for r in discovery.approved_regions}

    (lb_ops,) = list_in_scope(policy, scope, [("load_balancer", "list_load_balancers", clients)])
    load_balancers: list[Any] = []
    for (region, _), op in zip(scope, lb_ops, strict=True):
        load_balancers.extend(stamp_region(op.items, region))

    # Backend set names come free from the list call above; no separate list_backend_sets
    # call needed. get_backend_set_health takes no compartment_id.
    pairs = [(lb, name) for lb in load_balancers for name in (lb.backend_sets or {})]
    health_ops = policy.run(
        [
            functools.partial(
                call_once,
                service="load_balancer",
                operation="get_backend_set_health",
                call=clients[lb.region].get_backend_set_health,
                region=lb.region,
                load_balancer_id=lb.id,
                backend_set_name=name,
                retry_policy=policy,
            )
            for lb, name in pairs
        ]
    )
    backend_set_health_by_key = {
        (lb.id, name): op.items[0] for (lb, name), op in zip(pairs, health_ops, strict=True) if op.ok and op.items
    }

    return LoadBalancerCollectionResult(
        load_balancers=load_balancers,
        backend_set_health_by_key=backend_set_health_by_key,
        operations=[*lb_ops, *health_ops],
    )
