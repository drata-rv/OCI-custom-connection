"""Load balancer collection: ``list_load_balancers`` returns full ``LoadBalancer``
objects (no LoadBalancerSummary type) with backend set names included, then fans
out per (load balancer, backend set name) for ``get_backend_set_health``.
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

# Per-item fan-out concurrency, independent of runtime.maxConcurrency (see
# pagination.run_concurrently).
_PER_BACKEND_SET_CONCURRENCY = 8


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

    operations: list[OperationResult] = []
    load_balancers: list[Any] = []
    backend_set_health_by_key: dict[tuple[str, str], Any] = {}

    for region in discovery.approved_regions:
        client = regional_client(oci.load_balancer.LoadBalancerClient, signer, region=region)

        region_load_balancers: list[Any] = []
        for compartment_id in discovery.approved_compartment_ids:
            op = paginate(
                service="load_balancer",
                operation="list_load_balancers",
                call=client.list_load_balancers,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(op)
            region_load_balancers.extend(stamp_region(op.items, region))
        load_balancers.extend(region_load_balancers)

        # Backend set names come free from the list call above; no separate
        # list_backend_sets call needed.
        pairs = [
            (lb, backend_set_name)
            for lb in region_load_balancers
            for backend_set_name in (lb.backend_sets or {})
        ]

        def _get_health(
            pair: tuple[Any, str], *, _client: Any = client, _region: str = region
        ) -> tuple[str, str, OperationResult]:
            lb, backend_set_name = pair
            # get_backend_set_health takes no compartment_id; call_once's
            # compartment_id param is metadata-only, never auto-forwarded
            # (see pagination.py::call_once).
            op = call_once(
                service="load_balancer",
                operation="get_backend_set_health",
                call=lambda: _client.get_backend_set_health(
                    load_balancer_id=lb.id, backend_set_name=backend_set_name
                ),
                region=_region,
                retry_policy=retry_policy,
            )
            return lb.id, backend_set_name, op

        for lb_id, backend_set_name, op in run_concurrently(
            pairs, _get_health, max_workers=_PER_BACKEND_SET_CONCURRENCY
        ):
            operations.append(op)
            if op.ok and op.items:
                backend_set_health_by_key[(lb_id, backend_set_name)] = op.items[0]

    return LoadBalancerCollectionResult(
        load_balancers=load_balancers,
        backend_set_health_by_key=backend_set_health_by_key,
        operations=operations,
    )
