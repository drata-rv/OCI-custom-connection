"""Web Application Firewall collection: list_web_app_firewalls, per region/
compartment. Deliberately ``oci.waf`` (the current, purpose-built WAF service,
API version 2021), not ``oci.waas`` (the older Web Application Acceleration and
Security service, API version 2018) -- ``WaasPolicySummary`` is keyed by DNS
domain with no OCID link to any compute/network resource, so it can't answer
"does load balancer X have a WAF attached"; ``WebAppFirewallLoadBalancerSummary``
carries ``load_balancer_id`` directly, joinable against collection/load_balancer.py.
``list_web_app_firewalls`` is already full-fidelity (no drill-down call needed).

``list_web_app_firewalls`` returns a ``WebAppFirewallCollection``, not a bare
list -- paginate()'s ``response.data or []`` assumption crashes on it with
``TypeError: not iterable``. ``_unwrap`` adapts it to the plain list
:func:`pagination.paginate` expects, same pattern as
``collection/database_autonomous.py``'s ``_unwrap_peers`` for
``list_autonomous_database_peers``, the one other operation in this project
with this shape.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import OperationResult, RetryPolicy, operations_complete, paginate, stamp_region


@dataclasses.dataclass
class WafCollectionResult:
    web_app_firewalls: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> WafCollectionResult:
    return WafCollectionResult(
        web_app_firewalls=[],
        operations=[
            OperationResult(
                service="waf",
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


def _unwrap(client: oci.waf.WafClient) -> Callable[..., Any]:
    def _call(**kwargs: Any) -> Any:
        response = client.list_web_app_firewalls(**kwargs)
        response.data = response.data.items if response.data is not None else []
        return response

    return _call


def collect_waf(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> WafCollectionResult:
    if not services.waf:
        return _skip_result()

    operations: list[OperationResult] = []
    web_app_firewalls: list[Any] = []

    for region in discovery.approved_regions:
        client = regional_client(oci.waf.WafClient, signer, region=region)
        list_call = _unwrap(client)
        for compartment_id in discovery.approved_compartment_ids:
            op = paginate(
                service="waf",
                operation="list_web_app_firewalls",
                call=list_call,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(op)
            web_app_firewalls.extend(stamp_region(op.items, region))

    return WafCollectionResult(web_app_firewalls=web_app_firewalls, operations=operations)
