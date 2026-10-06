"""Monitoring collection: list_alarms, per region/compartment. AlarmSummary is
full-fidelity (is_enabled, namespace, query, lifecycle_state) -- no per-item
get_* drill-down needed, same shape as Autonomous Database's own list call.
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
    list_in_scope,
    operations_complete,
    stamp_region,
)


@dataclasses.dataclass
class MonitoringCollectionResult:
    alarms: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> MonitoringCollectionResult:
    return MonitoringCollectionResult(
        alarms=[],
        operations=[
            OperationResult(
                service="monitoring",
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


def collect_monitoring(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> MonitoringCollectionResult:
    if not services.monitoring:
        return _skip_result()

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    clients = {r: regional_client(oci.monitoring.MonitoringClient, signer, region=r) for r in discovery.approved_regions}

    (alarm_ops,) = list_in_scope(policy, scope, [("monitoring", "list_alarms", clients)])
    alarms: list[Any] = []
    for (region, _), op in zip(scope, alarm_ops, strict=True):
        alarms.extend(stamp_region(op.items, region))

    return MonitoringCollectionResult(alarms=alarms, operations=list(alarm_ops))
