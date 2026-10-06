"""Object Storage collection: get_namespace (per region; namespace is
tenancy-wide but the client is regional) -> list_buckets (per compartment,
summary only) -> get_bucket (concurrent fan-out, full fidelity). BucketSummary
omits public_access_type/kms_key_id/versioning, hence the get_bucket step.
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
    operations_complete,
    paginate,
    stamp_region,
)


@dataclasses.dataclass
class ObjectStorageCollectionResult:
    buckets: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> ObjectStorageCollectionResult:
    return ObjectStorageCollectionResult(
        buckets=[],
        operations=[
            OperationResult(
                service="object_storage",
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


def collect_object_storage(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> ObjectStorageCollectionResult:
    if not services.object_storage:
        return _skip_result()

    policy = retry_policy or RetryPolicy()
    regions = discovery.approved_regions
    clients = {r: regional_client(oci.object_storage.ObjectStorageClient, signer, region=r) for r in regions}

    namespace_ops = policy.run(
        [
            functools.partial(
                call_once,
                service="object_storage",
                operation="get_namespace",
                call=clients[region].get_namespace,
                region=region,
                retry_policy=policy,
            )
            for region in regions
        ]
    )
    operations: list[OperationResult] = list(namespace_ops)
    # No namespace means list_buckets/get_bucket can't be scoped for that region; the
    # namespace op above already records the failure.
    namespaces = {
        region: op.items[0] for region, op in zip(regions, namespace_ops, strict=True) if op.ok and op.items
    }

    bucket_scope = [(region, compartment_id) for region, compartment_id in discovery.scope if region in namespaces]
    list_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="object_storage",
                operation="list_buckets",
                call=clients[region].list_buckets,
                region=region,
                compartment_id=compartment_id,
                namespace_name=namespaces[region],
                retry_policy=policy,
            )
            for region, compartment_id in bucket_scope
        ]
    )
    operations.extend(list_ops)
    summaries: list[tuple[str, Any]] = []
    for (region, _), op in zip(bucket_scope, list_ops, strict=True):
        summaries.extend((region, summary) for summary in stamp_region(op.items, region))

    bucket_ops = policy.run(
        [
            functools.partial(
                call_once,
                service="object_storage",
                operation="get_bucket",
                call=clients[region].get_bucket,
                region=region,
                namespace_name=namespaces[region],
                bucket_name=summary.name,
                retry_policy=policy,
            )
            for region, summary in summaries
        ]
    )
    operations.extend(bucket_ops)
    buckets: list[Any] = []
    for (region, _), op in zip(summaries, bucket_ops, strict=True):
        if op.ok and op.items:
            buckets.extend(stamp_region(op.items, region))

    return ObjectStorageCollectionResult(buckets=buckets, operations=operations)
