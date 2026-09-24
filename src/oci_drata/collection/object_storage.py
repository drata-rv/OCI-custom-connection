"""Object Storage collection: get_namespace (per region; namespace is
tenancy-wide but the client is regional) -> list_buckets (per compartment,
summary only) -> get_bucket (concurrent fan-out, full fidelity). BucketSummary
omits public_access_type/kms_key_id/versioning, hence the get_bucket step.
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
_PER_BUCKET_CONCURRENCY = 8


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

    operations: list[OperationResult] = []
    buckets: list[Any] = []

    for region in discovery.approved_regions:
        client = regional_client(oci.object_storage.ObjectStorageClient, signer, region=region)

        namespace_op = call_once(
            service="object_storage",
            operation="get_namespace",
            call=client.get_namespace,
            region=region,
            retry_policy=retry_policy,
        )
        operations.append(namespace_op)
        if not namespace_op.ok or not namespace_op.items:
            # No namespace means list_buckets/get_bucket can't be scoped for this
            # region; namespace_op above already records the failure.
            continue
        namespace_name = namespace_op.items[0]

        region_bucket_summaries: list[Any] = []
        for compartment_id in discovery.approved_compartment_ids:
            op = paginate(
                service="object_storage",
                operation="list_buckets",
                call=client.list_buckets,
                region=region,
                compartment_id=compartment_id,
                namespace_name=namespace_name,
                retry_policy=retry_policy,
            )
            operations.append(op)
            region_bucket_summaries.extend(stamp_region(op.items, region))

        def _get_bucket(
            summary: Any, *, _client: Any = client, _namespace: str = namespace_name, _region: str = region
        ) -> OperationResult:
            return call_once(
                service="object_storage",
                operation="get_bucket",
                call=_client.get_bucket,
                region=_region,
                namespace_name=_namespace,
                bucket_name=summary.name,
                retry_policy=retry_policy,
            )

        for op in run_concurrently(
            region_bucket_summaries, _get_bucket, max_workers=_PER_BUCKET_CONCURRENCY
        ):
            operations.append(op)
            if op.ok and op.items:
                buckets.extend(stamp_region(op.items, region))

    return ObjectStorageCollectionResult(buckets=buckets, operations=operations)
