"""Boot and block storage evidence collection (spec 5.3).

Returns raw OCI SDK model objects only -- encryption-at-rest/in-transit
derivation happens later in :mod:`oci_drata.transform.normalize`, not here.
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
class StorageCollectionResult:
    boot_volumes: list[Any]
    block_volumes: list[Any]
    boot_volume_attachments: list[Any]
    volume_attachments: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def collect_storage(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> StorageCollectionResult:
    if not services.block_storage:
        return StorageCollectionResult(
            boot_volumes=[],
            block_volumes=[],
            boot_volume_attachments=[],
            volume_attachments=[],
            operations=[
                OperationResult(
                    service="blockstorage",
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
    boot_volumes: list[Any] = []
    block_volumes: list[Any] = []
    boot_volume_attachments: list[Any] = []
    volume_attachments: list[Any] = []

    for region in discovery.approved_regions:
        blockstorage_client = regional_client(oci.core.BlockstorageClient, signer, region=region)
        compute_client = regional_client(oci.core.ComputeClient, signer, region=region)
        availability_domains = discovery.availability_domains_by_region.get(region, [])

        for compartment_id in discovery.approved_compartment_ids:
            # list_boot_volumes/list_volumes/list_volume_attachments all
            # accept availability_domain as optional (verified via
            # inspect.getsource: neither is a required parameter), so one
            # call per compartment lists across every AD in the region.
            boot_volumes_op = paginate(
                service="blockstorage",
                operation="list_boot_volumes",
                call=blockstorage_client.list_boot_volumes,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(boot_volumes_op)
            boot_volumes.extend(boot_volumes_op.items)

            volumes_op = paginate(
                service="blockstorage",
                operation="list_volumes",
                call=blockstorage_client.list_volumes,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(volumes_op)
            block_volumes.extend(volumes_op.items)

            volume_attachments_op = paginate(
                service="compute",
                operation="list_volume_attachments",
                call=compute_client.list_volume_attachments,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(volume_attachments_op)
            volume_attachments.extend(volume_attachments_op.items)

            # list_boot_volume_attachments requires availability_domain as a
            # required positional parameter (verified via inspect.signature),
            # unlike the three calls above -- one call per AD per
            # compartment is unavoidable here.
            for ad in availability_domains:
                ad_name = getattr(ad, "name", None)
                if not ad_name:
                    continue
                boot_attachments_op = paginate(
                    service="compute",
                    operation="list_boot_volume_attachments",
                    call=compute_client.list_boot_volume_attachments,
                    region=region,
                    compartment_id=compartment_id,
                    availability_domain=ad_name,
                    retry_policy=retry_policy,
                )
                operations.append(boot_attachments_op)
                boot_volume_attachments.extend(boot_attachments_op.items)

    return StorageCollectionResult(
        boot_volumes=boot_volumes,
        block_volumes=block_volumes,
        boot_volume_attachments=boot_volume_attachments,
        volume_attachments=volume_attachments,
        operations=operations,
    )
