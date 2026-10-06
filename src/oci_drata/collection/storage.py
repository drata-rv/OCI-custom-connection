"""Boot and block storage evidence collection.

Returns raw OCI SDK model objects; encryption-at-rest/in-transit derivation
happens in :mod:`oci_drata.transform.normalize`.
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

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    regions = discovery.approved_regions
    blockstorage = {r: regional_client(oci.core.BlockstorageClient, signer, region=r) for r in regions}
    compute = {r: regional_client(oci.core.ComputeClient, signer, region=r) for r in regions}

    # list_boot_volumes/list_volumes/list_volume_attachments: availability_domain optional,
    # one call per compartment covers every AD in the region.
    boot_volume_ops, volume_ops, volume_attachment_ops = list_in_scope(
        policy,
        scope,
        [
            ("blockstorage", "list_boot_volumes", blockstorage),
            ("blockstorage", "list_volumes", blockstorage),
            ("compute", "list_volume_attachments", compute),
        ],
    )
    operations: list[OperationResult] = [*boot_volume_ops, *volume_ops, *volume_attachment_ops]

    boot_volumes: list[Any] = []
    block_volumes: list[Any] = []
    volume_attachments: list[Any] = []
    for index, (region, _) in enumerate(scope):
        boot_volumes.extend(stamp_region(boot_volume_ops[index].items, region))
        block_volumes.extend(stamp_region(volume_ops[index].items, region))
        volume_attachments.extend(stamp_region(volume_attachment_ops[index].items, region))

    # list_boot_volume_attachments requires an availability_domain, and an attachment is in
    # its boot volume's AD -- so only ADs holding at least one boot volume in the region can
    # have an attachment worth joining. Ask those, not every AD of every compartment.
    ads_by_region: dict[str, set[str]] = {}
    for boot_volume in boot_volumes:
        ad = getattr(boot_volume, "availability_domain", None)
        if ad:
            ads_by_region.setdefault(boot_volume.region, set()).add(ad)
    boot_attachment_scope = [
        (region, compartment_id, ad)
        for region, compartment_id in scope
        for ad in sorted(ads_by_region.get(region, ()))
    ]
    boot_attachment_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="compute",
                operation="list_boot_volume_attachments",
                call=compute[region].list_boot_volume_attachments,
                region=region,
                compartment_id=compartment_id,
                availability_domain=ad,
                retry_policy=policy,
            )
            for region, compartment_id, ad in boot_attachment_scope
        ]
    )
    operations.extend(boot_attachment_ops)
    boot_volume_attachments: list[Any] = []
    for (region, _, _), op in zip(boot_attachment_scope, boot_attachment_ops, strict=True):
        boot_volume_attachments.extend(stamp_region(op.items, region))

    return StorageCollectionResult(
        boot_volumes=boot_volumes,
        block_volumes=block_volumes,
        boot_volume_attachments=boot_volume_attachments,
        volume_attachments=volume_attachments,
        operations=operations,
    )
