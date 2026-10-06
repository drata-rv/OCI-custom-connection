"""Compute instance, image, and VNIC/IP evidence collection.

Returns raw OCI SDK objects; projection happens in oci_drata.transform.normalize. Three
concurrent stages: list instances and VNIC attachments in every region x compartment; look
up each distinct image once; enrich each distinct live VNIC once.
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
    paginate,
    stamp_region,
)
from oci_drata.transform.lifecycle import TERMINAL_LIFECYCLE_STATES


@dataclasses.dataclass
class ComputeCollectionResult:
    instances: list[Any]
    images: dict[str, Any]
    vnic_attachments: list[Any]
    vnics: dict[str, Any]
    private_ips: list[Any]
    public_ips_by_private_ip_id: dict[str, Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def collect_compute(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> ComputeCollectionResult:
    if not services.compute:
        return ComputeCollectionResult(
            instances=[],
            images={},
            vnic_attachments=[],
            vnics={},
            private_ips=[],
            public_ips_by_private_ip_id={},
            operations=[
                OperationResult(
                    service="compute",
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
    compute = {r: regional_client(oci.core.ComputeClient, signer, region=r) for r in discovery.approved_regions}
    vnet = {r: regional_client(oci.core.VirtualNetworkClient, signer, region=r) for r in discovery.approved_regions}

    # Stage 1: every instance and VNIC-attachment listing, all at once.
    list_ops = list_in_scope(
        policy, scope, [("compute", "list_instances", compute), ("compute", "list_vnic_attachments", compute)]
    )
    instance_ops, attachment_ops = list_ops
    operations: list[OperationResult] = [op for ops in list_ops for op in ops]

    instances: list[Any] = []
    vnic_attachments: list[Any] = []
    for (region, _), instance_op, attachment_op in zip(scope, instance_ops, attachment_ops, strict=True):
        instances.extend(stamp_region(instance_op.items, region))
        vnic_attachments.extend(stamp_region(attachment_op.items, region))

    # Stage 2: each distinct image once. Terminated instances are excluded from evidence, so
    # their images (and VNICs, below) aren't worth a lookup. A missing image lookup leaves
    # Windows classification "unknown" downstream, never assumed non-Windows.
    live_instances = [i for i in instances if getattr(i, "lifecycle_state", None) not in TERMINAL_LIFECYCLE_STATES]
    image_sources: dict[str, tuple[str, str]] = {}  # image_id -> (region, compartment_id) of first user
    for instance in live_instances:
        image_id = getattr(instance, "image_id", None)
        if image_id and image_id not in image_sources:
            image_sources[image_id] = (instance.region, instance.compartment_id)
    image_ops = policy.run(
        [
            functools.partial(
                call_once, service="compute", operation="get_image", call=compute[region].get_image,
                region=region, compartment_id=compartment_id, image_id=image_id, retry_policy=policy,
            )
            for image_id, (region, compartment_id) in image_sources.items()
        ]
    )
    operations.extend(image_ops)
    images = {
        image_id: stamp_region(op.items, region)[0]
        for (image_id, (region, _)), op in zip(image_sources.items(), image_ops, strict=True)
        if op.ok and op.items
    }

    # Stage 3: each distinct VNIC that is still part of a live instance. A DETACHED
    # attachment, or one of a terminated instance, points at a VNIC that may no longer
    # exist -- looking it up only manufactures a failure that withholds the whole domain.
    live_instance_ids = {i.id for i in live_instances}
    vnic_sources: dict[str, tuple[str, str]] = {}  # vnic_id -> (region, compartment_id)
    for attachment in vnic_attachments:
        vnic_id = getattr(attachment, "vnic_id", None)
        if (
            vnic_id
            and vnic_id not in vnic_sources
            and getattr(attachment, "lifecycle_state", None) != "DETACHED"
            and getattr(attachment, "instance_id", None) in live_instance_ids
        ):
            vnic_sources[vnic_id] = (attachment.region, attachment.compartment_id)

    def enrich_vnic(
        vnic_id: str, region: str, compartment_id: str
    ) -> tuple[list[OperationResult], Any, list[Any], dict[str, Any]]:
        client = vnet[region]
        ops: list[OperationResult] = []
        vnic_op = call_once(
            service="virtual_network", operation="get_vnic", call=client.get_vnic, region=region,
            compartment_id=compartment_id, vnic_id=vnic_id, retry_policy=policy,
        )
        ops.append(vnic_op)
        vnic = stamp_region(vnic_op.items, region)[0] if vnic_op.ok and vnic_op.items else None

        # list_private_ips rejects compartment_id -- filters by vnic_id/subnet_id/ip_address only, omit it
        private_ips_op = paginate(
            service="virtual_network", operation="list_private_ips", call=client.list_private_ips,
            region=region, vnic_id=vnic_id, retry_policy=policy,
        )
        ops.append(private_ips_op)
        private_ips = stamp_region(private_ips_op.items, region)

        public_ips: dict[str, Any] = {}
        for private_ip in private_ips:
            private_ip_id = getattr(private_ip, "id", None)
            if not private_ip_id:
                continue
            public_ip_op = call_once(
                service="virtual_network", operation="get_public_ip_by_private_ip_id",
                call=client.get_public_ip_by_private_ip_id, region=region, compartment_id=compartment_id,
                get_public_ip_by_private_ip_id_details=oci.core.models.GetPublicIpByPrivateIpIdDetails(
                    private_ip_id=private_ip_id
                ),
                retry_policy=policy, missing_ok=True,  # 404: no public IP assigned
            )
            ops.append(public_ip_op)
            if public_ip_op.ok and public_ip_op.items:
                public_ips[private_ip_id] = stamp_region(public_ip_op.items, region)[0]
        return ops, vnic, private_ips, public_ips

    vnic_results = policy.run(
        [
            functools.partial(enrich_vnic, vnic_id, region, compartment_id)
            for vnic_id, (region, compartment_id) in vnic_sources.items()
        ]
    )
    vnics: dict[str, Any] = {}
    private_ips: list[Any] = []
    public_ips_by_private_ip_id: dict[str, Any] = {}
    for vnic_id, (ops, vnic, vnic_private_ips, vnic_public_ips) in zip(vnic_sources, vnic_results, strict=True):
        operations.extend(ops)
        if vnic is not None:
            vnics[vnic_id] = vnic
        private_ips.extend(vnic_private_ips)
        public_ips_by_private_ip_id.update(vnic_public_ips)

    return ComputeCollectionResult(
        instances=instances,
        images=images,
        vnic_attachments=vnic_attachments,
        vnics=vnics,
        private_ips=private_ips,
        public_ips_by_private_ip_id=public_ips_by_private_ip_id,
        operations=operations,
    )
