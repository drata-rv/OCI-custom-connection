"""Compute instance, image, and VNIC/IP evidence collection (spec 5.2).

Returns raw OCI SDK model objects only -- Windows classification and any
other allowlisted-field projection happens later in
:mod:`oci_drata.transform.normalize`, not here.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import (
    RETRYABLE_STATUS_CODES,
    OperationResult,
    RetryPolicy,
    call_once,
    operations_complete,
    paginate,
    stamp_region,
)


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

    operations: list[OperationResult] = []
    instances: list[Any] = []
    images: dict[str, Any] = {}
    vnic_attachments: list[Any] = []
    vnics: dict[str, Any] = {}
    private_ips: list[Any] = []
    public_ips_by_private_ip_id: dict[str, Any] = {}

    for region in discovery.approved_regions:
        compute_client = regional_client(oci.core.ComputeClient, signer, region=region)
        vnet_client = regional_client(oci.core.VirtualNetworkClient, signer, region=region)

        for compartment_id in discovery.approved_compartment_ids:
            instances_op = paginate(
                service="compute",
                operation="list_instances",
                call=compute_client.list_instances,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(instances_op)
            region_instances = stamp_region(instances_op.items, region)
            instances.extend(region_instances)

            for instance in region_instances:
                image_id = getattr(instance, "image_id", None)
                # Cache across the whole run, not per region/compartment: many
                # instances share the same platform image, so this keeps
                # get_image calls to at most one per unique image_id.
                if not image_id or image_id in images:
                    continue
                image_op = call_once(
                    service="compute",
                    operation="get_image",
                    call=compute_client.get_image,
                    region=region,
                    compartment_id=compartment_id,
                    image_id=image_id,
                    retry_policy=retry_policy,
                )
                operations.append(image_op)
                if image_op.ok and image_op.items:
                    images[image_id] = stamp_region(image_op.items, region)[0]
                # A failed/missing image lookup is left unresolved here;
                # Windows classification for it becomes "unknown" downstream,
                # not a domain failure and not assumed non-Windows.

            attachments_op = paginate(
                service="compute",
                operation="list_vnic_attachments",
                call=compute_client.list_vnic_attachments,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(attachments_op)
            region_attachments = stamp_region(attachments_op.items, region)
            vnic_attachments.extend(region_attachments)

            for attachment in region_attachments:
                vnic_id = getattr(attachment, "vnic_id", None)
                if not vnic_id:
                    continue

                if vnic_id not in vnics:
                    vnic_op = call_once(
                        service="virtual_network",
                        operation="get_vnic",
                        call=vnet_client.get_vnic,
                        region=region,
                        compartment_id=compartment_id,
                        vnic_id=vnic_id,
                        retry_policy=retry_policy,
                    )
                    operations.append(vnic_op)
                    if vnic_op.ok and vnic_op.items:
                        vnics[vnic_id] = stamp_region(vnic_op.items, region)[0]

                # list_private_ips does not accept compartment_id (verified via
                # inspect.signature/expected_kwargs -- it filters by
                # vnic_id/subnet_id/ip_address only), so compartment_id is
                # deliberately omitted from this call.
                private_ips_op = paginate(
                    service="virtual_network",
                    operation="list_private_ips",
                    call=vnet_client.list_private_ips,
                    region=region,
                    vnic_id=vnic_id,
                    retry_policy=retry_policy,
                )
                operations.append(private_ips_op)
                region_private_ips = stamp_region(private_ips_op.items, region)
                private_ips.extend(region_private_ips)

                for private_ip in region_private_ips:
                    private_ip_id = getattr(private_ip, "id", None)
                    if not private_ip_id:
                        continue
                    public_ip_op, public_ip = _lookup_public_ip(
                        vnet_client,
                        private_ip_id,
                        region=region,
                        compartment_id=compartment_id,
                        retry_policy=retry_policy,
                    )
                    operations.append(public_ip_op)
                    if public_ip is not None:
                        public_ip.region = region
                        public_ips_by_private_ip_id[private_ip_id] = public_ip

    return ComputeCollectionResult(
        instances=instances,
        images=images,
        vnic_attachments=vnic_attachments,
        vnics=vnics,
        private_ips=private_ips,
        public_ips_by_private_ip_id=public_ips_by_private_ip_id,
        operations=operations,
    )


def _lookup_public_ip(
    vnet_client: Any,
    private_ip_id: str,
    *,
    region: str,
    compartment_id: str,
    retry_policy: RetryPolicy | None,
) -> tuple[OperationResult, Any | None]:
    """Look up the public IP assigned to one private IP.

    Not every private IP has a public IP, and OCI signals "none assigned" as
    a plain 404 ServiceError -- an expected, very common outcome, not a
    collection failure. call_once() has no way to distinguish that from a
    real failure (both would come back status="failed"), so this calls the
    SDK method directly with the same bounded retry/backoff as call_once,
    but treats a clean 404 as a synthetic success with item_count=0 rather
    than exhausting/failing the operation.
    """

    policy = retry_policy or RetryPolicy()
    result = OperationResult(
        service="virtual_network",
        operation="get_public_ip_by_private_ip_id",
        region=region,
        compartment_id=compartment_id,
        status="success",
    )
    details = oci.core.models.GetPublicIpByPrivateIpIdDetails(private_ip_id=private_ip_id)

    attempt = 0
    while True:
        try:
            response = vnet_client.get_public_ip_by_private_ip_id(
                get_public_ip_by_private_ip_id_details=details
            )
        except oci.exceptions.ServiceError as exc:
            request_id = getattr(exc, "request_id", None)
            if request_id:
                result.request_ids.append(request_id)
            if exc.status == 404:
                result.page_count = 1
                return result, None
            if exc.status not in RETRYABLE_STATUS_CODES or attempt >= policy.max_attempts - 1:
                result.status = "failed"
                result.error_code = str(getattr(exc, "code", exc.status))
                result.error_message = str(getattr(exc, "message", str(exc)))
                return result, None
            time.sleep(policy.delay_seconds(attempt))
            attempt += 1
            continue
        except (oci.exceptions.ConnectTimeout, oci.exceptions.RequestException) as exc:
            if attempt >= policy.max_attempts - 1:
                result.status = "failed"
                result.error_code = "transport_error"
                result.error_message = str(exc)
                return result, None
            time.sleep(policy.delay_seconds(attempt))
            attempt += 1
            continue

        request_id = None
        headers = getattr(response, "headers", None)
        if headers:
            request_id = headers.get("opc-request-id")
        if request_id:
            result.request_ids.append(request_id)
        result.page_count = 1
        result.item_count = 1
        result.items.append(response.data)
        return result, response.data
