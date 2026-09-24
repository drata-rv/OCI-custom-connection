"""Compute instance, image, and VNIC/IP evidence collection.

Returns raw OCI SDK objects; projection happens in oci_drata.transform.normalize.
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
    TEST_MODE_DEADLINE_ERROR_CODE,
    OperationResult,
    RetryPolicy,
    call_once,
    is_retryable_service_error,
    operations_complete,
    paginate,
    run_concurrently,
    stamp_region,
)

# Per-item fan-out concurrency, independent of runtime.maxConcurrency (see pagination.run_concurrently).
_PER_ATTACHMENT_CONCURRENCY = 8


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
                # image cache is keyed by image_id only, shared across every region/compartment
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
                # missing image lookup -> Windows classification "unknown" downstream, not assumed non-Windows

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

            # Workers only read the vnics cache and return their own data; this thread merges
            # results sequentially, so no lock is needed. Two attachments racing on the same
            # uncached vnic_id can trigger one harmless duplicate get_vnic call.
            def _process_attachment(
                attachment: Any,
                *,
                _vnet_client: Any = vnet_client,
                _region: str = region,
                _compartment_id: str = compartment_id,
                _vnics_snapshot: dict[str, Any] = vnics,
            ) -> tuple[list[OperationResult], tuple[str, Any] | None, list[Any], dict[str, Any]]:
                vnic_id = getattr(attachment, "vnic_id", None)
                if not vnic_id:
                    return [], None, [], {}

                ops: list[OperationResult] = []
                vnic_entry: tuple[str, Any] | None = None
                if vnic_id not in _vnics_snapshot:
                    vnic_op = call_once(
                        service="virtual_network",
                        operation="get_vnic",
                        call=_vnet_client.get_vnic,
                        region=_region,
                        compartment_id=_compartment_id,
                        vnic_id=vnic_id,
                        retry_policy=retry_policy,
                    )
                    ops.append(vnic_op)
                    if vnic_op.ok and vnic_op.items:
                        vnic_entry = (vnic_id, stamp_region(vnic_op.items, _region)[0])

                # list_private_ips rejects compartment_id -- filters by vnic_id/subnet_id/ip_address only, omit it
                private_ips_op = paginate(
                    service="virtual_network",
                    operation="list_private_ips",
                    call=_vnet_client.list_private_ips,
                    region=_region,
                    vnic_id=vnic_id,
                    retry_policy=retry_policy,
                )
                ops.append(private_ips_op)
                attachment_private_ips = stamp_region(private_ips_op.items, _region)

                attachment_public_ips: dict[str, Any] = {}
                for private_ip in attachment_private_ips:
                    private_ip_id = getattr(private_ip, "id", None)
                    if not private_ip_id:
                        continue
                    public_ip_op, public_ip = _lookup_public_ip(
                        _vnet_client,
                        private_ip_id,
                        region=_region,
                        compartment_id=_compartment_id,
                        retry_policy=retry_policy,
                    )
                    ops.append(public_ip_op)
                    if public_ip is not None:
                        public_ip.region = _region
                        attachment_public_ips[private_ip_id] = public_ip

                return ops, vnic_entry, attachment_private_ips, attachment_public_ips

            for ops, vnic_entry, attachment_private_ips, attachment_public_ips in run_concurrently(
                region_attachments, _process_attachment, max_workers=_PER_ATTACHMENT_CONCURRENCY
            ):
                operations.extend(ops)
                if vnic_entry is not None:
                    vnics[vnic_entry[0]] = vnic_entry[1]
                private_ips.extend(attachment_private_ips)
                public_ips_by_private_ip_id.update(attachment_public_ips)

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
    """Look up the public IP for a private IP; 404 (none assigned) is success with item_count=0, not failure."""

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
        if policy.deadline_exceeded():
            # Hand-rolled retry loop (not paginate()/call_once()), so --test's deadline
            # check has to be repeated here too.
            result.status = "failed"
            result.error_code = TEST_MODE_DEADLINE_ERROR_CODE
            return result, None
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
            if not is_retryable_service_error(exc) or attempt >= policy.max_attempts - 1:
                result.status = "failed"
                result.error_code = str(getattr(exc, "code", exc.status))
                result.error_message = str(getattr(exc, "message", str(exc)))
                return result, None
            delay = policy.delay_seconds(attempt)
            result.retry_delays_seconds.append(delay)
            time.sleep(delay)
            attempt += 1
            continue
        except (oci.exceptions.ConnectTimeout, oci.exceptions.RequestException) as exc:
            if attempt >= policy.max_attempts - 1:
                result.status = "failed"
                result.error_code = "transport_error"
                result.error_message = str(exc)
                return result, None
            delay = policy.delay_seconds(attempt)
            result.retry_delays_seconds.append(delay)
            time.sleep(delay)
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
