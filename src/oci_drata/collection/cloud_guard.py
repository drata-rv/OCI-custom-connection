"""Cloud Guard collection: get_configuration, once. Cloud Guard has a single
configuration per tenancy, not one per compartment or region -- mirrors
collection/identity.py's own single-call-from-the-discovery-region pattern
rather than looping per region/compartment like the resource-inventory
collectors elsewhere in this project.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import OperationResult, RetryPolicy, call_once, operations_complete


@dataclasses.dataclass
class CloudGuardCollectionResult:
    configuration: Any | None
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> CloudGuardCollectionResult:
    return CloudGuardCollectionResult(
        configuration=None,
        operations=[
            OperationResult(
                service="cloud_guard",
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


def collect_cloud_guard(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> CloudGuardCollectionResult:
    if not services.cloud_guard:
        return _skip_result()

    tenancy_ocid = discovery.tenancy.id if discovery.tenancy is not None else None
    if tenancy_ocid is None:
        # Mirrors collection/identity.py's own degradation: nothing to scope this
        # call to without a tenancy OCID, and get_tenancy's failure is already
        # reflected in discovery_complete -- no operation recorded here.
        return CloudGuardCollectionResult(configuration=None, operations=[])

    region = discovery.discovery_region
    client = regional_client(oci.cloud_guard.CloudGuardClient, signer, region=region)

    # call_once's own compartment_id parameter is metadata-only, never forwarded to
    # `call` (see its docstring) -- get_configuration's real compartment_id argument
    # is bound here via closure instead, and compartment_id= below is passed purely
    # for the operation manifest.
    op = call_once(
        service="cloud_guard",
        operation="get_configuration",
        call=lambda: client.get_configuration(compartment_id=tenancy_ocid),
        region=region,
        compartment_id=tenancy_ocid,
        retry_policy=retry_policy,
    )
    configuration = op.items[0] if op.ok and op.items else None
    return CloudGuardCollectionResult(configuration=configuration, operations=[op])
