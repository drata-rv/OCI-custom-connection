"""KMS vault collection: list_vaults (region/compartment, via KmsVaultClient,
a plain regional client) -> per-vault KmsManagementClient bound to that vault's
own ``management_endpoint`` field (a genuinely different construction than every
other collector's plain regional client -- KmsManagementClient takes
``service_endpoint`` as a required positional arg; see
``oci_auth.py::endpoint_client``) -> list_keys (per vault, no ``vault_id`` param
exists -- scoping is entirely by which endpoint the client was built against) ->
get_key per key, concurrently fanned out (rotation timing lives under
``Key.auto_key_rotation_details``, only present on the full model -- ``KeySummary``
only has the flat ``is_auto_rotation_enabled`` bool).
"""

from __future__ import annotations

import dataclasses
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, endpoint_client, regional_client
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
# pagination.run_concurrently) -- same value used elsewhere in this project.
_PER_KEY_CONCURRENCY = 8


@dataclasses.dataclass
class KmsVaultCollectionResult:
    vaults: list[Any]
    # Full Key objects (with auto_key_rotation_details), not KeySummary.
    keys: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> KmsVaultCollectionResult:
    return KmsVaultCollectionResult(
        vaults=[],
        keys=[],
        operations=[
            OperationResult(
                service="kms_vault",
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


def collect_kms_vault(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> KmsVaultCollectionResult:
    if not services.kms_vault:
        return _skip_result()

    operations: list[OperationResult] = []
    vaults: list[Any] = []
    keys: list[Any] = []

    for region in discovery.approved_regions:
        vault_client = regional_client(oci.key_management.KmsVaultClient, signer, region=region)

        region_vaults: list[Any] = []
        for compartment_id in discovery.approved_compartment_ids:
            op = paginate(
                service="kms_vault",
                operation="list_vaults",
                call=vault_client.list_vaults,
                region=region,
                compartment_id=compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(op)
            region_vaults.extend(stamp_region(op.items, region))
        vaults.extend(region_vaults)

        # (management_client, key_summary) pairs across every vault in this region
        # -- each vault needs its own KmsManagementClient built from its own
        # management_endpoint before list_keys can even be called.
        key_summary_pairs: list[tuple[Any, Any]] = []
        for vault in region_vaults:
            management_endpoint = getattr(vault, "management_endpoint", None)
            if not management_endpoint:
                # No endpoint means list_keys/get_key can't be scoped to this vault
                # at all -- not recorded as its own failed operation since nothing
                # was actually attempted, same convention as identity.py/
                # cloud_guard.py's own "nothing to scope this to" degradation.
                continue
            management_client = endpoint_client(
                oci.key_management.KmsManagementClient,
                signer,
                region=region,
                service_endpoint=management_endpoint,
            )
            keys_op = paginate(
                service="kms_management",
                operation="list_keys",
                call=management_client.list_keys,
                region=region,
                compartment_id=vault.compartment_id,
                retry_policy=retry_policy,
            )
            operations.append(keys_op)
            for key_summary in stamp_region(keys_op.items, region):
                key_summary_pairs.append((management_client, key_summary))

        def _get_key(
            pair: tuple[Any, Any], *, _region: str = region
        ) -> OperationResult:
            management_client, key_summary = pair
            return call_once(
                service="kms_management",
                operation="get_key",
                call=management_client.get_key,
                region=_region,
                key_id=key_summary.id,
                retry_policy=retry_policy,
            )

        for op in run_concurrently(key_summary_pairs, _get_key, max_workers=_PER_KEY_CONCURRENCY):
            operations.append(op)
            if op.ok and op.items:
                keys.extend(stamp_region(op.items, region))

    return KmsVaultCollectionResult(vaults=vaults, keys=keys, operations=operations)
