"""KMS vault collection: list_vaults (regional client) -> per-vault
KmsManagementClient bound to that vault's ``management_endpoint``
(``service_endpoint`` is a required positional arg; see
``oci_auth.py::endpoint_client``) -> list_keys (no ``vault_id`` param;
scoping is by which endpoint the client was built against) -> get_key per
key, concurrent fan-out (``auto_key_rotation_details`` exists only on the
full ``Key`` model, not on ``KeySummary``).
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

# Fan-out concurrency for get_key calls, independent of runtime.maxConcurrency
# (see pagination.run_concurrently).
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

        # (management_client, key_summary) pairs -- each vault has its own
        # management_client, needed for get_key below.
        key_summary_pairs: list[tuple[Any, Any]] = []
        for vault in region_vaults:
            management_endpoint = getattr(vault, "management_endpoint", None)
            if not management_endpoint:
                # No endpoint means list_keys/get_key can't be scoped to this vault --
                # skip silently, same "nothing to scope to" convention as
                # identity.py/cloud_guard.py.
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
