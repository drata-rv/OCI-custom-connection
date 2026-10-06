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
import functools
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, endpoint_client, regional_client
from oci_drata.pagination import (
    OperationResult,
    RetryPolicy,
    call_once,
    list_in_scope,
    operations_complete,
    paginate,
    stamp_region,
)


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

    policy = retry_policy or RetryPolicy()
    scope = discovery.scope
    vault_clients = {r: regional_client(oci.key_management.KmsVaultClient, signer, region=r) for r in discovery.approved_regions}

    (vault_ops,) = list_in_scope(policy, scope, [("kms_vault", "list_vaults", vault_clients)])
    operations: list[OperationResult] = list(vault_ops)
    vaults: list[Any] = []
    for (region, _), op in zip(scope, vault_ops, strict=True):
        vaults.extend(stamp_region(op.items, region))

    # (vault, management_client) pairs -- each vault has its own management endpoint, and so
    # its own client, for list_keys/get_key. A vault with no endpoint can't be scoped to --
    # skipped silently, same "nothing to scope to" convention as identity.py/cloud_guard.py.
    managed = [
        (
            vault,
            endpoint_client(
                oci.key_management.KmsManagementClient,
                signer,
                region=vault.region,
                service_endpoint=vault.management_endpoint,
            ),
        )
        for vault in vaults
        if getattr(vault, "management_endpoint", None)
    ]
    key_list_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="kms_management",
                operation="list_keys",
                call=client.list_keys,
                region=vault.region,
                compartment_id=vault.compartment_id,
                retry_policy=policy,
            )
            for vault, client in managed
        ]
    )
    operations.extend(key_list_ops)
    key_summaries: list[tuple[Any, Any]] = []  # (management_client, key_summary)
    for (vault, client), op in zip(managed, key_list_ops, strict=True):
        key_summaries.extend((client, summary) for summary in stamp_region(op.items, vault.region))

    # auto_key_rotation_details exists only on the full Key model, not on KeySummary.
    key_ops = policy.run(
        [
            functools.partial(
                call_once,
                service="kms_management",
                operation="get_key",
                call=client.get_key,
                region=summary.region,
                key_id=summary.id,
                retry_policy=policy,
            )
            for client, summary in key_summaries
        ]
    )
    operations.extend(key_ops)
    keys: list[Any] = []
    for (_, summary), op in zip(key_summaries, key_ops, strict=True):
        if op.ok and op.items:
            keys.extend(stamp_region(op.items, summary.region))

    return KmsVaultCollectionResult(vaults=vaults, keys=keys, operations=operations)
