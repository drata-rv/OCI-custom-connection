"""Collects users, per-user API keys (fanned out), and policies per approved
compartment. Tenancy-scoped: collected once from the discovery region, never
per-region. list_* responses are full-fidelity -- no drill-down calls needed.

Broadest trust footprint of any collector here (MFA status, API key ages, raw
policy text). Off by default; see README Section 4 for the required policy grant.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import oci

from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.config import OciServicesConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import OperationResult, RetryPolicy, operations_complete, paginate, run_concurrently

# Per-item fan-out concurrency, independent of runtime.maxConcurrency (see
# pagination.run_concurrently) -- same value used by database_autonomous.py.
_PER_USER_CONCURRENCY = 8


@dataclasses.dataclass
class IdentityCollectionResult:
    users: list[Any]
    api_keys_by_user_id: dict[str, list[Any]]
    policies: list[Any]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return operations_complete(self.operations)


def _skip_result() -> IdentityCollectionResult:
    return IdentityCollectionResult(
        users=[],
        api_keys_by_user_id={},
        policies=[],
        operations=[
            OperationResult(
                service="identity",
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


def collect_identity(
    signer: TenancySigner,
    discovery: DiscoveryResult,
    services: OciServicesConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> IdentityCollectionResult:
    if not services.identity:
        return _skip_result()

    operations: list[OperationResult] = []
    region = discovery.discovery_region
    client = regional_client(oci.identity.IdentityClient, signer, region=region)
    tenancy_ocid = discovery.tenancy.id if discovery.tenancy is not None else None

    users: list[Any] = []
    if tenancy_ocid is not None:
        users_op = paginate(
            service="identity",
            operation="list_users",
            call=client.list_users,
            region=region,
            compartment_id=tenancy_ocid,
            retry_policy=retry_policy,
        )
        operations.append(users_op)
        users = users_op.items

    def _list_api_keys(user: Any, *, _client: Any = client, _region: str = region) -> tuple[OperationResult, str, list[Any]]:
        op = paginate(
            service="identity",
            operation="list_api_keys",
            call=_client.list_api_keys,
            region=_region,
            user_id=user.id,
            retry_policy=retry_policy,
        )
        return op, user.id, op.items

    api_keys_by_user_id: dict[str, list[Any]] = {}
    for op, user_id, items in run_concurrently(users, _list_api_keys, max_workers=_PER_USER_CONCURRENCY):
        operations.append(op)
        api_keys_by_user_id[user_id] = items

    policies: list[Any] = []
    for compartment_id in discovery.approved_compartment_ids:
        policies_op = paginate(
            service="identity",
            operation="list_policies",
            call=client.list_policies,
            region=region,
            compartment_id=compartment_id,
            retry_policy=retry_policy,
        )
        operations.append(policies_op)
        policies.extend(policies_op.items)

    return IdentityCollectionResult(
        users=users,
        api_keys_by_user_id=api_keys_by_user_id,
        policies=policies,
        operations=operations,
    )
