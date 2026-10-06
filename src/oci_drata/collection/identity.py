"""Collects users, per-user API keys (fanned out), and policies per approved
compartment. Tenancy-scoped: collected once from the discovery region, never
per-region. list_* responses are full-fidelity -- no drill-down calls needed.

Broadest trust footprint of any collector here (MFA status, API key ages, raw
policy text). Off by default; see README Section 4 for the required policy grant.
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
)


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

    policy = retry_policy or RetryPolicy()
    region = discovery.discovery_region
    client = regional_client(oci.identity.IdentityClient, signer, region=region)
    tenancy_ocid = discovery.tenancy.id if discovery.tenancy is not None else None

    operations: list[OperationResult] = []
    users: list[Any] = []
    if tenancy_ocid is not None:
        users_op = paginate(
            service="identity",
            operation="list_users",
            call=client.list_users,
            region=region,
            compartment_id=tenancy_ocid,
            retry_policy=policy,
        )
        operations.append(users_op)
        users = users_op.items

    # Each user's API keys and each compartment's policies are independent: one concurrent
    # pass. IAM data is tenancy-wide, so everything is read from the discovery region.
    key_ops = policy.run(
        [
            functools.partial(
                paginate,
                service="identity",
                operation="list_api_keys",
                call=client.list_api_keys,
                region=region,
                user_id=user.id,
                retry_policy=policy,
            )
            for user in users
        ]
    )
    (iam_policy_ops,) = list_in_scope(
        policy,
        [(region, compartment_id) for compartment_id in discovery.approved_compartment_ids],
        [("identity", "list_policies", {region: client})],
    )
    operations.extend(key_ops)
    operations.extend(iam_policy_ops)

    return IdentityCollectionResult(
        users=users,
        api_keys_by_user_id={user.id: op.items for user, op in zip(users, key_ops, strict=True)},
        policies=[item for op in iam_policy_ops for item in op.items],
        operations=operations,
    )
