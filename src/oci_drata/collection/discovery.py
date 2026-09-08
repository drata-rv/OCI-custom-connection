"""Tenancy, region, and compartment discovery; runs once before all other collectors.

Derives approved_regions (subscribed+READY) and approved_compartment_ids
(root subtree, allow/deny applied); its failures count as required-domain
failures.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import oci

from oci_drata.config import AppConfig
from oci_drata.oci_auth import TenancySigner, regional_client
from oci_drata.pagination import (
    OperationResult,
    RetryPolicy,
    call_once,
    operations_complete,
    paginate,
    stamp_region,
)


@dataclasses.dataclass
class DiscoveryResult:
    tenancy: Any  # oci.identity.models.Tenancy, or None if the call failed
    region_subscriptions: list[Any]
    all_compartments: list[Any]  # every compartment seen: including excluded/inactive
    discovery_region: str  # region identity/compartment/AD-listing calls were made from
    approved_regions: tuple[str, ...]
    unready_regions: tuple[str, ...]  # configured but not subscribed+READY, or undiscoverable
    approved_compartment_ids: tuple[str, ...]
    excluded_compartment_ids: tuple[str, ...]
    inaccessible_compartment_ids: tuple[str, ...]
    availability_domains_by_region: dict[str, list[Any]]
    operations: list[OperationResult]

    @property
    def complete(self) -> bool:
        return not self.unready_regions and operations_complete(self.operations)


def _discovery_region(signer: TenancySigner) -> str:
    """Identity calls (get_tenancy/list_region_subscriptions/list_compartments) work from
    any subscribed region and return tenancy-wide data. Bootstrapping from the first
    *configured* region (oci.regions.allow[0]) fails before producing a useful diagnostic
    when that entry is misspelled or unsubscribed -- the region hasn't been validated yet
    at that point, that's what this call is for. The OCI SDK config file's own `region` is
    already validated by oci.config.validate_config() (required, pattern-checked) before a
    TenancySigner exists at all, so it's a safe, always-known-good bootstrap point,
    independent of the allow-list this call is validating."""

    return signer.base_config["region"]


def discover(
    signer: TenancySigner,
    app_config: AppConfig,
    *,
    retry_policy: RetryPolicy | None = None,
) -> DiscoveryResult:
    region = _discovery_region(signer)
    identity = regional_client(oci.identity.IdentityClient, signer, region=region)
    tenancy_ocid = app_config.oci.expected_tenancy_ocid
    operations: list[OperationResult] = []

    tenancy_op = call_once(
        service="identity",
        operation="get_tenancy",
        call=identity.get_tenancy,
        region=region,
        tenancy_id=tenancy_ocid,
        retry_policy=retry_policy,
    )
    operations.append(tenancy_op)
    tenancy = tenancy_op.items[0] if tenancy_op.ok and tenancy_op.items else None

    region_sub_op = paginate(
        service="identity",
        operation="list_region_subscriptions",
        call=identity.list_region_subscriptions,
        region=region,
        tenancy_id=tenancy_ocid,
        retry_policy=retry_policy,
    )
    operations.append(region_sub_op)

    approved_regions, unready_regions = _resolve_regions(app_config, region_sub_op)

    all_compartments: list[Any] = []
    for root in app_config.oci.compartments.roots:
        root_id = tenancy_ocid if root == "tenancy" else root
        op = paginate(
            service="identity",
            operation="list_compartments",
            call=identity.list_compartments,
            region=region,
            compartment_id=root_id,
            compartment_id_in_subtree=True,
            access_level="ANY",
            retry_policy=retry_policy,
        )
        operations.append(op)
        # Compartments aren't regional; stamped with discovery region only to satisfy schema's non-null region field.
        all_compartments.extend(stamp_region(op.items, region))

    # list_compartments never returns the root itself; roots stay in scope separately.
    root_ids = {
        (tenancy_ocid if root == "tenancy" else root) for root in app_config.oci.compartments.roots
    }

    excluded = set(app_config.oci.compartments.exclude_ocids)
    inaccessible = tuple(sorted(c.id for c in all_compartments if not getattr(c, "is_accessible", True)))
    active_ids = {
        c.id for c in all_compartments if getattr(c, "lifecycle_state", None) == "ACTIVE"
    } | root_ids
    approved_compartment_ids = tuple(sorted(active_ids - excluded))

    availability_domains_by_region: dict[str, list[Any]] = {}
    for r in approved_regions:
        ad_client = identity if r == region else regional_client(
            oci.identity.IdentityClient, signer, region=r
        )
        ad_op = paginate(
            service="identity",
            operation="list_availability_domains",
            call=ad_client.list_availability_domains,
            region=r,
            compartment_id=tenancy_ocid,
            retry_policy=retry_policy,
        )
        operations.append(ad_op)
        availability_domains_by_region[r] = ad_op.items

    return DiscoveryResult(
        tenancy=tenancy,
        region_subscriptions=region_sub_op.items,
        all_compartments=all_compartments,
        discovery_region=region,
        approved_regions=approved_regions,
        unready_regions=unready_regions,
        approved_compartment_ids=approved_compartment_ids,
        excluded_compartment_ids=tuple(sorted(excluded)),
        inaccessible_compartment_ids=inaccessible,
        availability_domains_by_region=availability_domains_by_region,
        operations=operations,
    )


def _resolve_regions(
    app_config: AppConfig, region_sub_op: OperationResult
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    configured = app_config.oci.regions.allow
    if not region_sub_op.ok:
        # API failure, not a subscription fact: treat all configured regions unready (can't prove otherwise).
        return (), tuple(configured)

    ready_by_name = {
        rs.region_name for rs in region_sub_op.items if getattr(rs, "status", None) == "READY"
    }
    approved = tuple(r for r in configured if r in ready_by_name)
    unready = tuple(r for r in configured if r not in ready_by_name)
    return approved, unready
