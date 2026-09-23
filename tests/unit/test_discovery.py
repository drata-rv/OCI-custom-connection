from __future__ import annotations

from types import SimpleNamespace

from oci_drata.collection.discovery import (
    DiscoveryResult,
    _discovery_region,
    _expand_to_subtrees,
    _resolve_regions,
    limit_for_sample,
)
from oci_drata.oci_auth import TenancySigner
from oci_drata.pagination import OperationResult


def _compartment(id_: str, parent_id: str) -> SimpleNamespace:
    return SimpleNamespace(id=id_, compartment_id=parent_id)


def test_discovery_region_uses_signer_config_region_not_allow_list_first_entry() -> None:
    """bootstrapping from oci.regions.allow[0] fails before producing a
    useful diagnostic when that entry is misspelled/unsubscribed. The OCI SDK config
    file's own region is already validated (required + pattern-checked) before a
    TenancySigner exists, independent of the allow-list this call is meant to validate."""

    signer = TenancySigner(base_config={"region": "us-ashburn-1", "tenancy": "t1", "user": "u1"})
    assert _discovery_region(signer) == "us-ashburn-1"


def test_discovery_region_ignores_allow_list_entirely() -> None:
    signer = TenancySigner(base_config={"region": "eu-frankfurt-1"})
    assert _discovery_region(signer) == "eu-frankfurt-1"


def _region_sub(name: str, status: str) -> SimpleNamespace:
    return SimpleNamespace(region_name=name, status=status)


def _app_config_with_allow(*regions: str) -> SimpleNamespace:
    return SimpleNamespace(oci=SimpleNamespace(regions=SimpleNamespace(allow=tuple(regions))))


def test_resolve_regions_splits_ready_and_unready() -> None:
    app_config = _app_config_with_allow("us-ashburn-1", "eu-frankfurt-1", "uk-london-1")
    op = OperationResult(
        service="identity", operation="list_region_subscriptions", region="us-ashburn-1",
        compartment_id=None, status="success",
        items=[_region_sub("us-ashburn-1", "READY"), _region_sub("eu-frankfurt-1", "NOT_READY")],
    )
    approved, unready = _resolve_regions(app_config, op)
    assert approved == ("us-ashburn-1",)
    assert unready == ("eu-frankfurt-1", "uk-london-1")  # uk-london-1 not subscribed at all


def test_expand_to_subtrees_excludes_descendants_not_just_the_configured_id() -> None:
    """excluding a parent compartment must exclude its whole subtree -- a child
    compartment not itself listed in exclude_ocids must still be excluded when its
    parent is."""

    tenancy = "ocid1.tenancy.oc1..t1"
    compartments = [
        _compartment("parent", tenancy),
        _compartment("child", "parent"),
        _compartment("grandchild", "child"),
        _compartment("unrelated", tenancy),
    ]
    expanded = _expand_to_subtrees(compartments, {"parent"})
    assert expanded == {"parent", "child", "grandchild"}
    assert "unrelated" not in expanded


def test_expand_to_subtrees_no_exclusions_is_empty() -> None:
    compartments = [_compartment("a", "tenancy")]
    assert _expand_to_subtrees(compartments, set()) == set()


def test_expand_to_subtrees_excluded_leaf_has_no_descendants() -> None:
    compartments = [_compartment("a", "tenancy"), _compartment("b", "tenancy")]
    assert _expand_to_subtrees(compartments, {"a"}) == {"a"}


def test_resolve_regions_api_failure_treats_all_configured_as_unready() -> None:
    """A failed list_region_subscriptions call is an API failure, not a subscription fact --
    every configured region must be treated as unproven, never silently approved."""

    app_config = _app_config_with_allow("us-ashburn-1", "eu-frankfurt-1")
    op = OperationResult(
        service="identity", operation="list_region_subscriptions", region="us-ashburn-1",
        compartment_id=None, status="failed", error_code="ServiceError",
    )
    approved, unready = _resolve_regions(app_config, op)
    assert approved == ()
    assert unready == ("us-ashburn-1", "eu-frankfurt-1")


def _discovery(**overrides: object) -> DiscoveryResult:
    defaults: dict[str, object] = dict(
        tenancy=None,
        region_subscriptions=[],
        all_compartments=[],
        discovery_region="us-ashburn-1",
        approved_regions=("us-ashburn-1",),
        unready_regions=(),
        approved_compartment_ids=("c1", "c2", "c3"),
        excluded_compartment_ids=(),
        inaccessible_compartment_ids=(),
        availability_domains_by_region={},
        operations=[],
    )
    defaults.update(overrides)
    return DiscoveryResult(**defaults)  # type: ignore[arg-type]


def test_limit_for_sample_caps_to_first_n_sorted_compartments() -> None:
    """Sorted, not insertion order -- the same subset is picked on every run
    regardless of what order list_compartments happened to return them in."""

    discovery = _discovery(approved_compartment_ids=("c3", "c1", "c4", "c2"))
    limited = limit_for_sample(discovery, max_compartments=2)
    assert limited.approved_compartment_ids == ("c1", "c2")


def test_limit_for_sample_noop_when_already_within_cap() -> None:
    discovery = _discovery(approved_compartment_ids=("c1", "c2"))
    limited = limit_for_sample(discovery, max_compartments=5)
    assert limited.approved_compartment_ids == ("c1", "c2")


def test_limit_for_sample_only_changes_compartment_ids() -> None:
    """Every other discovery field -- regions, tenancy, operations -- passes through
    untouched; sampling narrows scope, it doesn't change what discovery itself found."""

    discovery = _discovery(approved_regions=("us-ashburn-1", "us-phoenix-1"))
    limited = limit_for_sample(discovery, max_compartments=1)
    assert limited.approved_regions == ("us-ashburn-1", "us-phoenix-1")
    assert limited.approved_compartment_ids == ("c1",)
