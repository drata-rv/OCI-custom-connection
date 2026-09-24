from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from oci_drata.collection.discovery import _discovery_region, _expand_to_subtrees, _resolve_regions, discover
from oci_drata.oci_auth import TenancySigner
from oci_drata.pagination import OperationResult


def _compartment(id_: str, parent_id: str, *, lifecycle_state: str = "ACTIVE") -> SimpleNamespace:
    return SimpleNamespace(id=id_, compartment_id=parent_id, lifecycle_state=lifecycle_state, is_accessible=True)


def test_discovery_region_uses_signer_config_region_not_allow_list_first_entry() -> None:
    """allow[0] may be misspelled/unsubscribed with no diagnostic; the signer's
    config region is already validated (required + pattern-checked), so use that instead."""

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
    """Excluding a parent must exclude its whole subtree, even children not
    themselves listed in exclude_ocids."""

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
    """A failed list_region_subscriptions call must leave every configured region
    unproven -- none get silently approved."""

    app_config = _app_config_with_allow("us-ashburn-1", "eu-frankfurt-1")
    op = OperationResult(
        service="identity", operation="list_region_subscriptions", region="us-ashburn-1",
        compartment_id=None, status="failed", error_code="ServiceError",
    )
    approved, unready = _resolve_regions(app_config, op)
    assert approved == ()
    assert unready == ("us-ashburn-1", "eu-frankfurt-1")


# -- discover(): compartment_id_in_subtree is only ever valid on the tenancy root
# (oci.identity.IdentityClient.list_compartments's own documented constraint) --


def _response(data) -> MagicMock:
    return MagicMock(data=data, headers={})


def _app_config(*, roots: tuple[str, ...], tenancy_ocid: str = "ocid1.tenancy.oc1..t1") -> SimpleNamespace:
    return SimpleNamespace(
        oci=SimpleNamespace(
            expected_tenancy_ocid=tenancy_ocid,
            regions=SimpleNamespace(allow=("us-ashburn-1",)),
            compartments=SimpleNamespace(roots=roots, exclude_ocids=()),
        )
    )


@pytest.fixture
def identity_client() -> MagicMock:
    client = MagicMock()
    client.get_tenancy.return_value = _response(SimpleNamespace(id="ocid1.tenancy.oc1..t1"))
    client.list_region_subscriptions.return_value = _response(
        [SimpleNamespace(region_name="us-ashburn-1", status="READY")]
    )
    client.list_availability_domains.return_value = _response([])
    return client


def test_discover_calls_list_compartments_exactly_once_against_the_tenancy_root(
    monkeypatch: pytest.MonkeyPatch, identity_client: MagicMock
) -> None:
    """Regardless of how many roots are configured, compartment_id_in_subtree=True can
    only ever be requested against the tenancy itself -- one call, always tenancy-scoped."""

    monkeypatch.setattr(
        "oci_drata.collection.discovery.regional_client",
        lambda client_cls, signer, *, region: identity_client,
    )
    identity_client.list_compartments.return_value = _response([
        _compartment("c1", "ocid1.tenancy.oc1..t1"),
        _compartment("c2", "ocid1.tenancy.oc1..t1"),
    ])

    app_config = _app_config(roots=("tenancy", "ocid1.compartment.oc1..some-other-root"))
    discover(TenancySigner(base_config={"region": "us-ashburn-1"}), app_config)

    assert identity_client.list_compartments.call_count == 1
    call_kwargs = identity_client.list_compartments.call_args.kwargs
    assert call_kwargs["compartment_id"] == "ocid1.tenancy.oc1..t1"
    assert call_kwargs["compartment_id_in_subtree"] is True


def test_discover_non_tenancy_root_scopes_to_its_own_subtree_only(
    monkeypatch: pytest.MonkeyPatch, identity_client: MagicMock
) -> None:
    """A non-tenancy root must only see its own descendants; siblings returned by
    the necessarily tenancy-wide list_compartments call must not leak into approved_compartment_ids."""

    monkeypatch.setattr(
        "oci_drata.collection.discovery.regional_client",
        lambda client_cls, signer, *, region: identity_client,
    )
    tenancy = "ocid1.tenancy.oc1..t1"
    root = "ocid1.compartment.oc1..root"
    identity_client.list_compartments.return_value = _response([
        _compartment(root, tenancy),
        _compartment("child-of-root", root),
        _compartment("grandchild-of-root", "child-of-root"),
        _compartment("unrelated-sibling", tenancy),  # must NOT end up in scope
    ])

    app_config = _app_config(roots=(root,), tenancy_ocid=tenancy)
    result = discover(TenancySigner(base_config={"region": "us-ashburn-1"}), app_config)

    assert set(result.approved_compartment_ids) == {root, "child-of-root", "grandchild-of-root"}
    assert "unrelated-sibling" not in result.approved_compartment_ids
    # the one list_compartments call is still against the tenancy, never the non-tenancy root
    assert identity_client.list_compartments.call_args.kwargs["compartment_id"] == tenancy


