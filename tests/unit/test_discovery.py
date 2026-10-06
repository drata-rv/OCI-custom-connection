from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from oci_drata.collection.discovery import _expand_to_subtrees, discover
from oci_drata.oci_auth import TenancySigner


def _compartment(id_: str, parent_id: str, *, lifecycle_state: str = "ACTIVE") -> SimpleNamespace:
    return SimpleNamespace(id=id_, compartment_id=parent_id, lifecycle_state=lifecycle_state, is_accessible=True)


def _region_sub(name: str, status: str) -> SimpleNamespace:
    return SimpleNamespace(region_name=name, status=status)


def _app_config_with_allow(*regions: str) -> SimpleNamespace:
    return SimpleNamespace(oci=SimpleNamespace(regions=SimpleNamespace(allow=tuple(regions))))


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


