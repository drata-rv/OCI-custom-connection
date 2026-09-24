from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.identity import collect_identity
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False, identity=False,
    )
    base.update(overrides)
    return OciServicesConfig(**base)


@pytest.fixture
def discovery() -> SimpleNamespace:
    return SimpleNamespace(
        discovery_region="us-ashburn-1",
        tenancy=SimpleNamespace(id="ocid1.tenancy.oc1..tenancy1"),
        approved_compartment_ids=("ocid1.compartment.oc1..c1", "ocid1.compartment.oc1..c2"),
    )


def test_disabled_by_default_never_calls_oci(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    client = MagicMock()
    monkeypatch.setattr(
        "oci_drata.collection.identity.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_identity(signer=MagicMock(), discovery=discovery, services=_services())

    assert result.users == []
    assert result.policies == []
    assert result.complete
    client.list_users.assert_not_called()


def test_collect_identity_merges_users_keys_and_policies(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    user1 = oci.identity.models.User(id="u1", compartment_id="tenancy1", is_mfa_activated=True)
    user2 = oci.identity.models.User(id="u2", compartment_id="tenancy1", is_mfa_activated=False)
    key1 = oci.identity.models.ApiKey(key_id="key1", user_id="u1", fingerprint="aa:bb")
    policy_c1 = oci.identity.models.Policy(id="pol1", compartment_id="c1", statements=["Allow ..."])
    policy_c2 = oci.identity.models.Policy(id="pol2", compartment_id="c2", statements=["Allow ..."])

    client = MagicMock()
    client.list_users.return_value = _response(data=[user1, user2])

    def api_keys_side_effect(**kwargs):
        keys = {"u1": [key1], "u2": []}[kwargs["user_id"]]
        return _response(data=keys)

    def policies_side_effect(**kwargs):
        policies = {
            "ocid1.compartment.oc1..c1": [policy_c1],
            "ocid1.compartment.oc1..c2": [policy_c2],
        }[kwargs["compartment_id"]]
        return _response(data=policies)

    client.list_api_keys.side_effect = api_keys_side_effect
    client.list_policies.side_effect = policies_side_effect

    monkeypatch.setattr(
        "oci_drata.collection.identity.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_identity(signer=MagicMock(), discovery=discovery, services=_services(identity=True))

    assert {u.id for u in result.users} == {"u1", "u2"}
    assert [k.key_id for k in result.api_keys_by_user_id["u1"]] == ["key1"]
    assert result.api_keys_by_user_id["u2"] == []
    assert {p.id for p in result.policies} == {"pol1", "pol2"}
    assert result.complete
    client.list_users.assert_called_once_with(compartment_id="ocid1.tenancy.oc1..tenancy1")


def test_no_tenancy_skips_list_users_but_does_not_crash(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """discovery.tenancy is None when get_tenancy failed upstream (see discovery.py) --
    list_users requires a real tenancy OCID as compartment_id, so this must degrade to
    an empty user list rather than pass compartment_id=None to the OCI SDK."""

    discovery.tenancy = None
    client = MagicMock()
    client.list_policies.return_value = _response(data=[])
    monkeypatch.setattr(
        "oci_drata.collection.identity.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_identity(signer=MagicMock(), discovery=discovery, services=_services(identity=True))

    assert result.users == []
    client.list_users.assert_not_called()


def test_failed_list_users_marks_incomplete(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    client = MagicMock()
    client.list_users.side_effect = oci.exceptions.ServiceError(
        status=403, code="NotAuthorizedOrNotFound", headers={}, message="not authorized"
    )
    client.list_policies.return_value = _response(data=[])
    monkeypatch.setattr(
        "oci_drata.collection.identity.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_identity(signer=MagicMock(), discovery=discovery, services=_services(identity=True))

    assert not result.complete
