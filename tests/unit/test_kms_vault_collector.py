from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.kms_vault import collect_kms_vault
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
        identity=False, object_storage=False, cloud_guard=False, monitoring=False,
        load_balancer=False, waf=False, kms_vault=False,
    )
    base.update(overrides)
    return OciServicesConfig(**base)


@pytest.fixture
def discovery() -> SimpleNamespace:
    return SimpleNamespace(
        approved_regions=("us-ashburn-1",),
        approved_compartment_ids=("ocid1.compartment.oc1..c1",),
    )


def test_disabled_by_default_never_calls_oci(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    vault_client = MagicMock()
    monkeypatch.setattr(
        "oci_drata.collection.kms_vault.regional_client", lambda client_cls, signer, *, region: vault_client
    )
    endpoint_client = MagicMock()
    monkeypatch.setattr("oci_drata.collection.kms_vault.endpoint_client", endpoint_client)

    result = collect_kms_vault(signer=MagicMock(), discovery=discovery, services=_services())

    assert result.vaults == []
    assert result.keys == []
    assert result.complete
    vault_client.list_vaults.assert_not_called()
    endpoint_client.assert_not_called()


def test_collect_kms_vault_builds_a_management_client_per_vault_endpoint(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """KmsManagementClient can't be built the way every other collector's client
    is -- it needs the specific vault's own management_endpoint, resolved from
    list_vaults's own response, not a plain regional endpoint."""

    vault1 = oci.key_management.models.VaultSummary(
        id="v1", compartment_id="c1", management_endpoint="https://v1.kms.example.com",
    )
    vault_client = MagicMock()
    vault_client.list_vaults.return_value = _response(data=[vault1])
    monkeypatch.setattr(
        "oci_drata.collection.kms_vault.regional_client", lambda client_cls, signer, *, region: vault_client
    )

    management_client = MagicMock()
    key_summary = oci.key_management.models.KeySummary(id="k1", compartment_id="c1", vault_id="v1")
    management_client.list_keys.return_value = _response(data=[key_summary])
    full_key = oci.key_management.models.Key(id="k1", compartment_id="c1", vault_id="v1", is_auto_rotation_enabled=True)
    management_client.get_key.return_value = _response(data=full_key)

    endpoint_client_calls = []

    def _endpoint_client(client_cls, signer, *, region, service_endpoint):
        endpoint_client_calls.append((region, service_endpoint))
        return management_client

    monkeypatch.setattr("oci_drata.collection.kms_vault.endpoint_client", _endpoint_client)

    result = collect_kms_vault(signer=MagicMock(), discovery=discovery, services=_services(kms_vault=True))

    assert [v.id for v in result.vaults] == ["v1"]
    assert [k.id for k in result.keys] == ["k1"]
    assert result.keys[0].is_auto_rotation_enabled is True
    assert endpoint_client_calls == [("us-ashburn-1", "https://v1.kms.example.com")]
    assert result.complete


def test_vault_with_no_management_endpoint_is_skipped_without_crashing(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    vault_without_endpoint = oci.key_management.models.VaultSummary(id="v1", compartment_id="c1")
    vault_client = MagicMock()
    vault_client.list_vaults.return_value = _response(data=[vault_without_endpoint])
    monkeypatch.setattr(
        "oci_drata.collection.kms_vault.regional_client", lambda client_cls, signer, *, region: vault_client
    )
    endpoint_client = MagicMock()
    monkeypatch.setattr("oci_drata.collection.kms_vault.endpoint_client", endpoint_client)

    result = collect_kms_vault(signer=MagicMock(), discovery=discovery, services=_services(kms_vault=True))

    assert [v.id for v in result.vaults] == ["v1"]
    assert result.keys == []
    endpoint_client.assert_not_called()
    assert result.complete


def test_failed_list_vaults_marks_incomplete(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    vault_client = MagicMock()
    vault_client.list_vaults.side_effect = oci.exceptions.ServiceError(
        status=404, code="NotFound", headers={}, message="not found"
    )
    monkeypatch.setattr(
        "oci_drata.collection.kms_vault.regional_client", lambda client_cls, signer, *, region: vault_client
    )

    result = collect_kms_vault(signer=MagicMock(), discovery=discovery, services=_services(kms_vault=True))

    assert not result.complete
    assert result.vaults == []
