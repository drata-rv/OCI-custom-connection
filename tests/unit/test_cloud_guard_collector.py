from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.cloud_guard import collect_cloud_guard
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
        identity=False, object_storage=False, cloud_guard=False, monitoring=False,
    )
    base.update(overrides)
    return OciServicesConfig(**base)


@pytest.fixture
def discovery() -> SimpleNamespace:
    return SimpleNamespace(
        discovery_region="us-ashburn-1",
        tenancy=SimpleNamespace(id="ocid1.tenancy.oc1..tenancy1"),
    )


def test_disabled_by_default_never_calls_oci(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    client = MagicMock()
    monkeypatch.setattr(
        "oci_drata.collection.cloud_guard.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_cloud_guard(signer=MagicMock(), discovery=discovery, services=_services())

    assert result.configuration is None
    assert result.complete
    client.get_configuration.assert_not_called()


def test_collect_cloud_guard_returns_configuration(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    configuration = oci.cloud_guard.models.Configuration(status="ENABLED")
    client = MagicMock()
    client.get_configuration.return_value = _response(data=configuration)
    monkeypatch.setattr(
        "oci_drata.collection.cloud_guard.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_cloud_guard(signer=MagicMock(), discovery=discovery, services=_services(cloud_guard=True))

    assert result.configuration is configuration
    assert result.complete
    client.get_configuration.assert_called_once_with(compartment_id="ocid1.tenancy.oc1..tenancy1")


def test_no_tenancy_degrades_without_crashing(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    discovery.tenancy = None
    client = MagicMock()
    monkeypatch.setattr(
        "oci_drata.collection.cloud_guard.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_cloud_guard(signer=MagicMock(), discovery=discovery, services=_services(cloud_guard=True))

    assert result.configuration is None
    client.get_configuration.assert_not_called()


def test_failed_get_configuration_marks_incomplete(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    client = MagicMock()
    client.get_configuration.side_effect = oci.exceptions.ServiceError(
        status=404, code="NotFound", headers={}, message="not found"
    )
    monkeypatch.setattr(
        "oci_drata.collection.cloud_guard.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_cloud_guard(signer=MagicMock(), discovery=discovery, services=_services(cloud_guard=True))

    assert not result.complete
    assert result.configuration is None
