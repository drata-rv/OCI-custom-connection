from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.monitoring import collect_monitoring
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
        approved_regions=("us-ashburn-1",),
        approved_compartment_ids=("ocid1.compartment.oc1..c1",),
    )


def test_disabled_by_default_never_calls_oci(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    client = MagicMock()
    monkeypatch.setattr(
        "oci_drata.collection.monitoring.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_monitoring(signer=MagicMock(), discovery=discovery, services=_services())

    assert result.alarms == []
    assert result.complete
    client.list_alarms.assert_not_called()


def test_collect_monitoring_merges_alarms_across_compartments(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    alarm1 = oci.monitoring.models.AlarmSummary(id="a1", compartment_id="c1", is_enabled=True)
    client = MagicMock()
    client.list_alarms.return_value = _response(data=[alarm1])
    monkeypatch.setattr(
        "oci_drata.collection.monitoring.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_monitoring(signer=MagicMock(), discovery=discovery, services=_services(monitoring=True))

    assert [a.id for a in result.alarms] == ["a1"]
    assert result.alarms[0].region == "us-ashburn-1"
    assert result.complete
    client.list_alarms.assert_called_once_with(compartment_id="ocid1.compartment.oc1..c1")


def test_failed_list_alarms_marks_incomplete(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    client = MagicMock()
    client.list_alarms.side_effect = oci.exceptions.ServiceError(
        status=404, code="NotFound", headers={}, message="not found"
    )
    monkeypatch.setattr(
        "oci_drata.collection.monitoring.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_monitoring(signer=MagicMock(), discovery=discovery, services=_services(monitoring=True))

    assert not result.complete
