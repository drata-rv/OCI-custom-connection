from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.load_balancer import collect_load_balancer
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
        identity=False, object_storage=False, cloud_guard=False, monitoring=False,
        load_balancer=False,
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
        "oci_drata.collection.load_balancer.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_load_balancer(signer=MagicMock(), discovery=discovery, services=_services())

    assert result.load_balancers == []
    assert result.complete
    client.list_load_balancers.assert_not_called()


def test_collect_load_balancer_fans_out_backend_set_health_per_pair(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """list_load_balancers already returns full LoadBalancer objects with backend
    set names -- get_backend_set_health is a separate per-(lb, backend_set_name)
    call, not something list_load_balancers gives for free."""

    lb1 = oci.load_balancer.models.LoadBalancer(
        id="lb1", compartment_id="c1", is_private=False,
        backend_sets={
            "bs1": oci.load_balancer.models.BackendSet(name="bs1"),
            "bs2": oci.load_balancer.models.BackendSet(name="bs2"),
        },
    )
    client = MagicMock()
    client.list_load_balancers.return_value = _response(data=[lb1])

    def health_side_effect(**kwargs):
        status = {"bs1": "OK", "bs2": "CRITICAL"}[kwargs["backend_set_name"]]
        return _response(data=oci.load_balancer.models.BackendSetHealth(status=status))

    client.get_backend_set_health.side_effect = health_side_effect

    monkeypatch.setattr(
        "oci_drata.collection.load_balancer.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_load_balancer(signer=MagicMock(), discovery=discovery, services=_services(load_balancer=True))

    assert [lb.id for lb in result.load_balancers] == ["lb1"]
    assert result.backend_set_health_by_key[("lb1", "bs1")].status == "OK"
    assert result.backend_set_health_by_key[("lb1", "bs2")].status == "CRITICAL"
    assert result.complete
    client.list_load_balancers.assert_called_once_with(compartment_id="ocid1.compartment.oc1..c1")


def test_failed_list_load_balancers_marks_incomplete(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    client = MagicMock()
    client.list_load_balancers.side_effect = oci.exceptions.ServiceError(
        status=404, code="NotFound", headers={}, message="not found"
    )
    monkeypatch.setattr(
        "oci_drata.collection.load_balancer.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_load_balancer(signer=MagicMock(), discovery=discovery, services=_services(load_balancer=True))

    assert not result.complete
    assert result.load_balancers == []
    client.get_backend_set_health.assert_not_called()
