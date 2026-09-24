from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.waf import collect_waf
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
        identity=False, object_storage=False, cloud_guard=False, monitoring=False,
        load_balancer=False, waf=False,
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
    monkeypatch.setattr("oci_drata.collection.waf.regional_client", lambda client_cls, signer, *, region: client)

    result = collect_waf(signer=MagicMock(), discovery=discovery, services=_services())

    assert result.web_app_firewalls == []
    assert result.complete
    client.list_web_app_firewalls.assert_not_called()


def test_collect_waf_returns_load_balancer_joined_firewalls(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    waf1 = oci.waf.models.WebAppFirewallLoadBalancerSummary(
        id="w1", compartment_id="c1", backend_type="LOAD_BALANCER", load_balancer_id="lb1",
    )
    client = MagicMock()
    # list_web_app_firewalls returns a WebAppFirewallCollection wrapper, not a bare
    # list -- confirmed live against a real tenancy (paginate()'s generic "response.data
    # or []" assumption crashes on the real shape with TypeError: not iterable).
    client.list_web_app_firewalls.return_value = _response(
        data=oci.waf.models.WebAppFirewallCollection(items=[waf1])
    )
    monkeypatch.setattr("oci_drata.collection.waf.regional_client", lambda client_cls, signer, *, region: client)

    result = collect_waf(signer=MagicMock(), discovery=discovery, services=_services(waf=True))

    assert [w.id for w in result.web_app_firewalls] == ["w1"]
    assert result.web_app_firewalls[0].load_balancer_id == "lb1"
    assert result.web_app_firewalls[0].region == "us-ashburn-1"
    assert result.complete
    client.list_web_app_firewalls.assert_called_once_with(compartment_id="ocid1.compartment.oc1..c1")


def test_failed_list_marks_incomplete(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    client = MagicMock()
    client.list_web_app_firewalls.side_effect = oci.exceptions.ServiceError(
        status=404, code="NotFound", headers={}, message="not found"
    )
    monkeypatch.setattr("oci_drata.collection.waf.regional_client", lambda client_cls, signer, *, region: client)

    result = collect_waf(signer=MagicMock(), discovery=discovery, services=_services(waf=True))

    assert not result.complete
    assert result.web_app_firewalls == []
