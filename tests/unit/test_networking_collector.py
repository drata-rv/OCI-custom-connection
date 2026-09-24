from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.networking import collect_networking
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
    )
    base.update(overrides)
    return OciServicesConfig(**base)


@pytest.fixture
def discovery() -> SimpleNamespace:
    return SimpleNamespace(
        approved_regions=("us-ashburn-1",), approved_compartment_ids=("ocid1.compartment.oc1..c1",)
    )


def test_collect_networking_merges_concurrent_nsg_results(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """list_network_security_group_security_rules/_vnics per NSG was
    parallelized. Every NSG's rules and vnic membership (two NSGs here) must still be
    correctly keyed and merged regardless of which worker thread produced them."""

    nsg1 = oci.core.models.NetworkSecurityGroup(id="nsg1", compartment_id="c1")
    nsg2 = oci.core.models.NetworkSecurityGroup(id="nsg2", compartment_id="c1")
    rule1 = oci.core.models.SecurityRule(id="rule1", direction="INGRESS", protocol="6")
    rule2 = oci.core.models.SecurityRule(id="rule2", direction="EGRESS", protocol="all")
    vnic_membership1 = oci.core.models.NetworkSecurityGroupVnic(vnic_id="v1")

    client = MagicMock()
    client.list_vcns.return_value = _response(data=[])
    client.list_subnets.return_value = _response(data=[])
    client.list_route_tables.return_value = _response(data=[])
    client.list_internet_gateways.return_value = _response(data=[])
    client.list_security_lists.return_value = _response(data=[])
    client.list_network_security_groups.return_value = _response(data=[nsg1, nsg2])

    def rules_side_effect(**kwargs):
        rules = {"nsg1": [rule1], "nsg2": [rule2]}[kwargs["network_security_group_id"]]
        return _response(data=rules)

    def vnics_side_effect(**kwargs):
        vnics = {"nsg1": [vnic_membership1], "nsg2": []}[kwargs["network_security_group_id"]]
        return _response(data=vnics)

    client.list_network_security_group_security_rules.side_effect = rules_side_effect
    client.list_network_security_group_vnics.side_effect = vnics_side_effect

    monkeypatch.setattr(
        "oci_drata.collection.networking.regional_client",
        lambda client_cls, signer, *, region: client,
    )

    result = collect_networking(
        signer=MagicMock(), discovery=discovery, services=_services(network_exposure=True)
    )

    assert {r.id for r in result.nsg_security_rules_by_nsg_id["nsg1"]} == {"rule1"}
    assert {r.id for r in result.nsg_security_rules_by_nsg_id["nsg2"]} == {"rule2"}
    assert len(result.nsg_vnics_by_nsg_id["nsg1"]) == 1
    assert result.nsg_vnics_by_nsg_id["nsg2"] == []
    assert result.complete
