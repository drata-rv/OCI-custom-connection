from __future__ import annotations

import oci

from oci_drata.models import Instance, Vnic
from oci_drata.transform.exposure import ExposureConfig, derive_instance_exposure

CONFIG = ExposureConfig(administrative_ports=(22, 3389), public_source_cidrs=("0.0.0.0/0", "::/0"))


def _instance(vnic_ids: tuple[str, ...]) -> Instance:
    return Instance(
        id="i1", source_type="compute_instance", region="us-ashburn-1", compartment_id="c1",
        display_name="vm1", lifecycle_state="RUNNING", vnic_ids=vnic_ids,
    )


def _vnic(vnic_id: str, *, subnet_id: str, public_addresses: tuple[str, ...] = (), nsg_ids: tuple[str, ...] = ()) -> Vnic:
    return Vnic(
        id=vnic_id, source_type="vnic", region="us-ashburn-1", compartment_id="c1",
        display_name=None, lifecycle_state="AVAILABLE", subnet_id=subnet_id,
        nsg_ids=nsg_ids, private_addresses=("10.0.0.5",), public_addresses=public_addresses,
    )


def test_no_vnic_ids_is_unknown() -> None:
    result = derive_instance_exposure(
        [_instance(())], vnics_by_id={}, subnets_by_id={}, route_tables_by_id={},
        security_lists_by_id={}, nsg_security_rules_by_nsg_id={}, internet_gateway_ids=set(),
        config=CONFIG,
    )
    assert result[0].has_public_address is None
    assert result[0].effective_ingress_exposure == "unknown"


def test_no_public_address_is_definitively_not_exposed() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=())
    result = derive_instance_exposure(
        [_instance(("v1",))], vnics_by_id={"v1": vnic}, subnets_by_id={}, route_tables_by_id={},
        security_lists_by_id={}, nsg_security_rules_by_nsg_id={}, internet_gateway_ids=set(),
        config=CONFIG,
    )
    assert result[0].has_public_address is False
    assert result[0].effective_ingress_exposure == "not_exposed"
    assert result[0].exposed_administrative_ports == ()


def test_public_address_but_missing_subnet_is_unknown() -> None:
    vnic = _vnic("v1", subnet_id="sub-missing", public_addresses=("203.0.113.5",))
    result = derive_instance_exposure(
        [_instance(("v1",))], vnics_by_id={"v1": vnic}, subnets_by_id={}, route_tables_by_id={},
        security_lists_by_id={}, nsg_security_rules_by_nsg_id={}, internet_gateway_ids=set(),
        config=CONFIG,
    )
    assert result[0].has_public_address is True
    assert result[0].effective_ingress_exposure == "unknown"


def test_full_exposure_public_igw_route_and_permissive_nsg_rdp() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",), nsg_ids=("nsg1",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=[])
    route_table = oci.core.models.RouteTable(
        id="rt1",
        route_rules=[
            oci.core.models.RouteRule(destination="0.0.0.0/0", destination_type="CIDR_BLOCK", network_entity_id="ocid1.internetgateway.oc1..igw1")
        ],
    )
    nsg_rule = oci.core.models.SecurityRule(
        direction="INGRESS", protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
        tcp_options=oci.core.models.TcpOptions(destination_port_range=oci.core.models.PortRange(min=3389, max=3389)),
    )

    result = derive_instance_exposure(
        [_instance(("v1",))],
        vnics_by_id={"v1": vnic},
        subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table},
        security_lists_by_id={},
        nsg_security_rules_by_nsg_id={"nsg1": [nsg_rule]},
        internet_gateway_ids={"ocid1.internetgateway.oc1..igw1"},
        config=CONFIG,
    )
    assert result[0].has_public_address is True
    assert result[0].effective_ingress_exposure == "exposed"
    assert result[0].exposed_administrative_ports == (3389,)


def test_public_with_igw_but_no_permissive_rule_is_not_exposed() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",), nsg_ids=("nsg1",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=[])
    route_table = oci.core.models.RouteTable(
        id="rt1",
        route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")],
    )
    # NSG rule only opens port 443, not an administrative port.
    nsg_rule = oci.core.models.SecurityRule(
        direction="INGRESS", protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
        tcp_options=oci.core.models.TcpOptions(destination_port_range=oci.core.models.PortRange(min=443, max=443)),
    )
    result = derive_instance_exposure(
        [_instance(("v1",))], vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, security_lists_by_id={},
        nsg_security_rules_by_nsg_id={"nsg1": [nsg_rule]}, internet_gateway_ids={"igw1"},
        config=CONFIG,
    )
    assert result[0].effective_ingress_exposure == "not_exposed"
    assert result[0].exposed_administrative_ports == ()


def test_missing_nsg_membership_evidence_is_unknown_not_not_exposed() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",), nsg_ids=("nsg-unresolved",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=[])
    route_table = oci.core.models.RouteTable(
        id="rt1", route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")]
    )
    result = derive_instance_exposure(
        [_instance(("v1",))], vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, security_lists_by_id={},
        nsg_security_rules_by_nsg_id={},  # nsg-unresolved not present
        internet_gateway_ids={"igw1"}, config=CONFIG,
    )
    assert result[0].effective_ingress_exposure == "unknown"


def test_security_list_permissive_rule_with_null_tcp_options_means_all_ports() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=["sl1"])
    route_table = oci.core.models.RouteTable(
        id="rt1", route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")]
    )
    security_list = oci.core.models.SecurityList(
        id="sl1",
        ingress_security_rules=[
            oci.core.models.IngressSecurityRule(protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK", tcp_options=None)
        ],
    )
    result = derive_instance_exposure(
        [_instance(("v1",))], vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, security_lists_by_id={"sl1": security_list},
        nsg_security_rules_by_nsg_id={}, internet_gateway_ids={"igw1"}, config=CONFIG,
    )
    assert result[0].effective_ingress_exposure == "exposed"
    assert set(result[0].exposed_administrative_ports) == {22, 3389}


def test_non_public_source_cidr_does_not_count_as_exposed() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=["sl1"])
    route_table = oci.core.models.RouteTable(
        id="rt1", route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")]
    )
    security_list = oci.core.models.SecurityList(
        id="sl1",
        ingress_security_rules=[
            oci.core.models.IngressSecurityRule(protocol="6", source="10.0.0.0/8", source_type="CIDR_BLOCK", tcp_options=None)
        ],
    )
    result = derive_instance_exposure(
        [_instance(("v1",))], vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, security_lists_by_id={"sl1": security_list},
        nsg_security_rules_by_nsg_id={}, internet_gateway_ids={"igw1"}, config=CONFIG,
    )
    assert result[0].effective_ingress_exposure == "not_exposed"
