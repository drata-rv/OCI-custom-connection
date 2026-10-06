from __future__ import annotations

import oci

from oci_drata.models import Instance, Vnic
from oci_drata.transform.exposure import derive_public_ingress_facts

PUBLIC_SOURCE_CIDRS = ("0.0.0.0/0", "::/0")


def _instance(vnic_ids: tuple[str, ...]) -> Instance:
    return Instance(id="i1", region="us-ashburn-1", compartment_id="c1", display_name="vm1", vnic_ids=vnic_ids)


def _vnic(vnic_id: str, *, subnet_id: str, public_addresses: tuple[str, ...] = (), nsg_ids: tuple[str, ...] = ()) -> Vnic:
    return Vnic(id=vnic_id, subnet_id=subnet_id, nsg_ids=nsg_ids, public_addresses=public_addresses)


def _facts(instance, **by_id):
    result = derive_public_ingress_facts(
        [instance],
        vnics_by_id=by_id.get("vnics_by_id", {}),
        subnets_by_id=by_id.get("subnets_by_id", {}),
        route_tables_by_id=by_id.get("route_tables_by_id", {}),
        security_lists_by_id=by_id.get("security_lists_by_id", {}),
        nsg_security_rules_by_nsg_id=by_id.get("nsg_security_rules_by_nsg_id", {}),
        internet_gateway_ids=by_id.get("internet_gateway_ids", set()),
        public_source_cidrs=PUBLIC_SOURCE_CIDRS,
    )
    return result[instance.id]


def test_full_exposure_public_igw_route_and_permissive_nsg_named_port() -> None:
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
    result = _facts(
        _instance(("v1",)), vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, nsg_security_rules_by_nsg_id={"nsg1": [nsg_rule]},
        internet_gateway_ids={"ocid1.internetgateway.oc1..igw1"},
    )
    assert result.has_public_address is True
    assert result.public_ingress_ports == (3389,)
    assert result.has_ranged_public_ingress is False


def test_missing_nsg_membership_evidence_is_unknown_not_not_exposed() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",), nsg_ids=("nsg-unresolved",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=[])
    route_table = oci.core.models.RouteTable(
        id="rt1", route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")]
    )
    result = _facts(
        _instance(("v1",)), vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table},
        nsg_security_rules_by_nsg_id={},  # nsg-unresolved not present
        internet_gateway_ids={"igw1"},
    )
    assert result.has_ranged_public_ingress is None


def test_null_tcp_options_means_every_port_is_open_reports_ranged() -> None:
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
    result = _facts(
        _instance(("v1",)), vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, security_lists_by_id={"sl1": security_list},
        internet_gateway_ids={"igw1"},
    )
    assert result.public_ingress_ports == ()
    assert result.has_ranged_public_ingress is True


def test_broad_public_source_not_literally_0_0_0_0_0_still_counts_as_exposed() -> None:
    """A real internet-routable /24, not the literal default CIDR, must still be recognized as public."""
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=["sl1"])
    route_table = oci.core.models.RouteTable(
        id="rt1", route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")]
    )
    security_list = oci.core.models.SecurityList(
        id="sl1",
        ingress_security_rules=[
            oci.core.models.IngressSecurityRule(protocol="6", source="1.2.3.0/24", source_type="CIDR_BLOCK", tcp_options=None),
        ],
    )
    result = _facts(
        _instance(("v1",)), vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, security_lists_by_id={"sl1": security_list},
        internet_gateway_ids={"igw1"},
    )
    assert result.has_ranged_public_ingress is True


def test_nsg_sourced_rule_is_unknown_not_silently_dropped() -> None:
    """No NSG-to-NSG membership chain resolution in this MVP -- must fail closed, not assume not_exposed."""
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",), nsg_ids=("nsg1",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=[])
    route_table = oci.core.models.RouteTable(
        id="rt1", route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")]
    )
    nsg_rule = oci.core.models.SecurityRule(
        direction="INGRESS", protocol="6", source="ocid1.networksecuritygroup.oc1..other",
        source_type="NETWORK_SECURITY_GROUP",
        tcp_options=oci.core.models.TcpOptions(destination_port_range=oci.core.models.PortRange(min=3389, max=3389)),
    )
    result = _facts(
        _instance(("v1",)), vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, nsg_security_rules_by_nsg_id={"nsg1": [nsg_rule]},
        internet_gateway_ids={"igw1"},
    )
    assert result.has_ranged_public_ingress is None


def test_service_cidr_block_source_never_counts_as_public() -> None:
    vnic = _vnic("v1", subnet_id="sub1", public_addresses=("203.0.113.5",))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=["sl1"])
    route_table = oci.core.models.RouteTable(
        id="rt1", route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="igw1")]
    )
    security_list = oci.core.models.SecurityList(
        id="sl1",
        ingress_security_rules=[
            oci.core.models.IngressSecurityRule(
                protocol="6", source="all-iad-objectstorage", source_type="SERVICE_CIDR_BLOCK", tcp_options=None
            ),
        ],
    )
    result = _facts(
        _instance(("v1",)), vnics_by_id={"v1": vnic}, subnets_by_id={"sub1": subnet},
        route_tables_by_id={"rt1": route_table}, security_lists_by_id={"sl1": security_list},
        internet_gateway_ids={"igw1"},
    )
    assert result.public_ingress_ports == ()
    assert result.has_ranged_public_ingress is False


