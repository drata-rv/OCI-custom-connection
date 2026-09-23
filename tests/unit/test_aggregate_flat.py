from __future__ import annotations

import datetime

import oci
import pytest

from oci_drata.collection.compute import ComputeCollectionResult
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.networking import NetworkingCollectionResult
from oci_drata.config import DecisionsConfig
from oci_drata.transform.aggregate import build_flat_records
from oci_drata.validation.schema import load_flat_schema, validate_record

DECISIONS = DecisionsConfig(
    administrative_ports=(22, 3389),
    public_source_cidrs=("0.0.0.0/0", "::/0"),
    minimum_vpn_tunnel_count=2,
    minimum_up_vpn_tunnel_count=1,
    freshness_hours=26,
    require_customer_managed_volume_keys=False,
    require_customer_managed_database_keys=False,
)

COMPLETED_AT = datetime.datetime(2026, 9, 23, 12, 0, 0, tzinfo=datetime.UTC)


def _stamp(raw, region="us-ashburn-1"):
    raw.region = region
    return raw


def _discovery(*, complete: bool = True) -> DiscoveryResult:
    return DiscoveryResult(
        tenancy=None,
        region_subscriptions=[],
        all_compartments=[],
        discovery_region="us-ashburn-1",
        approved_regions=("us-ashburn-1",),
        unready_regions=() if complete else ("us-phoenix-1",),
        approved_compartment_ids=("c1",),
        excluded_compartment_ids=(),
        inaccessible_compartment_ids=(),
        availability_domains_by_region={},
        operations=[],
    )


def _compute(instances, *, vnic_attachments=(), vnics=None, private_ips=(), public_ips_by_private_ip_id=None):
    return ComputeCollectionResult(
        instances=instances,
        images={},
        vnic_attachments=list(vnic_attachments),
        vnics=vnics or {},
        private_ips=list(private_ips),
        public_ips_by_private_ip_id=public_ips_by_private_ip_id or {},
        operations=[],
    )


def _networking(*, subnets=None, route_tables=None, security_lists=None, internet_gateways=None,
                 nsg_security_rules_by_nsg_id=None):
    return NetworkingCollectionResult(
        vcns=[],
        subnets=list((subnets or {}).values()),
        route_tables=list((route_tables or {}).values()),
        internet_gateways=list(internet_gateways or []),
        security_lists=list((security_lists or {}).values()),
        network_security_groups=[],
        nsg_security_rules_by_nsg_id=nsg_security_rules_by_nsg_id or {},
        nsg_vnics_by_nsg_id={},
        operations=[],
    )


def test_exposed_instance_reports_raw_named_port_no_verdict() -> None:
    """No status/compliance verdict anywhere -- the compliance policy (which ports
    count as administrative) belongs in the Drata Custom Test, not the collector."""

    instance = _stamp(
        oci.core.models.Instance(
            id="i-exposed", compartment_id="c1", display_name="exposed-vm", lifecycle_state="RUNNING"
        )
    )
    vnic = _stamp(
        oci.core.models.Vnic(id="v1", compartment_id="c1", subnet_id="sub1", nsg_ids=["nsg1"])
    )
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=[])
    route_table = oci.core.models.RouteTable(
        id="rt1",
        route_rules=[
            oci.core.models.RouteRule(
                destination="0.0.0.0/0", destination_type="CIDR_BLOCK",
                network_entity_id="ocid1.internetgateway.oc1..igw1",
            )
        ],
    )
    nsg_rule = oci.core.models.SecurityRule(
        direction="INGRESS", protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
        tcp_options=oci.core.models.TcpOptions(
            destination_port_range=oci.core.models.PortRange(min=3389, max=3389)
        ),
    )
    igw = oci.core.models.InternetGateway(id="ocid1.internetgateway.oc1..igw1")

    result = build_flat_records(
        decisions=DECISIONS,
        discovery=_discovery(),
        compute=_compute(
            [instance],
            vnic_attachments=[oci.core.models.VnicAttachment(instance_id="i-exposed", vnic_id="v1")],
            vnics={"v1": vnic},
            private_ips=[oci.core.models.PrivateIp(id="p1", vnic_id="v1", ip_address="10.0.0.5")],
            public_ips_by_private_ip_id={"p1": oci.core.models.PublicIp(id="pub1", ip_address="203.0.113.5")},
        ),
        networking=_networking(
            subnets={"sub1": subnet}, route_tables={"rt1": route_table},
            internet_gateways=[igw], nsg_security_rules_by_nsg_id={"nsg1": [nsg_rule]},
        ),
        completed_at=COMPLETED_AT,
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record["id"] == "i-exposed"
    assert record["evidenceType"] == "instance"
    assert "status" not in record
    assert record["hasPublicAddress"] is True
    assert record["publicIngressPorts"] == [3389]
    assert record["hasRangedPublicIngress"] is False
    assert record["timestamp"] == "2026-09-23T12:00:00Z"

    schema_result = validate_record(record, load_flat_schema())
    assert schema_result.valid, schema_result.errors


def test_wide_open_rule_is_not_enumerated_but_flagged() -> None:
    """A rule with no port restriction can't be represented as discrete port
    numbers without enumerating up to 65536 entries -- it must show up as
    hasRangedPublicIngress=True instead of being silently dropped."""

    instance = _stamp(
        oci.core.models.Instance(
            id="i-wide-open", compartment_id="c1", lifecycle_state="RUNNING"
        )
    )
    vnic = _stamp(oci.core.models.Vnic(id="v1", compartment_id="c1", subnet_id="sub1", nsg_ids=["nsg1"]))
    subnet = oci.core.models.Subnet(id="sub1", route_table_id="rt1", security_list_ids=[])
    route_table = oci.core.models.RouteTable(
        id="rt1",
        route_rules=[
            oci.core.models.RouteRule(
                destination="0.0.0.0/0", destination_type="CIDR_BLOCK",
                network_entity_id="ocid1.internetgateway.oc1..igw1",
            )
        ],
    )
    # No tcp_options at all: every port is open.
    nsg_rule = oci.core.models.SecurityRule(
        direction="INGRESS", protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
    )
    igw = oci.core.models.InternetGateway(id="ocid1.internetgateway.oc1..igw1")

    result = build_flat_records(
        decisions=DECISIONS,
        discovery=_discovery(),
        compute=_compute(
            [instance],
            vnic_attachments=[oci.core.models.VnicAttachment(instance_id="i-wide-open", vnic_id="v1")],
            vnics={"v1": vnic},
            private_ips=[oci.core.models.PrivateIp(id="p1", vnic_id="v1", ip_address="10.0.0.5")],
            public_ips_by_private_ip_id={"p1": oci.core.models.PublicIp(id="pub1", ip_address="203.0.113.5")},
        ),
        networking=_networking(
            subnets={"sub1": subnet}, route_tables={"rt1": route_table},
            internet_gateways=[igw], nsg_security_rules_by_nsg_id={"nsg1": [nsg_rule]},
        ),
        completed_at=COMPLETED_AT,
    )

    record = result.records[0]
    assert record["publicIngressPorts"] == []
    assert record["hasRangedPublicIngress"] is True


def test_instance_with_no_public_address_reports_no_ingress() -> None:
    instance = _stamp(
        oci.core.models.Instance(
            id="i-safe", compartment_id="c1", display_name="safe-vm", lifecycle_state="RUNNING"
        )
    )
    vnic = _stamp(oci.core.models.Vnic(id="v1", compartment_id="c1", subnet_id="sub1"))

    result = build_flat_records(
        decisions=DECISIONS,
        discovery=_discovery(),
        compute=_compute(
            [instance],
            vnic_attachments=[oci.core.models.VnicAttachment(instance_id="i-safe", vnic_id="v1")],
            vnics={"v1": vnic},
        ),
        networking=_networking(),
        completed_at=COMPLETED_AT,
    )

    record = result.records[0]
    assert record["hasPublicAddress"] is False
    assert record["publicIngressPorts"] == []
    assert record["hasRangedPublicIngress"] is False
    assert validate_record(record, load_flat_schema()).valid


def test_instance_with_no_vnic_reports_null_facts_not_a_verdict() -> None:
    instance = _stamp(
        oci.core.models.Instance(
            id="i-unresolved", compartment_id="c1", display_name="unattached-vm", lifecycle_state="RUNNING"
        )
    )

    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([instance]),
        networking=_networking(), completed_at=COMPLETED_AT,
    )

    record = result.records[0]
    assert record["hasPublicAddress"] is None
    assert record["publicIngressPorts"] == []
    assert record["hasRangedPublicIngress"] is None
    assert validate_record(record, load_flat_schema()).valid


def test_records_sorted_by_id() -> None:
    instances = [
        _stamp(oci.core.models.Instance(id=i, compartment_id="c1", lifecycle_state="RUNNING"))
        for i in ("i-b", "i-a", "i-c")
    ]
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute(instances),
        networking=_networking(), completed_at=COMPLETED_AT,
    )
    assert [r["id"] for r in result.records] == ["i-a", "i-b", "i-c"]


def test_domain_complete_and_discovery_complete_pass_through() -> None:
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(complete=False), compute=_compute([]),
        networking=_networking(), completed_at=COMPLETED_AT,
    )
    assert result.records == []
    assert result.domain_complete == {"compute": True, "networking": True}
    assert result.discovery_complete is False


def test_flat_schema_is_valid_draft7() -> None:
    import jsonschema

    jsonschema.Draft7Validator.check_schema(load_flat_schema())


def test_flat_schema_rejects_wrong_type_for_has_public_address() -> None:
    record = {
        "id": "i1", "evidenceType": "instance", "name": "vm",
        "timestamp": "2026-09-23T12:00:00Z", "hasPublicAddress": "yes",
    }
    result = validate_record(record, load_flat_schema())
    assert not result.valid


@pytest.mark.parametrize("field", ["status", "exposedAdministrativePorts"])
def test_no_compliance_verdict_fields_in_schema(field: str) -> None:
    schema = load_flat_schema()
    assert field not in schema["properties"]
