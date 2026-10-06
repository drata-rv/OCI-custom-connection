"""build_flat_records: the per-resource facts a Drata Custom Test evaluates. Facts only --
no compliance verdict, and an unknown fact is null, never a guessed false."""

from __future__ import annotations

import datetime

import oci

from oci_drata.collection.cloud_guard import CloudGuardCollectionResult
from oci_drata.collection.compute import ComputeCollectionResult
from oci_drata.collection.database_autonomous import AutonomousDatabaseCollectionResult
from oci_drata.collection.database_base import DatabaseBaseCollectionResult
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.identity import IdentityCollectionResult
from oci_drata.collection.kms_vault import KmsVaultCollectionResult
from oci_drata.collection.load_balancer import LoadBalancerCollectionResult
from oci_drata.collection.monitoring import MonitoringCollectionResult
from oci_drata.collection.networking import NetworkingCollectionResult
from oci_drata.collection.object_storage import ObjectStorageCollectionResult
from oci_drata.collection.storage import StorageCollectionResult
from oci_drata.collection.vpn import VpnCollectionResult
from oci_drata.collection.waf import WafCollectionResult
from oci_drata.config import DecisionsConfig
from oci_drata.transform.aggregate import FlatRecordsResult, build_flat_records
from oci_drata.validation.schema import load_flat_schema, validate_record

COMPLETED_AT = datetime.datetime(2026, 9, 23, 12, 0, 0, tzinfo=datetime.UTC)


def _stamp(raw, region="us-ashburn-1"):
    raw.region = region
    return raw


def _build(**overrides) -> FlatRecordsResult:
    """Every collector result empty and complete, except what a test overrides."""

    args = dict(
        decisions=DecisionsConfig(),
        discovery=DiscoveryResult(
            tenancy=None, region_subscriptions=[], all_compartments=[], discovery_region="us-ashburn-1",
            approved_regions=("us-ashburn-1",), unready_regions=(), approved_compartment_ids=("c1",),
            excluded_compartment_ids=(), inaccessible_compartment_ids=(),
            operations=[],
        ),
        compute=ComputeCollectionResult(
            instances=[], images={}, vnic_attachments=[], vnics={}, private_ips=[],
            public_ips_by_private_ip_id={}, operations=[],
        ),
        storage=StorageCollectionResult(
            boot_volumes=[], block_volumes=[], boot_volume_attachments=[], volume_attachments=[], operations=[],
        ),
        networking=NetworkingCollectionResult(
            subnets=[], route_tables=[], internet_gateways=[], security_lists=[],
            nsg_security_rules_by_nsg_id={}, operations=[],
        ),
        database_base=DatabaseBaseCollectionResult(
            db_systems=[], db_homes=[], databases=[], data_guard_associations=[], operations=[],
        ),
        autonomous_database=AutonomousDatabaseCollectionResult(autonomous_databases=[], operations=[]),
        vpn=VpnCollectionResult(ip_sec_connections=[], tunnels_by_connection_id={}, operations=[]),
        identity=IdentityCollectionResult(users=[], api_keys_by_user_id={}, policies=[], operations=[]),
        object_storage=ObjectStorageCollectionResult(buckets=[], operations=[]),
        cloud_guard=CloudGuardCollectionResult(configuration=None, operations=[]),
        monitoring=MonitoringCollectionResult(alarms=[], operations=[]),
        load_balancer=LoadBalancerCollectionResult(load_balancers=[], backend_set_health_by_key={}, operations=[]),
        waf=WafCollectionResult(web_app_firewalls=[], operations=[]),
        kms_vault=KmsVaultCollectionResult(vaults=[], keys=[], operations=[]),
        completed_at=COMPLETED_AT,
    )
    args.update(overrides)
    return build_flat_records(**args)


def test_exposed_instance_reports_raw_named_port_no_verdict() -> None:
    """Policy (which ports count as administrative) belongs in the Drata Custom Test."""

    instance = _stamp(
        oci.core.models.Instance(
            id="i-exposed", compartment_id="c1", display_name="exposed-vm", lifecycle_state="RUNNING"
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
    nsg_rule = oci.core.models.SecurityRule(
        direction="INGRESS", protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
        tcp_options=oci.core.models.TcpOptions(
            destination_port_range=oci.core.models.PortRange(min=3389, max=3389)
        ),
    )

    result = _build(
        compute=ComputeCollectionResult(
            instances=[instance], images={},
            vnic_attachments=[oci.core.models.VnicAttachment(instance_id="i-exposed", vnic_id="v1")],
            vnics={"v1": vnic},
            private_ips=[oci.core.models.PrivateIp(id="p1", vnic_id="v1", ip_address="10.0.0.5")],
            public_ips_by_private_ip_id={"p1": oci.core.models.PublicIp(id="pub1", ip_address="203.0.113.5")},
            operations=[],
        ),
        networking=NetworkingCollectionResult(
            subnets=[subnet], route_tables=[route_table],
            internet_gateways=[oci.core.models.InternetGateway(id="ocid1.internetgateway.oc1..igw1")],
            security_lists=[], nsg_security_rules_by_nsg_id={"nsg1": [nsg_rule]}, operations=[],
        ),
    )

    (record,) = result.records
    assert record["id"] == "i-exposed"
    assert record["evidenceType"] == "instance"
    assert "status" not in record
    assert record["hasPublicAddress"] is True
    assert record["publicIngressPorts"] == [3389]
    assert record["hasRangedPublicIngress"] is False
    assert record["timestamp"] == "2026-09-23T12:00:00Z"
    assert validate_record(record, load_flat_schema()).valid


def test_instance_with_no_vnic_reports_null_facts_not_a_verdict() -> None:
    instance = _stamp(
        oci.core.models.Instance(
            id="i-unresolved", compartment_id="c1", display_name="unattached-vm", lifecycle_state="RUNNING"
        )
    )
    result = _build(
        compute=ComputeCollectionResult(
            instances=[instance], images={}, vnic_attachments=[], vnics={}, private_ips=[],
            public_ips_by_private_ip_id={}, operations=[],
        ),
    )

    (record,) = result.records
    assert record["hasPublicAddress"] is None
    assert record["publicIngressPorts"] == []
    assert record["hasRangedPublicIngress"] is None
    assert validate_record(record, load_flat_schema()).valid


def test_deleted_user_and_its_api_keys_are_excluded_and_queued_for_record_deletion() -> None:
    def user(user_id, state):
        return oci.identity.models.User(
            id=user_id, compartment_id="c1", name=user_id, is_mfa_activated=True, lifecycle_state=state
        )

    def key(user_id, fingerprint):
        return oci.identity.models.ApiKey(
            key_id=f"k-{fingerprint}", user_id=user_id, fingerprint=fingerprint,
            time_created=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC), lifecycle_state="ACTIVE",
        )

    result = _build(
        identity=IdentityCollectionResult(
            users=[user("u1", "ACTIVE"), user("u2", "DELETED")],
            api_keys_by_user_id={"u1": [key("u1", "aa:bb")], "u2": [key("u2", "dd:ee")]},
            policies=[], operations=[],
        ),
    )

    assert {r["id"] for r in result.records} == {"u1", "u1/aa:bb"}
    assert result.excluded_ids["iam_user"] == ["u2"]
    assert result.excluded_ids["api_key"] == ["u2/dd:ee"]
