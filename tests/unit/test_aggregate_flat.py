from __future__ import annotations

import datetime
from types import SimpleNamespace

import oci
import pytest

from oci_drata.collection.cloud_guard import CloudGuardCollectionResult
from oci_drata.collection.compute import ComputeCollectionResult
from oci_drata.collection.database_autonomous import AutonomousDatabaseCollectionResult
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.identity import IdentityCollectionResult
from oci_drata.collection.monitoring import MonitoringCollectionResult
from oci_drata.collection.networking import NetworkingCollectionResult
from oci_drata.collection.object_storage import ObjectStorageCollectionResult
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


def _autonomous_database(autonomous_databases=()):
    return AutonomousDatabaseCollectionResult(
        autonomous_databases=list(autonomous_databases),
        autonomous_database_backups=[],
        autonomous_database_dataguard_associations=[],
        autonomous_database_peers_by_adb_id={},
        operations=[],
    )


def _identity(users=(), api_keys_by_user_id=None, policies=()):
    return IdentityCollectionResult(
        users=list(users),
        api_keys_by_user_id=api_keys_by_user_id or {},
        policies=list(policies),
        operations=[],
    )


def _object_storage(buckets=()):
    return ObjectStorageCollectionResult(buckets=list(buckets), operations=[])


def _cloud_guard(configuration=None):
    return CloudGuardCollectionResult(configuration=configuration, operations=[])


def _monitoring(alarms=()):
    return MonitoringCollectionResult(alarms=list(alarms), operations=[])


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
        autonomous_database=_autonomous_database(), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
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
        autonomous_database=_autonomous_database(), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
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
        autonomous_database=_autonomous_database(), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
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
        networking=_networking(), autonomous_database=_autonomous_database(), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
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
        networking=_networking(), autonomous_database=_autonomous_database(), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )
    assert [r["id"] for r in result.records] == ["i-a", "i-b", "i-c"]


def test_domain_complete_and_discovery_complete_pass_through() -> None:
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(complete=False), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )
    assert result.records == []
    assert result.domain_complete == {
        "compute": True, "networking": True, "autonomousDatabase": True,
        "identity": True, "objectStorage": True, "cloudGuard": True, "monitoring": True,
    }
    assert result.discovery_complete is False


def test_autonomous_database_reports_raw_kms_and_endpoint_facts() -> None:
    """No verdict here either -- kmsKeyId/publicEndpointHostname are raw facts a
    Custom Test evaluates (e.g. kmsKeyId exist equal false), not a precomputed
    'encrypted'/'compliant' boolean."""

    adb = _stamp(
        oci.database.models.AutonomousDatabaseSummary(
            id="adb1", compartment_id="c1", display_name="adb-1", lifecycle_state="AVAILABLE",
            kms_key_id="ocid1.key.oc1..key1", public_endpoint="adb1.example.oraclecloud.com",
        )
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database([adb]), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record["id"] == "adb1"
    assert record["evidenceType"] == "autonomous_database"
    assert record["kmsKeyId"] == "ocid1.key.oc1..key1"
    assert record["publicEndpointHostname"] == "adb1.example.oraclecloud.com"
    assert "status" not in record
    assert validate_record(record, load_flat_schema()).valid


def test_autonomous_database_without_kms_key_reports_null_not_false() -> None:
    adb = _stamp(
        oci.database.models.AutonomousDatabaseSummary(
            id="adb2", compartment_id="c1", lifecycle_state="AVAILABLE",
        )
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database([adb]), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )

    record = result.records[0]
    assert record["kmsKeyId"] is None
    assert record["publicEndpointHostname"] is None


def test_instance_and_autonomous_database_records_sort_together_by_id() -> None:
    instance = _stamp(
        oci.core.models.Instance(id="z-instance", compartment_id="c1", lifecycle_state="RUNNING")
    )
    adb = _stamp(
        oci.database.models.AutonomousDatabaseSummary(
            id="a-adb", compartment_id="c1", lifecycle_state="AVAILABLE",
        )
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([instance]),
        networking=_networking(), autonomous_database=_autonomous_database([adb]), identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )
    assert [r["id"] for r in result.records] == ["a-adb", "z-instance"]
    assert [r["evidenceType"] for r in result.records] == ["autonomous_database", "instance"]


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


# -- Identity (iam_user/api_key/iam_policy) -- opt-in, broader trust footprint --


def _user(user_id, *, mfa, name="alice"):
    return oci.identity.models.User(
        id=user_id, compartment_id="c1", name=name, is_mfa_activated=mfa, lifecycle_state="ACTIVE",
    )


def test_iam_user_reports_raw_mfa_fact_not_a_verdict() -> None:
    user = _user("u1", mfa=False)
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity([user]), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(), completed_at=COMPLETED_AT,
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record["id"] == "u1"
    assert record["evidenceType"] == "iam_user"
    assert record["mfaActivated"] is False
    assert "status" not in record
    assert validate_record(record, load_flat_schema()).valid


def test_deleted_users_and_their_api_keys_are_excluded() -> None:
    active_user = _user("u1", mfa=True)
    deleted_user = oci.identity.models.User(
        id="u2", compartment_id="c1", name="bob", is_mfa_activated=False, lifecycle_state="DELETED",
    )
    api_key = oci.identity.models.ApiKey(
        key_id="key1", user_id="u1", fingerprint="aa:bb:cc",
        time_created=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC), lifecycle_state="ACTIVE",
    )
    orphaned_key_on_deleted_user = oci.identity.models.ApiKey(
        key_id="key2", user_id="u2", fingerprint="dd:ee:ff",
        time_created=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC), lifecycle_state="ACTIVE",
    )

    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(
            [active_user, deleted_user],
            api_keys_by_user_id={"u1": [api_key], "u2": [orphaned_key_on_deleted_user]},
        ), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )

    ids = {r["id"] for r in result.records}
    assert ids == {"u1", "key1"}


def test_api_key_reports_raw_creation_timestamp_for_rotation_age_checks() -> None:
    user = _user("u1", mfa=True)
    api_key = oci.identity.models.ApiKey(
        key_id="ocid1.apikey.oc1..key1", user_id="u1", fingerprint="aa:bb:cc:dd",
        time_created=datetime.datetime(2020, 6, 1, tzinfo=datetime.UTC), lifecycle_state="ACTIVE",
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity([user], api_keys_by_user_id={"u1": [api_key]}), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )

    key_record = next(r for r in result.records if r["evidenceType"] == "api_key")
    assert key_record["id"] == "ocid1.apikey.oc1..key1"
    assert key_record["userId"] == "u1"
    assert key_record["keyCreatedAt"] == "2020-06-01T00:00:00Z"
    assert "status" not in key_record  # no precomputed "rotation overdue" verdict
    assert validate_record(key_record, load_flat_schema()).valid


def test_iam_policy_reports_raw_statements() -> None:
    policy = oci.identity.models.Policy(
        id="pol1", compartment_id="c1", name="AdminPolicy", lifecycle_state="ACTIVE",
        statements=["Allow group Administrators to manage all-resources in tenancy"],
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(policies=[policy]), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(), completed_at=COMPLETED_AT,
    )

    record = result.records[0]
    assert record["evidenceType"] == "iam_policy"
    assert record["statements"] == ["Allow group Administrators to manage all-resources in tenancy"]
    assert validate_record(record, load_flat_schema()).valid


def test_identity_disabled_by_default_yields_no_identity_records() -> None:
    """collect_identity()'s own _skip_result() is exercised in test_identity_collector.py --
    this confirms build_flat_records produces nothing extra when identity is empty,
    the shape it's in when oci.services.identity is off."""

    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(), object_storage=_object_storage(), cloud_guard=_cloud_guard(), monitoring=_monitoring(), completed_at=COMPLETED_AT,
    )
    assert result.records == []


# -- Object storage buckets -- raw facts only, no "encrypted"/"compliant" verdict --


def test_bucket_reports_raw_public_access_and_kms_facts() -> None:
    bucket = _stamp(
        oci.object_storage.models.Bucket(
            id="ocid1.bucket.oc1..b1", compartment_id="c1", name="prod-data", namespace="ns1",
            public_access_type="ObjectRead", kms_key_id="ocid1.key.oc1..key1", versioning="Enabled",
        )
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(), object_storage=_object_storage([bucket]), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record["id"] == "ocid1.bucket.oc1..b1"
    assert record["evidenceType"] == "bucket"
    assert record["publicAccessType"] == "ObjectRead"
    assert record["kmsKeyId"] == "ocid1.key.oc1..key1"
    assert record["versioning"] == "Enabled"
    assert "status" not in record
    assert validate_record(record, load_flat_schema()).valid


def test_bucket_without_kms_key_reports_null_not_false() -> None:
    bucket = _stamp(
        oci.object_storage.models.Bucket(
            id="ocid1.bucket.oc1..b2", compartment_id="c1", name="no-cmk", namespace="ns1",
            public_access_type="NoPublicAccess", versioning="Disabled",
        )
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(), object_storage=_object_storage([bucket]), cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )

    record = result.records[0]
    assert record["kmsKeyId"] is None
    assert record["publicAccessType"] == "NoPublicAccess"


# -- Cloud Guard configuration -- singleton, no id/compartmentId of its own --


def test_cloud_guard_reports_raw_status_using_tenancy_id() -> None:
    configuration = oci.cloud_guard.models.Configuration(status="ENABLED")
    discovery = DiscoveryResult(
        tenancy=SimpleNamespace(id="ocid1.tenancy.oc1..tenancy1"),
        region_subscriptions=[], all_compartments=[], discovery_region="us-ashburn-1",
        approved_regions=("us-ashburn-1",), unready_regions=(), approved_compartment_ids=("c1",),
        excluded_compartment_ids=(), inaccessible_compartment_ids=(),
        availability_domains_by_region={}, operations=[],
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=discovery, compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(), object_storage=_object_storage(),
        cloud_guard=_cloud_guard(configuration), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record["id"] == "ocid1.tenancy.oc1..tenancy1"
    assert record["evidenceType"] == "cloud_guard_configuration"
    assert record["cloudGuardStatus"] == "ENABLED"
    assert "status" not in record
    assert validate_record(record, load_flat_schema()).valid


def test_cloud_guard_disabled_by_default_yields_no_record() -> None:
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(), object_storage=_object_storage(),
        cloud_guard=_cloud_guard(), monitoring=_monitoring(),
        completed_at=COMPLETED_AT,
    )
    assert result.records == []


# -- Monitoring alarms -- raw enabled/namespace/query, evidence-style like iam_policy --


def test_alarm_reports_raw_enabled_and_query_facts() -> None:
    alarm = _stamp(
        oci.monitoring.models.AlarmSummary(
            id="ocid1.alarm.oc1..a1", compartment_id="c1", display_name="cpu-high",
            is_enabled=True, namespace="oci_computeagent",
            query="CpuUtilization[1m].mean() > 80", lifecycle_state="ACTIVE",
        )
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(), object_storage=_object_storage(),
        cloud_guard=_cloud_guard(), monitoring=_monitoring([alarm]),
        completed_at=COMPLETED_AT,
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record["id"] == "ocid1.alarm.oc1..a1"
    assert record["evidenceType"] == "monitoring_alarm"
    assert record["alarmEnabled"] is True
    assert record["alarmNamespace"] == "oci_computeagent"
    assert "status" not in record
    assert validate_record(record, load_flat_schema()).valid


def test_deleted_alarm_is_excluded() -> None:
    alarm = _stamp(
        oci.monitoring.models.AlarmSummary(
            id="ocid1.alarm.oc1..deleted1", compartment_id="c1", is_enabled=False,
            lifecycle_state="DELETED",
        )
    )
    result = build_flat_records(
        decisions=DECISIONS, discovery=_discovery(), compute=_compute([]),
        networking=_networking(), autonomous_database=_autonomous_database(),
        identity=_identity(), object_storage=_object_storage(),
        cloud_guard=_cloud_guard(), monitoring=_monitoring([alarm]),
        completed_at=COMPLETED_AT,
    )
    assert result.records == []
