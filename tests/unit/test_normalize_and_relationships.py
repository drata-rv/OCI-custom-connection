from __future__ import annotations

import datetime

import oci
import pytest

from oci_drata.transform import normalize, relationships


def _stamp(obj, region="us-ashburn-1"):
    obj.region = region
    return obj


def test_normalize_timestamp_utc_z_suffix() -> None:
    dt = datetime.datetime(2026, 9, 8, 20, 0, 0, tzinfo=datetime.UTC)
    assert normalize.normalize_timestamp(dt) == "2026-09-08T20:00:00Z"


def test_normalize_timestamp_converts_non_utc_to_utc() -> None:
    tz = datetime.timezone(datetime.timedelta(hours=-5))
    dt = datetime.datetime(2026, 9, 8, 15, 0, 0, tzinfo=tz)
    assert normalize.normalize_timestamp(dt) == "2026-09-08T20:00:00Z"


def test_normalize_timestamp_none_passthrough() -> None:
    assert normalize.normalize_timestamp(None) is None


def test_normalize_timestamp_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="naive"):
        normalize.normalize_timestamp(datetime.datetime(2026, 9, 8, 20, 0, 0))


def test_flatten_defined_tags() -> None:
    flat = normalize._flatten_defined_tags({"Operations": {"CostCenter": "42"}})
    assert flat == {"Operations.CostCenter": "42"}


def test_normalize_instance_requires_region_stamp() -> None:
    raw = oci.core.models.Instance(id="i1", compartment_id="c1", lifecycle_state="RUNNING")
    with pytest.raises(ValueError, match="not region-stamped"):
        normalize.normalize_instance(raw)


def test_normalize_common_does_not_crash_on_unrecognized_lifecycle_state() -> None:
    """The OCI SDK's own enum-typed property setters silently coerce any value outside
    their known set to the literal sentinel "UNKNOWN_ENUM_VALUE" -- a genuinely new OCI
    lifecycle state (added after this SDK version was pinned) never reaches our code as its
    real name; the SDK has already discarded it one layer down. This codebase's fields are
    typed plain str (not a closed Python Enum) specifically so it never crashes or drops a
    resource over an unrecognized value -- but "preserve unknown enum values" only means
    "pass through whatever the SDK gives us", not "recover the SDK's own already-lost data"."""

    raw = _stamp(
        oci.core.models.Vcn(id="vcn1", compartment_id="c1", lifecycle_state="SOME_FUTURE_STATE_V2")
    )
    normalized = normalize.normalize_common(raw, source_type="vcn")
    assert normalized.lifecycle_state == "UNKNOWN_ENUM_VALUE"


def test_normalize_instance_basic_fields() -> None:
    raw = _stamp(
        oci.core.models.Instance(
            id="ocid1.instance.oc1..i1",
            compartment_id="ocid1.compartment.oc1..c1",
            display_name="vm1",
            lifecycle_state="RUNNING",
            image_id="ocid1.image.oc1..img1",
        )
    )
    normalized = normalize.normalize_instance(raw)
    assert normalized.id == "ocid1.instance.oc1..i1"
    assert normalized.region == "us-ashburn-1"
    assert normalized.image_id == "ocid1.image.oc1..img1"
    assert normalized.os_classification == "unknown"


def test_normalize_vnic_requires_subnet_id() -> None:
    raw = _stamp(oci.core.models.Vnic(id="v1", compartment_id="c1"))
    with pytest.raises(ValueError, match="subnet_id"):
        normalize.normalize_vnic(raw)


def test_normalize_volume_customer_managed_key_present() -> None:
    """list_volumes/list_boot_volumes return the full Volume/BootVolume type, not a
    lighter-weight summary -- kms_key_id is authoritative, so absent must resolve to a
    definite False (no CMK), never None/unknown."""

    with_key = _stamp(
        oci.core.models.Volume(
            id="vol1", compartment_id="c1", lifecycle_state="AVAILABLE", kms_key_id="key1"
        )
    )
    without_key = _stamp(
        oci.core.models.Volume(id="vol2", compartment_id="c1", lifecycle_state="AVAILABLE")
    )
    assert normalize.normalize_volume(with_key, source_type="block_volume").customer_managed_key_present is True
    assert normalize.normalize_volume(without_key, source_type="block_volume").customer_managed_key_present is False


def test_normalize_db_backup_status_variants() -> None:
    enabled = oci.database.models.DatabaseSummary(
        id="db1", db_backup_config=oci.database.models.DbBackupConfig(auto_backup_enabled=True)
    )
    disabled = oci.database.models.DatabaseSummary(
        id="db2", db_backup_config=oci.database.models.DbBackupConfig(auto_backup_enabled=False)
    )
    unknown = oci.database.models.DatabaseSummary(id="db3")
    assert normalize.normalize_db_backup_status(enabled) == "enabled"
    assert normalize.normalize_db_backup_status(disabled) == "disabled"
    assert normalize.normalize_db_backup_status(unknown) == "unknown"


def test_normalize_autonomous_database_posture_full_fields() -> None:
    raw = oci.database.models.AutonomousDatabaseSummary(
        id="a1",
        public_endpoint="adb.example.oraclecloudapps.com",
        private_endpoint="10.0.0.5",
        whitelisted_ips=["203.0.113.0/24", "198.51.100.0/24"],
        is_mtls_connection_required=True,
        nsg_ids=["nsg1"],
        backup_retention_period_in_days=30,
        is_backup_retention_locked=True,
        long_term_backup_schedule=oci.database.models.LongTermBackUpScheduleDetails(),
    )
    posture = normalize.normalize_autonomous_database_posture(raw)
    assert posture == {
        "public_endpoint_hostname": "adb.example.oraclecloudapps.com",
        "private_endpoint_configured": True,
        "public_endpoint_present": True,
        "access_control_enabled": True,
        "allowed_source_count": 2,
        "mtls_required": True,
        "network_security_group_ids": ("nsg1",),
        "backup_retention_days": 30,
        "backup_retention_locked": True,
        "long_term_backup_schedule_configured": True,
    }


def test_normalize_autonomous_database_posture_no_endpoint_data_resolves_definite_false() -> None:
    """Oracle always returns these fields for an existing ADB; None means "no public endpoint" etc,
    a fact we know, not an unresolvable unknown -- unlike raw retention/mTLS fields, which pass
    None through as-is since those genuinely can be absent on legacy records."""

    raw = oci.database.models.AutonomousDatabaseSummary(id="a2")
    posture = normalize.normalize_autonomous_database_posture(raw)
    assert posture["public_endpoint_hostname"] is None
    assert posture["public_endpoint_present"] is False
    assert posture["private_endpoint_configured"] is False
    assert posture["access_control_enabled"] is False
    assert posture["allowed_source_count"] == 0
    assert posture["long_term_backup_schedule_configured"] is False
    assert posture["backup_retention_days"] is None
    assert posture["backup_retention_locked"] is None
    assert posture["mtls_required"] is None


def test_normalize_autonomous_database_posture_public_endpoint_string_not_coerced_to_bool() -> None:
    """A raw hostname string must never land in a bool field."""
    raw = oci.database.models.AutonomousDatabaseSummary(id="a3", public_endpoint="host.example.com")
    posture = normalize.normalize_autonomous_database_posture(raw)
    assert posture["public_endpoint_hostname"] == "host.example.com"
    assert posture["public_endpoint_present"] is True
    assert isinstance(posture["public_endpoint_present"], bool)


def test_normalize_db_system_detail_preserves_shape_version_redundancy() -> None:
    raw = oci.database.models.DbSystemSummary(
        id="sys1", shape="VM.Standard2.4", version="19.0.0.0", os_version="7.9",
        node_count=2, disk_redundancy="HIGH", subnet_id="sub1", nsg_ids=["nsg1", "nsg2"],
    )
    detail = normalize.normalize_db_system_detail(raw)
    assert detail == {
        "shape": "VM.Standard2.4",
        "version": "19.0.0.0",
        "os_version": "7.9",
        "node_count": 2,
        "disk_redundancy": "HIGH",
        "subnet_id": "sub1",
        "network_security_group_ids": ("nsg1", "nsg2"),
    }


def test_normalize_database_detail_preserves_backup_and_patch_fields() -> None:
    now = datetime.datetime(2026, 9, 8, 20, 0, 0, tzinfo=datetime.UTC)
    raw = oci.database.models.DatabaseSummary(
        id="db1", last_backup_timestamp=now, patch_version="OCT2025",
        db_backup_config=oci.database.models.DbBackupConfig(auto_backup_enabled=True, recovery_window_in_days=14),
        database_management_config=oci.database.models.DatabaseManagementConfig(
            database_management_status="ENABLED"
        ),
    )
    detail = normalize.normalize_database_detail(raw)
    assert detail["last_backup_timestamp"] == "2026-09-08T20:00:00Z"
    assert detail["last_failed_backup_timestamp"] is None
    assert detail["patch_version"] == "OCT2025"
    assert detail["recovery_window_days"] == 14
    assert detail["database_management_status"] == "ENABLED"


def test_normalize_database_detail_no_backup_config_is_null_not_error() -> None:
    raw = oci.database.models.DatabaseSummary(id="db2")
    detail = normalize.normalize_database_detail(raw)
    assert detail["recovery_window_days"] is None
    assert detail["database_management_status"] is None


def test_normalize_data_guard_detail_preserves_role_and_protection_mode() -> None:
    raw = oci.database.models.DataGuardAssociation(
        id="dg1", database_id="db1", role="PRIMARY", peer_role="STANDBY",
        protection_mode="MAXIMUM_AVAILABILITY", transport_type="SYNC",
    )
    detail = normalize.normalize_data_guard_detail(raw)
    assert detail == {
        "data_guard_role": "PRIMARY",
        "data_guard_peer_role": "STANDBY",
        "data_guard_protection_mode": "MAXIMUM_AVAILABILITY",
        "data_guard_transport_type": "SYNC",
    }


def test_normalize_route_table_preserves_route_rules() -> None:
    raw = _stamp(
        oci.core.models.RouteTable(
            id="rt1", compartment_id="c1",
            route_rules=[
                oci.core.models.RouteRule(
                    destination="0.0.0.0/0", destination_type="CIDR_BLOCK",
                    network_entity_id="ocid1.internetgateway.oc1..igw1", description="default route",
                )
            ],
        )
    )
    normalized = normalize.normalize_route_table(raw)
    assert len(normalized.route_rules) == 1
    rule = normalized.route_rules[0]
    assert rule.destination == "0.0.0.0/0"
    assert rule.network_entity_id == "ocid1.internetgateway.oc1..igw1"
    assert rule.description == "default route"


def test_normalize_security_list_preserves_ingress_and_egress_rules() -> None:
    raw = _stamp(
        oci.core.models.SecurityList(
            id="sl1", compartment_id="c1",
            ingress_security_rules=[
                oci.core.models.IngressSecurityRule(
                    protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK", is_stateless=False,
                    tcp_options=oci.core.models.TcpOptions(
                        destination_port_range=oci.core.models.PortRange(min=22, max=22)
                    ),
                )
            ],
            egress_security_rules=[
                oci.core.models.EgressSecurityRule(
                    protocol="all", destination="0.0.0.0/0", destination_type="CIDR_BLOCK",
                )
            ],
        )
    )
    normalized = normalize.normalize_security_list(raw)
    assert len(normalized.ingress_rules) == 1
    assert normalized.ingress_rules[0].direction == "ingress"
    assert normalized.ingress_rules[0].source == "0.0.0.0/0"
    assert normalized.ingress_rules[0].tcp_port_range == normalize.PortRange(min=22, max=22)
    assert len(normalized.egress_rules) == 1
    assert normalized.egress_rules[0].direction == "egress"
    assert normalized.egress_rules[0].destination == "0.0.0.0/0"


def test_normalize_network_security_group_preserves_joined_security_rules() -> None:
    raw = _stamp(oci.core.models.NetworkSecurityGroup(id="nsg1", compartment_id="c1"))
    rules = [
        oci.core.models.SecurityRule(
            direction="INGRESS", protocol="6", source="203.0.113.0/24", source_type="CIDR_BLOCK",
            tcp_options=oci.core.models.TcpOptions(
                destination_port_range=oci.core.models.PortRange(min=3389, max=3389)
            ),
        )
    ]
    normalized = normalize.normalize_network_security_group(raw, security_rules=rules)
    assert len(normalized.security_rules) == 1
    rule = normalized.security_rules[0]
    assert rule.direction == "ingress"  # normalized to lowercase
    assert rule.source == "203.0.113.0/24"
    assert rule.tcp_port_range == normalize.PortRange(min=3389, max=3389)


def test_normalize_internet_gateway_preserves_enabled_and_vcn() -> None:
    raw = _stamp(
        oci.core.models.InternetGateway(id="igw1", compartment_id="c1", is_enabled=True, vcn_id="vcn1")
    )
    normalized = normalize.normalize_internet_gateway(raw)
    assert normalized.is_enabled is True
    assert normalized.vcn_id == "vcn1"


class TestClassifyWindows:
    def test_windows_image(self) -> None:
        raw = _stamp(
            oci.core.models.Instance(id="i1", compartment_id="c1", image_id="img1", lifecycle_state="RUNNING")
        )
        images = {"img1": oci.core.models.Image(id="img1", operating_system="Windows Server")}
        result = relationships.classify_windows([normalize.normalize_instance(raw)], images)
        assert result[0].os_classification == "windows"

    def test_non_windows_image(self) -> None:
        raw = _stamp(
            oci.core.models.Instance(id="i1", compartment_id="c1", image_id="img1", lifecycle_state="RUNNING")
        )
        images = {"img1": oci.core.models.Image(id="img1", operating_system="Oracle Linux")}
        result = relationships.classify_windows([normalize.normalize_instance(raw)], images)
        assert result[0].os_classification == "non_windows"

    def test_missing_image_is_unknown_not_non_windows(self) -> None:
        raw = _stamp(
            oci.core.models.Instance(id="i1", compartment_id="c1", image_id="img-missing", lifecycle_state="RUNNING")
        )
        result = relationships.classify_windows([normalize.normalize_instance(raw)], images={})
        assert result[0].os_classification == "unknown"

    def test_no_image_id_is_unknown(self) -> None:
        raw = _stamp(oci.core.models.Instance(id="i1", compartment_id="c1", lifecycle_state="RUNNING"))
        result = relationships.classify_windows([normalize.normalize_instance(raw)], images={})
        assert result[0].os_classification == "unknown"


def test_resolve_instance_network_and_storage_joins() -> None:
    instance = normalize.normalize_instance(
        _stamp(oci.core.models.Instance(id="i1", compartment_id="c1", lifecycle_state="RUNNING"))
    )
    vnic_attachment = oci.core.models.VnicAttachment(id="att1", instance_id="i1", vnic_id="v1")
    boot_attachment = oci.core.models.BootVolumeAttachment(id="ba1", instance_id="i1", boot_volume_id="bv1")
    volume_attachment = oci.core.models.VolumeAttachment(id="va1", instance_id="i1", volume_id="vol1")

    resolved, unresolved = relationships.resolve_instance_network_and_storage(
        [instance],
        vnic_attachments=[vnic_attachment],
        boot_volume_attachments=[boot_attachment],
        volume_attachments=[volume_attachment],
    )
    assert resolved[0].vnic_ids == ("v1",)
    assert resolved[0].volume_ids == ("bv1", "vol1")
    assert unresolved == []


def test_resolve_instance_network_unresolved_when_instance_missing() -> None:
    orphan_attachment = oci.core.models.VnicAttachment(id="att1", instance_id="ghost", vnic_id="v1")
    _, unresolved = relationships.resolve_instance_network_and_storage(
        [], vnic_attachments=[orphan_attachment], boot_volume_attachments=[], volume_attachments=[]
    )
    assert len(unresolved) == 1
    assert unresolved[0].target_id == "ghost"


def test_resolve_vnic_addresses_aggregates_private_and_public() -> None:
    vnic = normalize.normalize_vnic(_stamp(oci.core.models.Vnic(id="v1", compartment_id="c1", subnet_id="sub1")))
    attachment = oci.core.models.VnicAttachment(id="att1", instance_id="i1", vnic_id="v1")
    private_ip = oci.core.models.PrivateIp(id="pip1", vnic_id="v1", ip_address="10.0.0.5")
    public_ip = oci.core.models.PublicIp(id="pub1", ip_address="203.0.113.5")

    resolved, unresolved = relationships.resolve_vnic_addresses(
        [vnic],
        vnic_attachments=[attachment],
        private_ips=[private_ip],
        public_ips_by_private_ip_id={"pip1": public_ip},
    )
    assert resolved[0].instance_id == "i1"
    assert resolved[0].private_addresses == ("10.0.0.5",)
    assert resolved[0].public_addresses == ("203.0.113.5",)
    assert unresolved == []


def test_resolve_base_database_relationship_chain() -> None:
    raw_system = oci.database.models.DbSystemSummary(id="sys1", compartment_id="c1", shape="VM.Standard2.1")
    raw_home = oci.database.models.DbHomeSummary(id="home1", compartment_id="c1", db_system_id="sys1")
    raw_db = oci.database.models.DatabaseSummary(id="db1", compartment_id="c1", db_home_id="home1")
    raw_backup = oci.database.models.BackupSummary(id="bkp1", compartment_id="c1", database_id="db1")
    raw_dg = oci.database.models.DataGuardAssociation(id="dg1", database_id="db1")

    for r in (raw_system, raw_home, raw_db, raw_backup):
        _stamp(r)
    _stamp(raw_dg)

    db_system = normalize.normalize_database_resource(raw_system, database_type="base_db_system", source_type="db_system")
    db_home = normalize.normalize_database_resource(raw_home, database_type="db_home", source_type="db_home")
    database = normalize.normalize_database_resource(raw_db, database_type="base_database", source_type="database")
    backup = normalize.normalize_database_resource(raw_backup, database_type="backup", source_type="backup")
    dg = normalize.normalize_database_resource(
        raw_dg, database_type="data_guard", source_type="data_guard_association", compartment_id="unknown-until-resolved"
    )

    (
        db_systems, db_homes, databases, backups, dgs, unresolved
    ) = relationships.resolve_base_database_relationships(
        raw_db_systems=[raw_system], db_systems=[db_system],
        raw_db_homes=[raw_home], db_homes=[db_home],
        raw_databases=[raw_db], databases=[database],
        raw_backups=[raw_backup], backups=[backup],
        raw_data_guard_associations=[raw_dg], data_guard_associations=[dg],
    )

    assert unresolved == []
    # db_home link is bidirectional: parent db_system and child database.
    assert set(db_homes[0].related_resource_ids) == {"sys1", "db1"}
    assert set(db_systems[0].related_resource_ids) == {"home1"}
    assert set(databases[0].related_resource_ids) == {"home1", "bkp1", "dg1"}
    assert backups[0].related_resource_ids == ("db1",)
    # compartment_id backfilled from parent database.
    assert dgs[0].compartment_id == "c1"
    assert dgs[0].related_resource_ids == ("db1",)


def test_resolve_base_database_relationship_records_unresolved_when_parent_missing() -> None:
    raw_backup = oci.database.models.BackupSummary(id="bkp1", compartment_id="c1", database_id="ghost-db")
    _stamp(raw_backup)
    backup = normalize.normalize_database_resource(raw_backup, database_type="backup", source_type="backup")

    _, _, _, backups, _, unresolved = relationships.resolve_base_database_relationships(
        raw_db_systems=[], db_systems=[],
        raw_db_homes=[], db_homes=[],
        raw_databases=[], databases=[],
        raw_backups=[raw_backup], backups=[backup],
        raw_data_guard_associations=[], data_guard_associations=[],
    )
    assert len(unresolved) == 1
    assert unresolved[0].target_id == "ghost-db"
    # Raw OCID reference is preserved even when unresolved.
    assert backups[0].related_resource_ids == ("ghost-db",)


def test_resolve_autonomous_database_relationships_folds_peers() -> None:
    raw_adb = _stamp(oci.database.models.AutonomousDatabaseSummary(id="adb1", compartment_id="c1"))
    adb = normalize.normalize_database_resource(raw_adb, database_type="autonomous_database", source_type="autonomous_database")

    peer = oci.database.models.AutonomousDatabasePeerSummary(id="adb2", region="us-phoenix-1")

    adbs, backups, dgs, unresolved = relationships.resolve_autonomous_database_relationships(
        autonomous_databases=[adb],
        raw_autonomous_database_backups=[],
        autonomous_database_backups=[],
        raw_autonomous_database_dataguard_associations=[],
        autonomous_database_dataguard_associations=[],
        autonomous_database_peers_by_adb_id={"adb1": [peer]},
    )
    assert unresolved == []
    assert adbs[0].related_resource_ids == ("adb2",)
