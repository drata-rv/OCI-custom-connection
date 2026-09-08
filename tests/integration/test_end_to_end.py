"""End-to-end mocked collection producing one schema-valid record via
build_snapshot(), validate_record(), check_payload_size(), decide_completeness().
"""

from __future__ import annotations

import datetime

import oci
import pytest

from oci_drata.collection.compute import ComputeCollectionResult
from oci_drata.collection.database_autonomous import AutonomousDatabaseCollectionResult
from oci_drata.collection.database_base import DatabaseBaseCollectionResult
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.exadata_detection import ExadataDetectionResult
from oci_drata.collection.networking import NetworkingCollectionResult
from oci_drata.collection.storage import StorageCollectionResult
from oci_drata.collection.vpn import VpnCollectionResult
from oci_drata.config import (
    AppConfig,
    DecisionsConfig,
    DeploymentConfig,
    DrataConfig,
    OciAuthenticationConfig,
    OciCompartmentsConfig,
    OciConfig,
    OciRegionsConfig,
    OciServicesConfig,
    RuntimeConfig,
    SecretRef,
)
from oci_drata.pagination import OperationResult
from oci_drata.transform.aggregate import build_snapshot
from oci_drata.validation.completeness import decide_completeness
from oci_drata.validation.schema import load_schema, validate_record
from oci_drata.validation.size import check_payload_size

TENANCY_OCID = "ocid1.tenancy.oc1..aaaaaaaatest"
REGION = "us-ashburn-1"
COMPARTMENT_OCID = "ocid1.compartment.oc1..aaaaaaaatest"


def _stamp(obj, region=REGION):
    obj.region = region
    return obj


def _app_config(**decision_overrides) -> AppConfig:
    decisions = dict(
        administrative_ports=(22, 3389),
        public_source_cidrs=("0.0.0.0/0", "::/0"),
        minimum_vpn_tunnel_count=2,
        minimum_up_vpn_tunnel_count=1,
        freshness_hours=26,
        require_customer_managed_volume_keys=False,
        require_customer_managed_database_keys=False,
    )
    decisions.update(decision_overrides)
    return AppConfig(
        deployment=DeploymentConfig(name="test-deployment", snapshot_display_name="Test snapshot"),
        oci=OciConfig(
            authentication=OciAuthenticationConfig(
                type="api_signing_user", config_file="~/.oci/config", profile="DEFAULT",
                private_key_passphrase_secret_ref=None,
            ),
            expected_tenancy_ocid=TENANCY_OCID,
            regions=OciRegionsConfig(allow=(REGION,)),
            compartments=OciCompartmentsConfig(roots=("tenancy",), exclude_ocids=()),
            services=OciServicesConfig(
                compute=True, network_exposure=True, block_storage=True, base_database=True,
                autonomous_database=True, exadata_detection=True, site_to_site_vpn=True,
            ),
        ),
        decisions=DecisionsConfig(**decisions),
        drata=DrataConfig(
            base_url="https://public-api.drata.com/public/v2", connection_id=1, resource_id=2,
            record_id="oci-snapshot-test0123456789abcdef01234567",
            api_token_secret_ref=SecretRef(provider="env", name="DRATA_API_TOKEN"),
        ),
        runtime=RuntimeConfig(max_payload_bytes=4_500_000, max_concurrency=8, log_level="INFO", dry_run=True),
    )


def _discovery(*, complete: bool = True) -> DiscoveryResult:
    tenancy = oci.identity.models.Tenancy(id=TENANCY_OCID, name="Test Tenancy", home_region_key="IAD")
    return DiscoveryResult(
        tenancy=tenancy,
        region_subscriptions=[],
        all_compartments=[
            _stamp(oci.identity.models.Compartment(
                id=COMPARTMENT_OCID, compartment_id=TENANCY_OCID, lifecycle_state="ACTIVE", is_accessible=True
            ))
        ],
        discovery_region=REGION,
        approved_regions=(REGION,),
        unready_regions=(),
        approved_compartment_ids=(COMPARTMENT_OCID,),
        excluded_compartment_ids=(),
        inaccessible_compartment_ids=(),
        availability_domains_by_region={REGION: []},
        operations=[
            OperationResult(service="identity", operation="get_tenancy", region=REGION, compartment_id=None, status="success" if complete else "failed")
        ],
    )


def _empty_ok(service: str) -> OperationResult:
    return OperationResult(service=service, operation="list_x", region=REGION, compartment_id=COMPARTMENT_OCID, status="success")


def _exposed_windows_compute() -> ComputeCollectionResult:
    instance = _stamp(oci.core.models.Instance(
        id="ocid1.instance.oc1..vm1", compartment_id=COMPARTMENT_OCID, display_name="win-vm-1",
        lifecycle_state="RUNNING", image_id="ocid1.image.oc1..img1",
    ))
    image = _stamp(oci.core.models.Image(id="ocid1.image.oc1..img1", compartment_id=COMPARTMENT_OCID, operating_system="Windows Server"))
    attachment = oci.core.models.VnicAttachment(id="ocid1.vnicattachment.oc1..att1", instance_id=instance.id, vnic_id="ocid1.vnic.oc1..v1")
    vnic = _stamp(oci.core.models.Vnic(id="ocid1.vnic.oc1..v1", compartment_id=COMPARTMENT_OCID, subnet_id="ocid1.subnet.oc1..sub1", nsg_ids=["ocid1.networksecuritygroup.oc1..nsg1"]))
    private_ip = _stamp(oci.core.models.PrivateIp(id="ocid1.privateip.oc1..pip1", compartment_id=COMPARTMENT_OCID, vnic_id=vnic.id, ip_address="10.0.0.5"))
    public_ip = _stamp(oci.core.models.PublicIp(id="ocid1.publicip.oc1..pub1", compartment_id=COMPARTMENT_OCID, ip_address="203.0.113.9"))
    return ComputeCollectionResult(
        instances=[instance], images={image.id: image}, vnic_attachments=[attachment],
        vnics={vnic.id: vnic}, private_ips=[private_ip],
        public_ips_by_private_ip_id={private_ip.id: public_ip},
        operations=[_empty_ok("compute")],
    )


def _networking_allowing_rdp() -> NetworkingCollectionResult:
    subnet = _stamp(oci.core.models.Subnet(
        id="ocid1.subnet.oc1..sub1", compartment_id=COMPARTMENT_OCID, route_table_id="ocid1.routetable.oc1..rt1",
        security_list_ids=[],
    ))
    route_table = _stamp(oci.core.models.RouteTable(
        id="ocid1.routetable.oc1..rt1", compartment_id=COMPARTMENT_OCID,
        route_rules=[oci.core.models.RouteRule(destination="0.0.0.0/0", network_entity_id="ocid1.internetgateway.oc1..igw1")],
    ))
    igw = _stamp(oci.core.models.InternetGateway(id="ocid1.internetgateway.oc1..igw1", compartment_id=COMPARTMENT_OCID))
    nsg = _stamp(oci.core.models.NetworkSecurityGroup(id="ocid1.networksecuritygroup.oc1..nsg1", compartment_id=COMPARTMENT_OCID))
    nsg_rule = oci.core.models.SecurityRule(
        direction="INGRESS", protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
        tcp_options=oci.core.models.TcpOptions(destination_port_range=oci.core.models.PortRange(min=3389, max=3389)),
    )
    return NetworkingCollectionResult(
        vcns=[_stamp(oci.core.models.Vcn(id="ocid1.vcn.oc1..vcn1", compartment_id=COMPARTMENT_OCID))],
        subnets=[subnet], route_tables=[route_table], internet_gateways=[igw],
        security_lists=[], network_security_groups=[nsg],
        nsg_security_rules_by_nsg_id={nsg.id: [nsg_rule]},
        nsg_vnics_by_nsg_id={nsg.id: []},
        operations=[_empty_ok("virtual_network")],
    )


def _storage() -> StorageCollectionResult:
    boot_volume = _stamp(oci.core.models.BootVolume(
        id="ocid1.bootvolume.oc1..bv1", compartment_id=COMPARTMENT_OCID, lifecycle_state="AVAILABLE",
        kms_key_id="ocid1.key.oc1..key1",
    ))
    attachment = _stamp(oci.core.models.BootVolumeAttachment(
        id="ocid1.bootvolumeattachment.oc1..bva1", compartment_id=COMPARTMENT_OCID,
        instance_id="ocid1.instance.oc1..vm1", boot_volume_id=boot_volume.id
    ))
    return StorageCollectionResult(
        boot_volumes=[boot_volume], block_volumes=[], boot_volume_attachments=[attachment],
        volume_attachments=[], operations=[_empty_ok("blockstorage")],
    )


def _database_base_empty() -> DatabaseBaseCollectionResult:
    return DatabaseBaseCollectionResult(
        db_systems=[], db_homes=[], databases=[], backups=[], data_guard_associations=[],
        operations=[_empty_ok("database")],
    )


def _autonomous_database() -> AutonomousDatabaseCollectionResult:
    adb = _stamp(oci.database.models.AutonomousDatabaseSummary(
        id="ocid1.autonomousdatabase.oc1..adb1", compartment_id=COMPARTMENT_OCID, lifecycle_state="AVAILABLE",
        public_endpoint=True, is_dedicated=False, backup_retention_period_in_days=7,
        kms_key_id="ocid1.key.oc1..key2",
    ))
    return AutonomousDatabaseCollectionResult(
        autonomous_databases=[adb], autonomous_database_backups=[],
        autonomous_database_dataguard_associations=[], autonomous_database_peers_by_adb_id={},
        operations=[_empty_ok("database")],
    )


def _exadata_not_detected() -> ExadataDetectionResult:
    return ExadataDetectionResult(
        detected=False, reasons=[], affected_db_system_ids=(), affected_autonomous_database_ids=(),
        cloud_vm_clusters=[], exadata_infrastructures=[], cloud_exadata_infrastructures=[],
        autonomous_exadata_infrastructures=[], operations=[_empty_ok("database")],
    )


def _vpn_non_redundant() -> VpnCollectionResult:
    connection = _stamp(oci.core.models.IPSecConnection(
        id="ocid1.ipsecconnection.oc1..c1", compartment_id=COMPARTMENT_OCID,
        cpe_id="ocid1.cpe.oc1..cpe1", drg_id="ocid1.drg.oc1..drg1",
    ))
    tunnel = _stamp(oci.core.models.IPSecConnectionTunnel(id="ocid1.tunnel.oc1..t1", compartment_id=COMPARTMENT_OCID, status="UP"))
    return VpnCollectionResult(
        ip_sec_connections=[connection], tunnels_by_connection_id={connection.id: [tunnel]},
        cpes=[_stamp(oci.core.models.Cpe(id="ocid1.cpe.oc1..cpe1", compartment_id=COMPARTMENT_OCID))],
        drgs=[_stamp(oci.core.models.Drg(id="ocid1.drg.oc1..drg1", compartment_id=COMPARTMENT_OCID))],
        drg_attachments=[], drg_route_tables_by_drg_id={}, drg_route_rules_by_route_table_id={},
        operations=[_empty_ok("virtual_network")],
    )


def test_complete_collection_produces_one_schema_valid_record() -> None:
    app_config = _app_config()
    now = datetime.datetime(2026, 9, 8, 20, 0, 0, tzinfo=datetime.timezone.utc)

    result = build_snapshot(
        app_config,
        discovery=_discovery(),
        compute=_exposed_windows_compute(),
        storage=_storage(),
        networking=_networking_allowing_rdp(),
        database_base=_database_base_empty(),
        autonomous_database=_autonomous_database(),
        exadata=_exadata_not_detected(),
        vpn=_vpn_non_redundant(),
        started_at=now,
        completed_at=now,
    )

    schema = load_schema()
    schema_result = validate_record(result.record, schema)
    assert schema_result.valid, schema_result.errors

    size_result = check_payload_size(result.record, app_config.runtime.max_payload_bytes)
    assert size_result.within_budget

    decision = decide_completeness(
        discovery_complete=result.discovery_complete,
        unready_regions=(),
        domain_complete=result.domain_complete,
        exadata_detected=result.exadata_detected,
        unresolved_relationship_count=result.unresolved_relationship_count,
        schema_valid=schema_result.valid,
        within_payload_budget=size_result.within_budget,
    )
    assert decision.snapshot_status == "complete"
    assert decision.should_upload is True

    instances = result.record["resources"]["instances"]
    assert len(instances) == 1
    assert instances[0]["osClassification"] == "windows"
    assert instances[0]["effectiveIngressExposure"] == "exposed"
    assert instances[0]["exposedAdministrativePorts"] == [3389]
    assert result.record["metrics"]["internetExposedWindowsVmCount"] == 1

    assert result.record["resources"]["ipsecConnections"][0]["redundancyStatus"] == "not_redundant"
    assert result.record["metrics"]["nonRedundantIpsecConnectionCount"] == 1

    # deterministic: same input produces same output
    result2 = build_snapshot(
        app_config, discovery=_discovery(), compute=_exposed_windows_compute(), storage=_storage(),
        networking=_networking_allowing_rdp(), database_base=_database_base_empty(),
        autonomous_database=_autonomous_database(), exadata=_exadata_not_detected(),
        vpn=_vpn_non_redundant(), started_at=now, completed_at=now,
    )
    assert result.record == result2.record


def test_exadata_detection_blocks_upload_even_when_everything_else_succeeds() -> None:
    app_config = _app_config()
    now = datetime.datetime(2026, 9, 8, 20, 0, 0, tzinfo=datetime.timezone.utc)
    exadata = ExadataDetectionResult(
        detected=True, reasons=["db_system X has Exadata shape"], affected_db_system_ids=("x",),
        affected_autonomous_database_ids=(), cloud_vm_clusters=[], exadata_infrastructures=[],
        cloud_exadata_infrastructures=[], autonomous_exadata_infrastructures=[],
        operations=[_empty_ok("database")],
    )
    result = build_snapshot(
        app_config, discovery=_discovery(), compute=_exposed_windows_compute(), storage=_storage(),
        networking=_networking_allowing_rdp(), database_base=_database_base_empty(),
        autonomous_database=_autonomous_database(), exadata=exadata, vpn=_vpn_non_redundant(),
        started_at=now, completed_at=now,
    )
    schema_result = validate_record(result.record, load_schema())
    assert schema_result.valid, schema_result.errors

    decision = decide_completeness(
        discovery_complete=result.discovery_complete, unready_regions=(),
        domain_complete=result.domain_complete, exadata_detected=result.exadata_detected,
        unresolved_relationship_count=result.unresolved_relationship_count,
        schema_valid=schema_result.valid, within_payload_budget=True,
    )
    assert decision.snapshot_status == "incomplete"
    assert decision.should_upload is False
    assert any("Exadata" in reason for reason in decision.reasons)


def test_failed_operation_blocks_upload() -> None:
    app_config = _app_config()
    now = datetime.datetime(2026, 9, 8, 20, 0, 0, tzinfo=datetime.timezone.utc)
    failed_storage = StorageCollectionResult(
        boot_volumes=[], block_volumes=[], boot_volume_attachments=[], volume_attachments=[],
        operations=[OperationResult(service="blockstorage", operation="list_boot_volumes", region=REGION, compartment_id=COMPARTMENT_OCID, status="failed", error_code="ServiceError")],
    )
    result = build_snapshot(
        app_config, discovery=_discovery(), compute=_exposed_windows_compute(), storage=failed_storage,
        networking=_networking_allowing_rdp(), database_base=_database_base_empty(),
        autonomous_database=_autonomous_database(), exadata=_exadata_not_detected(),
        vpn=_vpn_non_redundant(), started_at=now, completed_at=now,
    )
    schema_result = validate_record(result.record, load_schema())
    decision = decide_completeness(
        discovery_complete=result.discovery_complete, unready_regions=(),
        domain_complete=result.domain_complete, exadata_detected=result.exadata_detected,
        unresolved_relationship_count=result.unresolved_relationship_count,
        schema_valid=schema_result.valid, within_payload_budget=True,
    )
    assert decision.snapshot_status == "incomplete"
    assert decision.should_upload is False
    assert any("storage" in reason for reason in decision.reasons)


def test_oversized_payload_fails_regardless_of_completeness() -> None:
    app_config = _app_config()
    now = datetime.datetime(2026, 9, 8, 20, 0, 0, tzinfo=datetime.timezone.utc)
    result = build_snapshot(
        app_config, discovery=_discovery(), compute=_exposed_windows_compute(), storage=_storage(),
        networking=_networking_allowing_rdp(), database_base=_database_base_empty(),
        autonomous_database=_autonomous_database(), exadata=_exadata_not_detected(),
        vpn=_vpn_non_redundant(), started_at=now, completed_at=now,
    )
    size_result = check_payload_size(result.record, max_bytes=10)
    decision = decide_completeness(
        discovery_complete=True, unready_regions=(), domain_complete={}, exadata_detected=False,
        unresolved_relationship_count=0, schema_valid=True, within_payload_budget=size_result.within_budget,
    )
    assert decision.snapshot_status == "failed"
    assert decision.should_upload is False
