"""runner.run() and cli.main() with the collectors mocked at the function boundary:
delivery gating, failure artifacts, output permissions, and every evidenceType end to end."""

from __future__ import annotations

import dataclasses
import json
import stat
from pathlib import Path
from unittest.mock import MagicMock

import oci
import pytest
import yaml

from oci_drata import cli, runner
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
from oci_drata.delivery.drata import DeliveryResult
from oci_drata.pagination import OperationResult
from oci_drata.transform.aggregate import EVIDENCE_TYPE_REQUIRED_DOMAINS
from oci_drata.validation.schema import load_flat_schema, validate_record

TENANCY_OCID = "ocid1.tenancy.oc1..aaaaaaaatest"
REGION = "us-ashburn-1"
COMPARTMENT_OCID = "ocid1.compartment.oc1..aaaaaaaatest"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _stamp(obj, region=REGION):
    obj.region = region
    return obj


def _app_config() -> AppConfig:
    return AppConfig(
        deployment=DeploymentConfig(name="test-deployment"),
        oci=OciConfig(
            authentication=OciAuthenticationConfig(
                type="api_signing_user", config_file="~/.oci/config", profile="DEFAULT",
                private_key_passphrase_secret_ref=None,
            ),
            expected_tenancy_ocid=TENANCY_OCID,
            regions=OciRegionsConfig(allow=(REGION,)),
            compartments=OciCompartmentsConfig(roots=("tenancy",), exclude_ocids=()),
            services=OciServicesConfig(
                compute=True, network_exposure=True, autonomous_database=True,
                block_storage=False, base_database=False, site_to_site_vpn=False,
            ),
        ),
        decisions=DecisionsConfig(),
        drata=DrataConfig(
            base_url="https://public-api.drata.com/public/v2", connection_id=1, resource_id=2,
            api_token_secret_ref=SecretRef(provider="env", name="DRATA_API_TOKEN"),
        ),
        runtime=RuntimeConfig(max_payload_bytes=4_500_000, max_concurrency=8, log_level="INFO", dry_run=True),
    )


def _write_config(tmp_path: Path, *, dry_run: bool) -> Path:
    """config.example.yaml with real-looking IDs, scoped to the collectors the fixture mocks."""

    raw = yaml.safe_load((REPO_ROOT / "config.example.yaml").read_text())
    raw["oci"]["expectedTenancyOcid"] = TENANCY_OCID
    raw["oci"]["regions"]["allow"] = [REGION]
    raw["oci"]["services"].update(blockStorage=False, baseDatabase=False, siteToSiteVpn=False)
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    raw["runtime"]["dryRun"] = dry_run
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


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
    # Terminated instance must be excluded without its dropped attachment surfacing as an unresolved relationship.
    terminated_instance = _stamp(oci.core.models.Instance(
        id="ocid1.instance.oc1..vmold", compartment_id=COMPARTMENT_OCID, display_name="old-vm",
        lifecycle_state="TERMINATED", image_id="ocid1.image.oc1..img1",
    ))
    image = _stamp(oci.core.models.Image(id="ocid1.image.oc1..img1", compartment_id=COMPARTMENT_OCID, operating_system="Windows Server"))
    attachment = oci.core.models.VnicAttachment(id="ocid1.vnicattachment.oc1..att1", instance_id=instance.id, vnic_id="ocid1.vnic.oc1..v1")
    terminated_attachment = oci.core.models.VnicAttachment(
        id="ocid1.vnicattachment.oc1..attold", instance_id=terminated_instance.id, vnic_id="ocid1.vnic.oc1..vold"
    )
    vnic = _stamp(oci.core.models.Vnic(id="ocid1.vnic.oc1..v1", compartment_id=COMPARTMENT_OCID, subnet_id="ocid1.subnet.oc1..sub1", nsg_ids=["ocid1.networksecuritygroup.oc1..nsg1"]))
    private_ip = _stamp(oci.core.models.PrivateIp(id="ocid1.privateip.oc1..pip1", compartment_id=COMPARTMENT_OCID, vnic_id=vnic.id, ip_address="10.0.0.5"))
    public_ip = _stamp(oci.core.models.PublicIp(id="ocid1.publicip.oc1..pub1", compartment_id=COMPARTMENT_OCID, ip_address="203.0.113.9"))
    return ComputeCollectionResult(
        instances=[instance, terminated_instance], images={image.id: image},
        vnic_attachments=[attachment, terminated_attachment],
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
        subnets=[subnet], route_tables=[route_table], internet_gateways=[igw],
        security_lists=[], nsg_security_rules_by_nsg_id={nsg.id: [nsg_rule]},
        operations=[_empty_ok("virtual_network")],
    )


def _autonomous_database() -> AutonomousDatabaseCollectionResult:
    # public_endpoint is a hostname string on the SDK model, never a bool -- don't store it into a boolean schema field.
    adb = _stamp(oci.database.models.AutonomousDatabaseSummary(
        id="ocid1.autonomousdatabase.oc1..adb1", compartment_id=COMPARTMENT_OCID, lifecycle_state="AVAILABLE",
        public_endpoint="adb1.adb.us-ashburn-1.oraclecloudapps.com", is_dedicated=False,
        backup_retention_period_in_days=7, is_backup_retention_locked=False,
        whitelisted_ips=["203.0.113.0/24"], is_mtls_connection_required=True,
        kms_key_id="ocid1.key.oc1..key2",
    ))
    return AutonomousDatabaseCollectionResult(autonomous_databases=[adb], operations=[_empty_ok("database")])


@pytest.fixture
def patched_collectors(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    monkeypatch.setattr(runner, "build_signer", lambda app_config, **kwargs: MagicMock())
    monkeypatch.setattr(runner, "discover", lambda signer, app_config, retry_policy=None: _discovery())
    monkeypatch.setattr(runner, "collect_compute", lambda *a, **k: _exposed_windows_compute())
    monkeypatch.setattr(runner, "collect_networking", lambda *a, **k: _networking_allowing_rdp())
    monkeypatch.setattr(runner, "collect_autonomous_database", lambda *a, **k: _autonomous_database())
    upsert = MagicMock(return_value=[])
    monkeypatch.setattr(runner, "upsert_records", upsert)
    monkeypatch.setattr(runner, "delete_records", MagicMock(return_value=[]))
    return upsert


def test_dry_run_never_calls_drata(patched_collectors: MagicMock) -> None:
    app_config = _app_config()
    result = runner.run(app_config, dry_run=True)
    assert result.uploaded is False
    assert result.report["uploadDecision"] == "skipped_dry_run"
    patched_collectors.assert_not_called()
    assert result.exit_code == runner.EXIT_OK


def test_complete_run_uploads(patched_collectors: MagicMock) -> None:
    patched_collectors.return_value = [
        DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)
    ]
    app_config = _app_config()
    result = runner.run(app_config, dry_run=False)
    assert result.uploaded is True
    assert result.report["uploadDecision"] == "uploaded"
    patched_collectors.assert_called_once()
    assert result.exit_code == runner.EXIT_OK


def test_delivery_failure_blocks_exit_code(patched_collectors: MagicMock) -> None:
    patched_collectors.return_value = [
        DeliveryResult(uploaded=False, created=None, status_code=500, attempts=5, error_class="unexpected")
    ]
    result = runner.run(_app_config(), dry_run=False)
    assert result.uploaded is False
    assert result.report["uploadDecision"] == "delivery_failed"
    assert result.exit_code == runner.EXIT_BLOCKED


def test_run_report_includes_access_summary_with_real_auth_gap(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    failed_networking = NetworkingCollectionResult(
        subnets=[], route_tables=[], internet_gateways=[], security_lists=[], nsg_security_rules_by_nsg_id={},
        operations=[
            OperationResult(
                service="virtual_network", operation="list_subnets", region="us-ashburn-1",
                compartment_id="c1", status="failed", error_code="NotAuthorizedOrNotFound",
            )
        ],
    )
    monkeypatch.setattr(runner, "collect_networking", lambda *a, **k: failed_networking)

    result = runner.run(_app_config(), dry_run=True)
    assert result.report["accessSummary"]["compartmentsWithAuthGap"] == ["c1"]


def test_domain_failure_withholds_only_that_domains_evidence(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    """One failed domain must not zero out delivery for every other domain -- only the
    evidenceTypes that depend on it (see EVIDENCE_TYPE_REQUIRED_DOMAINS) are withheld."""

    failed_networking = NetworkingCollectionResult(
        subnets=[], route_tables=[], internet_gateways=[], security_lists=[], nsg_security_rules_by_nsg_id={},
        operations=[OperationResult(service="virtual_network", operation="list_subnets", region="us-ashburn-1", compartment_id="c1", status="failed")],
    )
    monkeypatch.setattr(runner, "collect_networking", lambda *a, **k: failed_networking)
    patched_collectors.return_value = [DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)]

    result = runner.run(_app_config(), dry_run=False)

    assert result.report["uploadDecision"] == "uploaded_partial"
    assert result.report["domainsWithheld"] == ["networking"]
    delivered_ids = {r["id"] for r in patched_collectors.call_args.args[1]}
    assert delivered_ids == {"ocid1.autonomousdatabase.oc1..adb1"}  # instance withheld, ADB still delivered
    assert result.exit_code == runner.EXIT_OK


def test_all_domains_failing_blocks_upload_entirely(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    monkeypatch.setattr(runner, "discover", lambda signer, app_config, retry_policy=None: _discovery(complete=False))

    result = runner.run(_app_config(), dry_run=False)

    assert result.report["uploadDecision"] == "blocked"
    assert "discovery incomplete" in result.report["blockedReasons"]
    patched_collectors.assert_not_called()
    assert result.exit_code == runner.EXIT_BLOCKED


def test_unresolved_relationship_withholds_only_compute(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    """A dangling vnic_attachment (references an instance outside the collected set)
    folds into compute's own completeness -- it must not withhold unrelated domains
    like autonomousDatabase."""

    dangling = oci.core.models.VnicAttachment(
        id="att-dangling", instance_id="i-does-not-exist", vnic_id="v1", compartment_id="c1",
    )
    compute_with_dangling_attachment = ComputeCollectionResult(
        instances=[], images={}, vnic_attachments=[dangling], vnics={}, private_ips=[],
        public_ips_by_private_ip_id={},
        operations=[OperationResult(service="compute", operation="list_instances", region="us-ashburn-1", compartment_id="c1", status="success")],
    )
    monkeypatch.setattr(runner, "collect_compute", lambda *a, **k: compute_with_dangling_attachment)
    patched_collectors.return_value = [DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)]

    result = runner.run(_app_config(), dry_run=False)

    assert result.report["domainsWithheld"] == ["compute"]
    assert result.report["unresolvedRelationships"] == 1
    delivered_ids = {r["id"] for r in patched_collectors.call_args.args[1]}
    assert delivered_ids == {"ocid1.autonomousdatabase.oc1..adb1"}


def test_dry_run_flag_wins_over_config_needs_no_token_and_writes_owner_only_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    monkeypatch.delenv("DRATA_API_TOKEN", raising=False)
    out = tmp_path / "out"

    # Config says live (dryRun: false); --dry-run must still win, and must not need the token.
    exit_code = cli.main(["--config", str(_write_config(tmp_path, dry_run=False)), "--dry-run", "--out-dir", str(out)])

    assert exit_code == cli.EXIT_OK
    patched_collectors.assert_not_called()
    report = json.loads((out / "collection-report.json").read_text())
    assert report["uploadDecision"] == "skipped_dry_run"
    flat_records = json.loads((out / "flat-records.json").read_text())
    assert {r["id"] for r in flat_records} == {"ocid1.instance.oc1..vm1", "ocid1.autonomousdatabase.oc1..adb1"}
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for name in ("collection-report.json", "flat-records.json"):
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600


def test_missing_drata_token_fails_before_any_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A live run must not spend minutes collecting only to die at the first POST."""

    monkeypatch.delenv("DRATA_API_TOKEN", raising=False)
    monkeypatch.setattr(cli, "run", lambda *a, **k: pytest.fail("collection started without a Drata token"))

    assert cli.main(["--config", str(_write_config(tmp_path, dry_run=False))]) == cli.EXIT_CONFIG_ERROR


def test_unexpected_failure_still_writes_a_failure_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "run", boom)
    out = tmp_path / "out"

    exit_code = cli.main(["--config", str(_write_config(tmp_path, dry_run=True)), "--out-dir", str(out)])

    assert exit_code == cli.EXIT_UNEXPECTED
    report = json.loads((out / "collection-report.json").read_text())
    assert (report["uploadDecision"], report["errorType"], report["error"]) == ("failed", "RuntimeError", "boom")


def test_upload_crash_keeps_the_collected_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    """An unexpected failure during delivery must not discard what the run already collected."""

    monkeypatch.setenv("DRATA_API_TOKEN", "token")
    patched_collectors.side_effect = RuntimeError("network exploded")
    out = tmp_path / "out"

    exit_code = cli.main(["--config", str(_write_config(tmp_path, dry_run=False)), "--out-dir", str(out)])

    assert exit_code == cli.EXIT_BLOCKED
    report = json.loads((out / "collection-report.json").read_text())
    assert report["uploadDecision"] == "delivery_failed"
    assert "network exploded" in report["deliveryError"]
    assert len(json.loads((out / "flat-records.json").read_text())) == 2


def test_output_refuses_to_follow_symlinks(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "out").symlink_to(elsewhere)
    with pytest.raises(RuntimeError, match="symlink"):
        cli._prepare_restricted_output_dir(tmp_path / "out")

    (tmp_path / "report.json").symlink_to(elsewhere / "target.json")
    with pytest.raises(OSError):
        cli._write_restricted(tmp_path / "report.json", b"{}")


# -- --test: sample mode, see pagination.py::RetryPolicy.deadline --


def test_test_mode_skips_stale_record_deletion(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    """A sampled run's absences aren't confirmed deletions -- cleanup must not run
    even when there are excluded ids and the owning domain is deliverable."""

    compute_with_terminated_only = ComputeCollectionResult(
        instances=[
            _stamp(oci.core.models.Instance(id="i-gone", compartment_id="c1", lifecycle_state="TERMINATED"))
        ],
        images={}, vnic_attachments=[], vnics={}, private_ips=[], public_ips_by_private_ip_id={},
        operations=[_empty_ok("compute")],
    )
    monkeypatch.setattr(runner, "collect_compute", lambda *a, **k: compute_with_terminated_only)
    delete_mock = MagicMock(return_value=[])
    monkeypatch.setattr(runner, "delete_records", delete_mock)
    patched_collectors.return_value = [DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)]

    runner.run(_app_config(), dry_run=False, test_mode=True)

    delete_mock.assert_not_called()


# -- Every evidenceType at once --


def _app_config_with_everything_enabled() -> AppConfig:
    app_config = _app_config()
    services = dataclasses.replace(
        app_config.oci.services,
        block_storage=True, base_database=True, site_to_site_vpn=True,
        identity=True, object_storage=True, cloud_guard=True, monitoring=True,
        load_balancer=True, waf=True, kms_vault=True,
    )
    return dataclasses.replace(app_config, oci=dataclasses.replace(app_config.oci, services=services))


def _patch_every_other_collector(monkeypatch: pytest.MonkeyPatch) -> None:
    def patch(name: str, result) -> None:
        monkeypatch.setattr(runner, name, lambda *a, **k: result)

    instance_id = "ocid1.instance.oc1..vm1"
    patch("collect_storage", StorageCollectionResult(
        boot_volumes=[_stamp(oci.core.models.BootVolume(
            id="ocid1.bootvolume.oc1..bv1", compartment_id="c1", display_name="bv1", lifecycle_state="AVAILABLE",
        ))],
        block_volumes=[_stamp(oci.core.models.Volume(
            id="ocid1.volume.oc1..vol1", compartment_id="c1", display_name="vol1", lifecycle_state="AVAILABLE",
            kms_key_id="ocid1.key.oc1..volkey",
        ))],
        boot_volume_attachments=[
            oci.core.models.BootVolumeAttachment(boot_volume_id="ocid1.bootvolume.oc1..bv1", instance_id=instance_id)
        ],
        volume_attachments=[
            oci.core.models.VolumeAttachment(volume_id="ocid1.volume.oc1..vol1", instance_id=instance_id)
        ],
        operations=[],
    ))
    patch("collect_database_base", DatabaseBaseCollectionResult(
        db_systems=[_stamp(oci.database.models.DbSystemSummary(
            id="ocid1.dbsystem.oc1..dbs1", compartment_id="c1", display_name="dbs1", lifecycle_state="AVAILABLE",
            shape="VM.Standard2.2", version="19.0.0.0", disk_redundancy="HIGH", node_count=1,
        ))],
        db_homes=[oci.database.models.DbHomeSummary(
            id="ocid1.dbhome.oc1..h1", db_system_id="ocid1.dbsystem.oc1..dbs1", compartment_id="c1",
            lifecycle_state="AVAILABLE",
        )],
        databases=[_stamp(oci.database.models.DatabaseSummary(
            id="ocid1.database.oc1..db1", compartment_id="c1", db_name="DB1", db_home_id="ocid1.dbhome.oc1..h1",
            lifecycle_state="AVAILABLE",
            db_backup_config=oci.database.models.DbBackupConfig(auto_backup_enabled=True, recovery_window_in_days=30),
        ))],
        data_guard_associations=[oci.database.models.DataGuardAssociationSummary(
            database_id="ocid1.database.oc1..db1", role="PRIMARY", lifecycle_state="AVAILABLE",
        )],
        operations=[],
    ))
    patch("collect_vpn", VpnCollectionResult(
        ip_sec_connections=[_stamp(oci.core.models.IPSecConnection(
            id="ocid1.ipsecconnection.oc1..ip1", compartment_id="c1", display_name="vpn1", lifecycle_state="AVAILABLE",
        ))],
        tunnels_by_connection_id={
            "ocid1.ipsecconnection.oc1..ip1": [
                oci.core.models.IPSecConnectionTunnel(id="t1", status="UP", lifecycle_state="AVAILABLE"),
                oci.core.models.IPSecConnectionTunnel(id="t2", status="DOWN", lifecycle_state="AVAILABLE"),
            ]
        },
        operations=[],
    ))
    patch("collect_identity", IdentityCollectionResult(
        users=[oci.identity.models.User(id="ocid1.user.oc1..u1", compartment_id="c1", is_mfa_activated=True)],
        api_keys_by_user_id={
            "ocid1.user.oc1..u1": [
                oci.identity.models.ApiKey(key_id="ocid1.apikey.oc1..k1", user_id="ocid1.user.oc1..u1", fingerprint="aa:bb")
            ]
        },
        policies=[oci.identity.models.Policy(id="ocid1.policy.oc1..p1", compartment_id="c1", statements=["Allow ..."])],
        operations=[],
    ))
    patch("collect_object_storage", ObjectStorageCollectionResult(
        buckets=[_stamp(oci.object_storage.models.Bucket(
            id="ocid1.bucket.oc1..b1", compartment_id="c1", name="my-bucket", namespace="ns1",
            public_access_type="NoPublicAccess", kms_key_id="ocid1.key.oc1..bucketkey1", versioning="Enabled",
        ))],
        operations=[],
    ))
    patch("collect_cloud_guard", CloudGuardCollectionResult(
        configuration=oci.cloud_guard.models.Configuration(status="ENABLED"), operations=[],
    ))
    patch("collect_monitoring", MonitoringCollectionResult(
        alarms=[_stamp(oci.monitoring.models.AlarmSummary(
            id="ocid1.alarm.oc1..a1", compartment_id="c1", is_enabled=True, namespace="oci_computeagent",
        ))],
        operations=[],
    ))
    patch("collect_load_balancer", LoadBalancerCollectionResult(
        load_balancers=[_stamp(oci.load_balancer.models.LoadBalancer(
            id="ocid1.loadbalancer.oc1..lb1", compartment_id="c1", is_private=False,
            backend_sets={"bs1": oci.load_balancer.models.BackendSet(name="bs1")},
        ))],
        backend_set_health_by_key={
            ("ocid1.loadbalancer.oc1..lb1", "bs1"): oci.load_balancer.models.BackendSetHealth(status="OK")
        },
        operations=[],
    ))
    patch("collect_waf", WafCollectionResult(
        web_app_firewalls=[_stamp(oci.waf.models.WebAppFirewallLoadBalancerSummary(
            id="ocid1.webappfirewall.oc1..w1", compartment_id="c1",
            backend_type="LOAD_BALANCER", load_balancer_id="ocid1.loadbalancer.oc1..lb1",
        ))],
        operations=[],
    ))
    patch("collect_kms_vault", KmsVaultCollectionResult(
        vaults=[oci.key_management.models.VaultSummary(id="ocid1.vault.oc1..v1", compartment_id="c1")],
        keys=[_stamp(oci.key_management.models.Key(
            id="ocid1.key.oc1..kmskey1", compartment_id="c1", vault_id="ocid1.vault.oc1..v1",
            is_auto_rotation_enabled=True,
        ))],
        operations=[],
    ))


def test_every_evidence_type_is_produced_schema_valid_and_collision_free(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    _patch_every_other_collector(monkeypatch)

    result = runner.run(_app_config_with_everything_enabled(), dry_run=True)

    assert {r["evidenceType"] for r in result.records} == set(EVIDENCE_TYPE_REQUIRED_DOMAINS)
    ids = [r["id"] for r in result.records]
    assert len(ids) == len(set(ids)), f"duplicate ids across evidenceTypes: {ids}"
    schema = load_flat_schema()
    invalid = [(r["id"], validate_record(r, schema).errors) for r in result.records]
    assert not [i for i in invalid if i[1]], f"schema-invalid records: {invalid}"
    assert result.report["schemaValid"] is True

    by_type = {r["evidenceType"]: r for r in result.records}
    assert by_type["boot_volume"]["attachedInstanceIds"] == ["ocid1.instance.oc1..vm1"]
    assert by_type["block_volume"]["kmsKeyId"] == "ocid1.key.oc1..volkey"
    assert by_type["database"]["dataGuardRole"] == "PRIMARY"
    assert by_type["database"]["backupStatus"] == "enabled"
    assert (by_type["ipsec_connection"]["tunnelCount"], by_type["ipsec_connection"]["upTunnelCount"]) == (2, 1)
    # Region comes from the collectors' stamp, not a schema-valid null.
    assert all(r["region"] == REGION for r in result.records if r["evidenceType"] not in _TENANCY_LEVEL_TYPES)


_TENANCY_LEVEL_TYPES = {"iam_user", "api_key", "iam_policy", "cloud_guard_configuration"}
