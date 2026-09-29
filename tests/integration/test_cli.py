"""Tests cli.run() orchestration; collectors mocked at function boundary.
OCI-client-mock level coverage for individual transforms lives in their own unit tests.
"""

from __future__ import annotations

import dataclasses
import json
import stat
import time
from pathlib import Path
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata import cli
from oci_drata.collection.compute import ComputeCollectionResult
from oci_drata.collection.database_autonomous import AutonomousDatabaseCollectionResult
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.networking import NetworkingCollectionResult
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
from oci_drata.pagination import OperationResult, RetryPolicy
from oci_drata.validation.schema import load_flat_schema, validate_record

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
            services=OciServicesConfig(compute=True, network_exposure=True, autonomous_database=True),
        ),
        decisions=DecisionsConfig(**decisions),
        drata=DrataConfig(
            base_url="https://public-api.drata.com/public/v2", connection_id=1, resource_id=2,
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
        vcns=[_stamp(oci.core.models.Vcn(id="ocid1.vcn.oc1..vcn1", compartment_id=COMPARTMENT_OCID))],
        subnets=[subnet], route_tables=[route_table], internet_gateways=[igw],
        security_lists=[], network_security_groups=[nsg],
        nsg_security_rules_by_nsg_id={nsg.id: [nsg_rule]},
        nsg_vnics_by_nsg_id={nsg.id: []},
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
    return AutonomousDatabaseCollectionResult(
        autonomous_databases=[adb], autonomous_database_backups=[],
        autonomous_database_dataguard_associations=[], autonomous_database_peers_by_adb_id={},
        operations=[_empty_ok("database")],
    )


@pytest.fixture
def patched_collectors(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    monkeypatch.setattr(cli, "build_signer", lambda app_config: MagicMock())
    monkeypatch.setattr(cli, "discover", lambda signer, app_config, retry_policy=None: _discovery())
    monkeypatch.setattr(cli, "collect_compute", lambda *a, **k: _exposed_windows_compute())
    monkeypatch.setattr(cli, "collect_networking", lambda *a, **k: _networking_allowing_rdp())
    monkeypatch.setattr(cli, "collect_autonomous_database", lambda *a, **k: _autonomous_database())
    upsert = MagicMock(return_value=[])
    monkeypatch.setattr(cli, "upsert_records", upsert)
    monkeypatch.setattr(cli, "delete_records", MagicMock(return_value=[]))
    return upsert


def test_dry_run_never_calls_drata(patched_collectors: MagicMock) -> None:
    app_config = _app_config()
    result = cli.run(app_config, dry_run=True)
    assert result.uploaded is False
    assert result.report["uploadDecision"] == "skipped_dry_run"
    patched_collectors.assert_not_called()
    assert result.exit_code == cli.EXIT_OK


def test_complete_run_uploads(patched_collectors: MagicMock) -> None:
    patched_collectors.return_value = [
        DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)
    ]
    app_config = _app_config()
    result = cli.run(app_config, dry_run=False)
    assert result.uploaded is True
    assert result.report["uploadDecision"] == "uploaded"
    patched_collectors.assert_called_once()
    assert result.exit_code == cli.EXIT_OK


def test_delivery_failure_blocks_exit_code(patched_collectors: MagicMock) -> None:
    patched_collectors.return_value = [
        DeliveryResult(uploaded=False, created=None, status_code=500, attempts=5, error_class="unexpected")
    ]
    result = cli.run(_app_config(), dry_run=False)
    assert result.uploaded is False
    assert result.report["uploadDecision"] == "delivery_failed"
    assert result.exit_code == cli.EXIT_BLOCKED


# -- _access_summary: distinguishes real access gaps from compartments with no data --


def _op(compartment_id, status="success", error_code=None, item_count=0, service="s", operation="o"):
    return OperationResult(
        service=service, operation=operation, region=None, compartment_id=compartment_id,
        status=status, error_code=error_code, item_count=item_count,
    )


def test_log_operation_failure_summary_aggregates_by_service_operation_error_code(
    caplog: pytest.LogCaptureFixture,
) -> None:
    operations = [
        _op("c1", status="failed", error_code="NotAuthorizedOrNotFound", service="database", operation="list_x"),
        _op("c2", status="failed", error_code="NotAuthorizedOrNotFound", service="database", operation="list_x"),
        _op("c3", status="failed", error_code="NotAuthorizedOrNotFound", service="database", operation="list_x"),
        _op("c4", status="success", service="database", operation="list_x"),
        _op("c5", status="failed", error_code="TooManyRequests", service="compute", operation="list_y"),
    ]
    with caplog.at_level("WARNING", logger="oci_drata.cli"):
        cli._log_operation_failure_summary(operations)

    assert len(caplog.records) == 2
    by_operation = {r.operation: r for r in caplog.records}  # type: ignore[attr-defined]
    assert by_operation["list_x"].occurrences == 3  # type: ignore[attr-defined]
    assert by_operation["list_y"].occurrences == 1  # type: ignore[attr-defined]


def test_access_summary_groups_by_compartment() -> None:
    operations = [
        _op("c1", status="failed", error_code="NotAuthorizedOrNotFound"),
        _op("c1", status="failed", error_code="NotAuthorizedOrNotFound"),  # same compartment, still one entry
        _op("c2", status="success", item_count=5),
        _op("c3", status="success", item_count=0),  # succeeded but genuinely nothing there
        _op("c4", status="failed", error_code="TooManyRequests"),  # transient, not an access gap
    ]
    summary = cli._access_summary(operations)
    assert summary["compartmentsSeen"] == 4
    assert summary["compartmentsWithAuthGap"] == ["c1"]
    assert summary["compartmentsWithRealData"] == ["c2"]


def test_access_summary_excludes_test_mode_deadline_from_auth_gap() -> None:
    """A --test deadline isn't an access gap; conflating them would misreport where
    the real access gap is."""

    operations = [_op("c1", status="failed", error_code="TestModeDeadlineExceeded")]
    summary = cli._access_summary(operations)
    assert summary["compartmentsWithAuthGap"] == []


def test_access_summary_ignores_operations_with_no_compartment() -> None:
    operations = [_op(None, status="success", item_count=3)]
    summary = cli._access_summary(operations)
    assert summary == {"compartmentsSeen": 0, "compartmentsWithAuthGap": [], "compartmentsWithRealData": []}


def test_access_summary_empty_operations() -> None:
    assert cli._access_summary([]) == {
        "compartmentsSeen": 0, "compartmentsWithAuthGap": [], "compartmentsWithRealData": [],
    }


def test_run_report_includes_access_summary_with_real_auth_gap(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    failed_networking = NetworkingCollectionResult(
        vcns=[], subnets=[], route_tables=[], internet_gateways=[], security_lists=[],
        network_security_groups=[], nsg_security_rules_by_nsg_id={}, nsg_vnics_by_nsg_id={},
        operations=[
            OperationResult(
                service="virtual_network", operation="list_subnets", region="us-ashburn-1",
                compartment_id="c1", status="failed", error_code="NotAuthorizedOrNotFound",
            )
        ],
    )
    monkeypatch.setattr(cli, "collect_networking", lambda *a, **k: failed_networking)

    result = cli.run(_app_config(), dry_run=True)
    assert result.report["accessSummary"]["compartmentsWithAuthGap"] == ["c1"]


def test_domain_failure_withholds_only_that_domains_evidence(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    """One failed domain must not zero out delivery for every other domain -- only the
    evidenceTypes that depend on it (see EVIDENCE_TYPE_REQUIRED_DOMAINS) are withheld."""

    failed_networking = NetworkingCollectionResult(
        vcns=[], subnets=[], route_tables=[], internet_gateways=[], security_lists=[],
        network_security_groups=[], nsg_security_rules_by_nsg_id={}, nsg_vnics_by_nsg_id={},
        operations=[OperationResult(service="virtual_network", operation="list_subnets", region="us-ashburn-1", compartment_id="c1", status="failed")],
    )
    monkeypatch.setattr(cli, "collect_networking", lambda *a, **k: failed_networking)
    patched_collectors.return_value = [DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)]

    result = cli.run(_app_config(), dry_run=False)

    assert result.report["uploadDecision"] == "uploaded_partial"
    assert result.report["domainsWithheld"] == ["networking"]
    delivered_ids = {r["id"] for r in patched_collectors.call_args.args[1]}
    assert delivered_ids == {"ocid1.autonomousdatabase.oc1..adb1"}  # instance withheld, ADB still delivered
    assert result.exit_code == cli.EXIT_OK


def test_all_domains_failing_blocks_upload_entirely(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    monkeypatch.setattr(cli, "discover", lambda signer, app_config, retry_policy=None: _discovery(complete=False))

    result = cli.run(_app_config(), dry_run=False)

    assert result.report["uploadDecision"] == "blocked"
    assert "discovery incomplete" in result.report["blockedReasons"]
    patched_collectors.assert_not_called()
    assert result.exit_code == cli.EXIT_BLOCKED


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
    monkeypatch.setattr(cli, "collect_compute", lambda *a, **k: compute_with_dangling_attachment)
    patched_collectors.return_value = [DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)]

    result = cli.run(_app_config(), dry_run=False)

    assert result.report["domainsWithheld"] == ["compute"]
    assert result.report["unresolvedRelationships"] == 1
    delivered_ids = {r["id"] for r in patched_collectors.call_args.args[1]}
    assert delivered_ids == {"ocid1.autonomousdatabase.oc1..adb1"}


def test_dry_run_writes_report_and_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    import yaml

    sample = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"
    raw = yaml.safe_load(sample.read_text())
    raw["oci"]["expectedTenancyOcid"] = "ocid1.tenancy.oc1..aaaaaaaatest"
    raw["oci"]["regions"]["allow"] = ["us-ashburn-1"]
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    config_path.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("DRATA_API_TOKEN", "unused")

    exit_code = cli.main(["--config", str(config_path), "--dry-run", "--out-dir", "out"])
    assert exit_code == cli.EXIT_OK

    report = json.loads((tmp_path / "out" / "collection-report.json").read_text())
    assert report["uploadDecision"] == "skipped_dry_run"
    patched_collectors.assert_not_called()

    out_dir = tmp_path / "out"
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((out_dir / "collection-report.json").stat().st_mode) == 0o600


def test_prepare_restricted_output_dir_tightens_preexisting_permissive_dir(tmp_path: Path) -> None:
    """mkdir's mode only applies at creation -- a directory left over from an older,
    less restrictive run (or created by another process) must still be tightened."""

    out_dir = tmp_path / "out"
    out_dir.mkdir(mode=0o755)
    cli._prepare_restricted_output_dir(out_dir)
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700


def test_prepare_restricted_output_dir_refuses_symlink(tmp_path: Path) -> None:
    real_target = tmp_path / "elsewhere"
    real_target.mkdir()
    symlink = tmp_path / "out"
    symlink.symlink_to(real_target)
    with pytest.raises(RuntimeError, match="symlink"):
        cli._prepare_restricted_output_dir(symlink)


def test_write_restricted_refuses_symlink(tmp_path: Path) -> None:
    real_target = tmp_path / "elsewhere.json"
    real_target.write_text("{}")
    symlink = tmp_path / "snapshot.json"
    symlink.symlink_to(real_target)
    with pytest.raises(OSError):
        cli._write_restricted(symlink, b"{}")


def test_main_returns_config_error_exit_code(tmp_path: Path) -> None:
    exit_code = cli.main(["--config", str(tmp_path / "does-not-exist.yaml")])
    assert exit_code == cli.EXIT_CONFIG_ERROR


# -- --test: sample mode, see pagination.py::RetryPolicy.deadline --


def test_run_test_mode_sets_a_deadline_every_collector_shares(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deadline flows through one retry_policy shared by discover() and every collector
    via paginate()/call_once() (pagination.py). Asserted on what discover() receives, not
    cli.py's local variable, so a refactor can't silently drop the threading."""

    seen_policies: list[RetryPolicy] = []

    def _capture_discover(signer, app_config, retry_policy=None):
        seen_policies.append(retry_policy)
        return _discovery()

    monkeypatch.setattr(cli, "build_signer", lambda app_config: MagicMock())
    monkeypatch.setattr(cli, "discover", _capture_discover)
    monkeypatch.setattr(cli, "collect_compute", lambda *a, **k: _exposed_windows_compute())
    monkeypatch.setattr(cli, "collect_networking", lambda *a, **k: _networking_allowing_rdp())
    monkeypatch.setattr(cli, "collect_autonomous_database", lambda *a, **k: _autonomous_database())
    monkeypatch.setattr(cli, "upsert_records", MagicMock(return_value=[]))
    monkeypatch.setattr(cli, "delete_records", MagicMock(return_value=[]))

    before = time.monotonic()
    cli.run(_app_config(), dry_run=True, test_mode=True)
    after = time.monotonic()
    deadline = seen_policies[0].deadline
    assert deadline is not None
    assert before + cli.TEST_MODE_TIME_BUDGET_SECONDS <= deadline <= after + cli.TEST_MODE_TIME_BUDGET_SECONDS

    seen_policies.clear()
    cli.run(_app_config(), dry_run=True, test_mode=False)
    assert seen_policies[0].deadline is None


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
    monkeypatch.setattr(cli, "collect_compute", lambda *a, **k: compute_with_terminated_only)
    delete_mock = MagicMock(return_value=[])
    monkeypatch.setattr(cli, "delete_records", delete_mock)
    patched_collectors.return_value = [DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)]

    cli.run(_app_config(), dry_run=False, test_mode=True)

    delete_mock.assert_not_called()


def test_domain_all_skipped_true_only_when_every_op_is_the_skip_marker() -> None:
    skipped = [OperationResult(service="s", operation="collect", region=None, compartment_id=None, status="skipped")]
    ran_and_found_nothing = [OperationResult(service="s", operation="list_x", region="r", compartment_id="c1", status="success", item_count=0)]
    assert cli._domain_all_skipped(skipped) is True
    assert cli._domain_all_skipped(ran_and_found_nothing) is False
    assert cli._domain_all_skipped([]) is False  # no ops at all is not the same claim as "disabled by config"


def test_report_distinguishes_disabled_from_empty_domains(patched_collectors: MagicMock) -> None:
    """domainComplete=true only means nothing failed, not that the service ran at all.
    identity/objectStorage/etc are off by default, so they must show skipped; compute
    is on and ran, so it must not."""

    result = cli.run(_app_config(), dry_run=True)
    domain_skipped = result.report["domainSkipped"]
    assert domain_skipped["identity"] is True
    assert domain_skipped["compute"] is False
    assert result.report["excludedByLifecycle"]["kmsKey"] == 0
    assert result.report["unresolvedRelationships"] == 0


def test_dry_run_writes_flat_records_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    import yaml

    sample = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"
    raw = yaml.safe_load(sample.read_text())
    raw["oci"]["expectedTenancyOcid"] = "ocid1.tenancy.oc1..aaaaaaaatest"
    raw["oci"]["regions"]["allow"] = ["us-ashburn-1"]
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    config_path.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("DRATA_API_TOKEN", "unused")

    exit_code = cli.main(["--config", str(config_path), "--dry-run", "--out-dir", "out"])
    assert exit_code == cli.EXIT_OK

    flat_records = json.loads((tmp_path / "out" / "flat-records.json").read_text())
    assert {r["id"] for r in flat_records} == {
        "ocid1.instance.oc1..vm1", "ocid1.autonomousdatabase.oc1..adb1",
    }
    assert stat.S_IMODE((tmp_path / "out" / "flat-records.json").stat().st_mode) == 0o600


# -- Full integration: every opt-in evidenceType enabled at once --
#
# Exercises all 10 domains simultaneously: no id collisions across evidenceTypes, every
# record schema-valid, nothing crashes.


def _app_config_with_everything_enabled():
    app_config = _app_config()
    services = dataclasses.replace(
        app_config.oci.services,
        identity=True, object_storage=True, cloud_guard=True, monitoring=True,
        load_balancer=True, waf=True, kms_vault=True,
    )
    return dataclasses.replace(app_config, oci=dataclasses.replace(app_config.oci, services=services))


def _all_domains_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    import oci

    from oci_drata.collection.cloud_guard import CloudGuardCollectionResult
    from oci_drata.collection.identity import IdentityCollectionResult
    from oci_drata.collection.kms_vault import KmsVaultCollectionResult
    from oci_drata.collection.load_balancer import LoadBalancerCollectionResult
    from oci_drata.collection.monitoring import MonitoringCollectionResult
    from oci_drata.collection.object_storage import ObjectStorageCollectionResult
    from oci_drata.collection.waf import WafCollectionResult

    monkeypatch.setattr(
        cli, "collect_identity",
        lambda *a, **k: IdentityCollectionResult(
            users=[oci.identity.models.User(id="ocid1.user.oc1..u1", compartment_id="c1", is_mfa_activated=True)],
            api_keys_by_user_id={
                "ocid1.user.oc1..u1": [
                    oci.identity.models.ApiKey(key_id="ocid1.apikey.oc1..k1", user_id="ocid1.user.oc1..u1", fingerprint="aa:bb")
                ]
            },
            policies=[oci.identity.models.Policy(id="ocid1.policy.oc1..p1", compartment_id="c1", statements=["Allow ..."])],
            operations=[],
        ),
    )
    monkeypatch.setattr(
        cli, "collect_object_storage",
        lambda *a, **k: ObjectStorageCollectionResult(
            buckets=[
                _stamp(oci.object_storage.models.Bucket(
                    id="ocid1.bucket.oc1..b1", compartment_id="c1", name="my-bucket", namespace="ns1",
                    public_access_type="NoPublicAccess", kms_key_id="ocid1.key.oc1..bucketkey1", versioning="Enabled",
                ))
            ],
            operations=[],
        ),
    )
    monkeypatch.setattr(
        cli, "collect_cloud_guard",
        lambda *a, **k: CloudGuardCollectionResult(
            configuration=oci.cloud_guard.models.Configuration(status="ENABLED"), operations=[]
        ),
    )
    monkeypatch.setattr(
        cli, "collect_monitoring",
        lambda *a, **k: MonitoringCollectionResult(
            alarms=[
                _stamp(oci.monitoring.models.AlarmSummary(
                    id="ocid1.alarm.oc1..a1", compartment_id="c1", is_enabled=True, namespace="oci_computeagent",
                ))
            ],
            operations=[],
        ),
    )
    monkeypatch.setattr(
        cli, "collect_load_balancer",
        lambda *a, **k: LoadBalancerCollectionResult(
            load_balancers=[
                _stamp(oci.load_balancer.models.LoadBalancer(
                    id="ocid1.loadbalancer.oc1..lb1", compartment_id="c1", is_private=False,
                    backend_sets={"bs1": oci.load_balancer.models.BackendSet(name="bs1")},
                ))
            ],
            backend_set_health_by_key={
                ("ocid1.loadbalancer.oc1..lb1", "bs1"): oci.load_balancer.models.BackendSetHealth(status="OK")
            },
            operations=[],
        ),
    )
    monkeypatch.setattr(
        cli, "collect_waf",
        lambda *a, **k: WafCollectionResult(
            web_app_firewalls=[
                _stamp(oci.waf.models.WebAppFirewallLoadBalancerSummary(
                    id="ocid1.webappfirewall.oc1..w1", compartment_id="c1",
                    backend_type="LOAD_BALANCER", load_balancer_id="ocid1.loadbalancer.oc1..lb1",
                ))
            ],
            operations=[],
        ),
    )
    monkeypatch.setattr(
        cli, "collect_kms_vault",
        lambda *a, **k: KmsVaultCollectionResult(
            vaults=[oci.key_management.models.VaultSummary(id="ocid1.vault.oc1..v1", compartment_id="c1")],
            keys=[
                _stamp(oci.key_management.models.Key(
                    id="ocid1.key.oc1..kmskey1", compartment_id="c1", vault_id="ocid1.vault.oc1..v1",
                    is_auto_rotation_enabled=True,
                ))
            ],
            operations=[],
        ),
    )


def test_all_evidence_types_together_no_id_collisions(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    _all_domains_enabled(monkeypatch)

    result = cli.run(_app_config_with_everything_enabled(), dry_run=True)

    evidence_types = {r["evidenceType"] for r in result.records}
    assert evidence_types == {
        "instance", "autonomous_database", "iam_user", "api_key", "iam_policy",
        "bucket", "cloud_guard_configuration", "monitoring_alarm",
        "load_balancer", "load_balancer_backend_set", "waf", "kms_key",
    }, f"missing or unexpected evidenceTypes: {evidence_types}"

    ids = [r["id"] for r in result.records]
    assert len(ids) == len(set(ids)), f"duplicate ids across evidenceTypes: {ids}"

    schema = load_flat_schema()
    invalid = [(r["id"], validate_record(r, schema).errors) for r in result.records]
    invalid = [(rid, errs) for rid, errs in invalid if errs]
    assert not invalid, f"schema-invalid records: {invalid}"

    assert result.report["uploadDecision"] == "skipped_dry_run"
    assert result.report["schemaValid"] is True

    # Confirms these fixtures look like real collector output (real region), not
    # just schema-valid nulls.
    stamped_types = {
        "bucket", "monitoring_alarm", "load_balancer", "load_balancer_backend_set", "waf", "kms_key",
    }
    for record in result.records:
        if record["evidenceType"] in stamped_types:
            assert record["region"] == "us-ashburn-1", record
