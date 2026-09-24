"""Tests cli.run() orchestration; collectors mocked at function boundary.
OCI-client-mock level coverage lives in test_end_to_end.py.
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
from oci_drata.delivery.drata import DeliveryResult
from oci_drata.pagination import OperationResult, RetryPolicy
from oci_drata.validation.schema import load_flat_schema, validate_record

from .test_end_to_end import (
    _app_config,
    _autonomous_database,
    _database_base_empty,
    _discovery,
    _exadata_not_detected,
    _exposed_windows_compute,
    _networking_allowing_rdp,
    _storage,
    _vpn_non_redundant,
)


@pytest.fixture
def patched_collectors(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    monkeypatch.setattr(cli, "build_signer", lambda app_config: MagicMock())
    monkeypatch.setattr(cli, "discover", lambda signer, app_config, retry_policy=None: _discovery())
    monkeypatch.setattr(cli, "collect_compute", lambda *a, **k: _exposed_windows_compute())
    monkeypatch.setattr(cli, "collect_storage", lambda *a, **k: _storage())
    monkeypatch.setattr(cli, "collect_networking", lambda *a, **k: _networking_allowing_rdp())
    monkeypatch.setattr(cli, "collect_database_base", lambda *a, **k: _database_base_empty())
    monkeypatch.setattr(cli, "collect_autonomous_database", lambda *a, **k: _autonomous_database())
    monkeypatch.setattr(cli, "collect_vpn", lambda *a, **k: _vpn_non_redundant())
    monkeypatch.setattr(cli, "detect_exadata", lambda *a, **k: _exadata_not_detected())
    upsert = MagicMock()
    monkeypatch.setattr(cli, "upsert_record", upsert)
    return upsert


def test_dry_run_never_calls_drata(patched_collectors: MagicMock) -> None:
    app_config = _app_config()
    result = cli.run(app_config, dry_run=True)
    assert result.snapshot_status == "complete"
    assert result.uploaded is False
    assert result.report["uploadDecision"] == "skipped_dry_run"
    patched_collectors.assert_not_called()
    assert result.exit_code == cli.EXIT_OK


def test_complete_run_uploads(patched_collectors: MagicMock) -> None:
    patched_collectors.return_value = MagicMock(uploaded=True, created=True, attempts=1, error_class=None)
    app_config = _app_config()
    result = cli.run(app_config, dry_run=False)
    assert result.uploaded is True
    assert result.report["uploadDecision"] == "uploaded"
    patched_collectors.assert_called_once()
    assert result.exit_code == cli.EXIT_OK


# -- _access_summary: turning a wall of per-operation failures into "where does this
# API user's access and the tenancy's real data actually overlap" --


def _op(compartment_id, status="success", error_code=None, item_count=0):
    return OperationResult(
        service="s", operation="o", region=None, compartment_id=compartment_id,
        status=status, error_code=error_code, item_count=item_count,
    )


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
    """A --test cutoff is not a permission problem -- conflating the two would make
    the summary lie about where the real access gap is."""

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
    from oci_drata.collection.storage import StorageCollectionResult
    from oci_drata.pagination import OperationResult

    failed_storage = StorageCollectionResult(
        boot_volumes=[], block_volumes=[], boot_volume_attachments=[], volume_attachments=[],
        operations=[
            OperationResult(
                service="blockstorage", operation="list_boot_volumes", region="us-ashburn-1",
                compartment_id="c1", status="failed", error_code="NotAuthorizedOrNotFound",
            )
        ],
    )
    monkeypatch.setattr(cli, "collect_storage", lambda *a, **k: failed_storage)

    result = cli.run(_app_config(), dry_run=True)
    assert result.report["accessSummary"]["compartmentsWithAuthGap"] == ["c1"]


def test_incomplete_run_blocks_upload(monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock) -> None:
    from oci_drata.collection.storage import StorageCollectionResult
    from oci_drata.pagination import OperationResult

    failed_storage = StorageCollectionResult(
        boot_volumes=[], block_volumes=[], boot_volume_attachments=[], volume_attachments=[],
        operations=[OperationResult(service="blockstorage", operation="list_boot_volumes", region="us-ashburn-1", compartment_id="c1", status="failed")],
    )
    monkeypatch.setattr(cli, "collect_storage", lambda *a, **k: failed_storage)

    app_config = _app_config()
    result = cli.run(app_config, dry_run=False)
    assert result.snapshot_status == "incomplete"
    assert result.uploaded is False
    patched_collectors.assert_not_called()
    assert result.exit_code == cli.EXIT_BLOCKED


def test_dry_run_writes_sanitized_snapshot_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    import yaml


    sample = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"
    raw = yaml.safe_load(sample.read_text())
    raw["oci"]["expectedTenancyOcid"] = "ocid1.tenancy.oc1..aaaaaaaatest"
    raw["oci"]["regions"]["allow"] = ["us-ashburn-1"]
    raw["drata"]["recordId"] = "oci-snapshot-test0123456789abcdef01234567"
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    config_path.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("DRATA_API_TOKEN", "unused")

    exit_code = cli.main(["--config", str(config_path), "--dry-run", "--out-dir", "out"])
    assert exit_code == cli.EXIT_OK

    report = json.loads((tmp_path / "out" / "collection-report.json").read_text())
    assert report["uploadDecision"] == "skipped_dry_run"
    snapshot = json.loads((tmp_path / "out" / "snapshot.json").read_text())
    assert snapshot["id"] == "oci-snapshot-test0123456789abcdef01234567"
    patched_collectors.assert_not_called()

    out_dir = tmp_path / "out"
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((out_dir / "collection-report.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((out_dir / "snapshot.json").stat().st_mode) == 0o600


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
    """Every OCI call goes through paginate()/call_once() (pagination.py), both keyed
    off the one retry_policy threaded through discover() and every collector -- setting
    its deadline here, once, bounds the whole run without touching a single collector
    file. Asserted on what discover() actually receives, not just cli.py's own local
    variable, so a future refactor that stops threading this same policy through can't
    silently break the time budget."""

    seen_policies: list[RetryPolicy] = []

    def _capture_discover(signer, app_config, retry_policy=None):
        seen_policies.append(retry_policy)
        return _discovery()

    monkeypatch.setattr(cli, "build_signer", lambda app_config: MagicMock())
    monkeypatch.setattr(cli, "discover", _capture_discover)
    monkeypatch.setattr(cli, "collect_compute", lambda *a, **k: _exposed_windows_compute())
    monkeypatch.setattr(cli, "collect_storage", lambda *a, **k: _storage())
    monkeypatch.setattr(cli, "collect_networking", lambda *a, **k: _networking_allowing_rdp())
    monkeypatch.setattr(cli, "collect_database_base", lambda *a, **k: _database_base_empty())
    monkeypatch.setattr(cli, "collect_autonomous_database", lambda *a, **k: _autonomous_database())
    monkeypatch.setattr(cli, "collect_vpn", lambda *a, **k: _vpn_non_redundant())
    monkeypatch.setattr(cli, "detect_exadata", lambda *a, **k: _exadata_not_detected())

    before = time.monotonic()
    cli.run(_app_config(), dry_run=True, test_mode=True)
    after = time.monotonic()
    deadline = seen_policies[0].deadline
    assert deadline is not None
    assert before + cli.TEST_MODE_TIME_BUDGET_SECONDS <= deadline <= after + cli.TEST_MODE_TIME_BUDGET_SECONDS

    seen_policies.clear()
    cli.run(_app_config(), dry_run=True, test_mode=False)
    assert seen_policies[0].deadline is None


def test_main_test_mode_skips_nested_upload_even_if_config_says_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    """A time-bounded partial scan is never a complete picture of the tenancy -- the
    nested/original path must never be able to reach a real Drata upload under --test,
    no matter what runtime.dryRun says. (The flat-record path is unaffected -- covered
    by test_flat_records_uploads_to_configured_resource_id-style tests -- since each
    flat record is standalone evidence, honest regardless of how much was collected.)"""

    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    import yaml

    sample = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"
    raw = yaml.safe_load(sample.read_text())
    raw["oci"]["expectedTenancyOcid"] = "ocid1.tenancy.oc1..aaaaaaaatest"
    raw["oci"]["regions"]["allow"] = ["us-ashburn-1"]
    raw["drata"]["recordId"] = "oci-snapshot-test0123456789abcdef01234567"
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    raw["runtime"]["dryRun"] = False
    config_path.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("DRATA_API_TOKEN", "unused")

    exit_code = cli.main(["--config", str(config_path), "--test", "--out-dir", "out"])
    report = json.loads((tmp_path / "out" / "collection-report.json").read_text())
    assert report["dryRun"] is False
    assert report["uploadDecision"] == "skipped_test_mode"
    patched_collectors.assert_not_called()
    assert exit_code == cli.EXIT_BLOCKED  # nested path didn't upload and this wasn't a dry run


# -- Flat-record architecture -- opt-in via drata.flatResourceId --


def _app_config_with_flat_resource(flat_resource_id: int = 99):
    app_config = _app_config()
    return dataclasses.replace(
        app_config, drata=dataclasses.replace(app_config.drata, flat_resource_id=flat_resource_id)
    )


def test_flat_records_disabled_by_default(patched_collectors: MagicMock) -> None:
    result = cli.run(_app_config(), dry_run=True)
    assert result.flat_records is None
    assert "flatRecords" not in result.report


def test_flat_records_dry_run_never_uploads(monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock) -> None:
    upsert_records = MagicMock()
    monkeypatch.setattr(cli, "upsert_records", upsert_records)

    result = cli.run(_app_config_with_flat_resource(), dry_run=True)

    assert result.flat_records is not None
    assert len(result.flat_records) == 2  # one instance, one autonomous database
    instance_record = next(r for r in result.flat_records if r["evidenceType"] == "instance")
    assert instance_record["id"] == "ocid1.instance.oc1..vm1"
    assert "status" not in instance_record  # raw facts only -- no precomputed verdict
    assert instance_record["hasPublicAddress"] is True
    assert instance_record["publicIngressPorts"] == [3389]

    adb_record = next(r for r in result.flat_records if r["evidenceType"] == "autonomous_database")
    assert adb_record["id"] == "ocid1.autonomousdatabase.oc1..adb1"
    assert "status" not in adb_record
    assert adb_record["kmsKeyId"] == "ocid1.key.oc1..key2"
    assert adb_record["publicEndpointHostname"] == "adb1.adb.us-ashburn-1.oraclecloudapps.com"

    assert result.report["flatRecords"]["uploadDecision"] == "skipped_dry_run"
    upsert_records.assert_not_called()


def test_flat_records_uploads_to_configured_resource_id(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    upsert_records = MagicMock(return_value=[DeliveryResult(uploaded=True, created=True, status_code=201, attempts=1)])
    monkeypatch.setattr(cli, "upsert_records", upsert_records)

    result = cli.run(_app_config_with_flat_resource(flat_resource_id=99), dry_run=False)

    assert result.report["flatRecords"]["uploadDecision"] == "uploaded"
    assert result.report["flatRecords"]["recordCount"] == 2
    upsert_records.assert_called_once()
    called_config = upsert_records.call_args.args[0]
    assert called_config.resource_id == 99
    # the nested-schema resourceId (drata.resourceId) must be untouched by the flat path
    assert called_config.resource_id != _app_config().drata.resource_id


def test_flat_records_delivery_failure_does_not_affect_nested_path_exit_code(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    patched_collectors.return_value = MagicMock(uploaded=True, created=True, attempts=1, error_class=None)
    monkeypatch.setattr(
        cli, "upsert_records",
        MagicMock(return_value=[DeliveryResult(uploaded=False, created=None, status_code=500, attempts=5, error_class="unexpected")]),
    )

    result = cli.run(_app_config_with_flat_resource(), dry_run=False)

    assert result.report["flatRecords"]["uploadDecision"] == "delivery_failed"
    assert result.uploaded is True  # nested path succeeded independently
    assert result.exit_code == cli.EXIT_OK


def test_flat_records_blocked_when_networking_incomplete(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    from oci_drata.collection.networking import NetworkingCollectionResult
    from oci_drata.pagination import OperationResult

    incomplete_networking = NetworkingCollectionResult(
        vcns=[], subnets=[], route_tables=[], internet_gateways=[], security_lists=[],
        network_security_groups=[], nsg_security_rules_by_nsg_id={}, nsg_vnics_by_nsg_id={},
        operations=[OperationResult(service="virtual_network", operation="list_subnets", region="us-ashburn-1", compartment_id="c1", status="failed")],
    )
    monkeypatch.setattr(cli, "collect_networking", lambda *a, **k: incomplete_networking)
    upsert_records = MagicMock()
    monkeypatch.setattr(cli, "upsert_records", upsert_records)

    result = cli.run(_app_config_with_flat_resource(), dry_run=False)

    assert result.report["flatRecords"]["uploadDecision"] == "blocked"
    assert "compute/networking collection incomplete" in result.report["flatRecords"]["blockedReasons"]
    upsert_records.assert_not_called()


def test_domain_all_skipped_true_only_when_every_op_is_the_skip_marker() -> None:
    skipped = [OperationResult(service="s", operation="collect", region=None, compartment_id=None, status="skipped")]
    ran_and_found_nothing = [OperationResult(service="s", operation="list_x", region="r", compartment_id="c1", status="success", item_count=0)]
    assert cli._domain_all_skipped(skipped) is True
    assert cli._domain_all_skipped(ran_and_found_nothing) is False
    assert cli._domain_all_skipped([]) is False  # no ops at all is not the same claim as "disabled by config"


def test_flat_records_report_distinguishes_disabled_from_empty_domains(
    patched_collectors: MagicMock,
) -> None:
    """The exact ambiguity a real run hit: domainComplete=true tells you nothing failed,
    not whether the service ran at all. identity/objectStorage/etc are off by default
    (see _app_config_with_flat_resource -> _app_config), so they must show up as
    skipped; compute is on and (per patched_collectors) actually ran, so it must not."""

    result = cli.run(_app_config_with_flat_resource(), dry_run=True)
    domain_skipped = result.report["flatRecords"]["domainSkipped"]
    assert domain_skipped["identity"] is True
    assert domain_skipped["compute"] is False
    assert result.report["flatRecords"]["excludedByLifecycle"]["kmsKey"] == 0
    assert result.report["flatRecords"]["unresolvedRelationships"] == 0


def test_flat_records_blocked_when_unresolved_relationships_exist(
    monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock
) -> None:
    """A dangling vnic_attachment (references an instance not in the collected set)
    used to be silently discarded on the flat path -- unlike build_snapshot's nested
    path, which hard-blocks upload on exactly this signal via decide_completeness()."""

    from oci_drata.collection.compute import ComputeCollectionResult

    dangling = oci.core.models.VnicAttachment(
        id="att-dangling", instance_id="i-does-not-exist", vnic_id="v1", compartment_id="c1",
    )
    compute_with_dangling_attachment = ComputeCollectionResult(
        instances=[], images={}, vnic_attachments=[dangling], vnics={}, private_ips=[],
        public_ips_by_private_ip_id={},
        operations=[OperationResult(service="compute", operation="list_instances", region="us-ashburn-1", compartment_id="c1", status="success")],
    )
    monkeypatch.setattr(cli, "collect_compute", lambda *a, **k: compute_with_dangling_attachment)
    upsert_records = MagicMock()
    monkeypatch.setattr(cli, "upsert_records", upsert_records)

    result = cli.run(_app_config_with_flat_resource(), dry_run=False)

    assert result.report["flatRecords"]["uploadDecision"] == "blocked"
    assert "unresolved relationships" in result.report["flatRecords"]["blockedReasons"]
    upsert_records.assert_not_called()


def test_dry_run_writes_flat_records_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patched_collectors: MagicMock) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    import yaml

    sample = Path(__file__).resolve().parent.parent.parent / "config.example.yaml"
    raw = yaml.safe_load(sample.read_text())
    raw["oci"]["expectedTenancyOcid"] = "ocid1.tenancy.oc1..aaaaaaaatest"
    raw["oci"]["regions"]["allow"] = ["us-ashburn-1"]
    raw["drata"]["recordId"] = "oci-snapshot-test0123456789abcdef01234567"
    raw["drata"]["connectionId"] = 101
    raw["drata"]["resourceId"] = 202
    raw["drata"]["flatResourceId"] = 303
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
# Every test above exercises one collector/evidenceType in isolation (or the base
# two that are always on). This runs the whole flat-record pipeline with all 7
# opt-in domains enabled simultaneously: no id collisions across evidenceTypes,
# every record schema-valid, nothing crashes when every opt-in toggle is
# flipped on at the same time.


def _app_config_with_everything_enabled():
    app_config = _app_config_with_flat_resource(flat_resource_id=99)
    services = dataclasses.replace(
        app_config.oci.services,
        identity=True, object_storage=True, cloud_guard=True, monitoring=True,
        load_balancer=True, waf=True, kms_vault=True,
    )
    return dataclasses.replace(app_config, oci=dataclasses.replace(app_config.oci, services=services))


def _stamp(raw, region="us-ashburn-1"):
    """Every real collector calls pagination.stamp_region() before returning an
    object -- mock fixtures that skip this don't represent real collector output
    (aggregate.py's flatteners degrade a missing .region to null rather than
    crashing, but a test fixture should still look like production data)."""

    raw.region = region
    return raw


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

    assert result.flat_records is not None
    evidence_types = {r["evidenceType"] for r in result.flat_records}
    assert evidence_types == {
        "instance", "autonomous_database", "iam_user", "api_key", "iam_policy",
        "bucket", "cloud_guard_configuration", "monitoring_alarm",
        "load_balancer", "load_balancer_backend_set", "waf", "kms_key",
    }, f"missing or unexpected evidenceTypes: {evidence_types}"

    ids = [r["id"] for r in result.flat_records]
    assert len(ids) == len(set(ids)), f"duplicate ids across evidenceTypes: {ids}"

    schema = load_flat_schema()
    invalid = [(r["id"], validate_record(r, schema).errors) for r in result.flat_records]
    invalid = [(rid, errs) for rid, errs in invalid if errs]
    assert not invalid, f"schema-invalid records: {invalid}"

    assert result.report["flatRecords"]["uploadDecision"] == "skipped_dry_run"
    assert result.report["flatRecords"]["schemaValid"] is True

    # Every record from a raw-SDK-object evidenceType should carry a real region
    # (not null) when its collector correctly region-stamps -- confirms the test
    # fixtures represent realistic collector output, not just schema-valid nulls.
    stamped_types = {
        "bucket", "monitoring_alarm", "load_balancer", "load_balancer_backend_set", "waf", "kms_key",
    }
    for record in result.flat_records:
        if record["evidenceType"] in stamped_types:
            assert record["region"] == "us-ashburn-1", record
