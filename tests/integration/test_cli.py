"""Tests cli.run() orchestration; collectors mocked at function boundary.
OCI-client-mock level coverage lives in test_end_to_end.py.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from oci_drata import cli

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
