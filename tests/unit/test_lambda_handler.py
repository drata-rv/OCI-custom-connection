"""The Lambda entry point: deadlines inside the function timeout, metrics, failure semantics."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
import yaml

from oci_drata import lambda_handler
from oci_drata.runner import EXIT_BLOCKED, EXIT_OK, RunResult

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Context:
    def __init__(self, remaining_seconds: float) -> None:
        self._remaining = remaining_seconds

    def get_remaining_time_in_millis(self) -> int:
        return int(self._remaining * 1000)


def _report(**overrides) -> dict:
    report = {
        "dryRun": False, "uploadDecision": "uploaded", "recordCount": 5, "recordCountDelivered": 5,
        "recordCountWithheld": 0, "domainsWithheld": [], "deadlineExceeded": False,
        "operationsFailed": 0, "elapsedSeconds": 12.5,
    }
    report.update(overrides)
    return report


@pytest.fixture
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    raw = yaml.safe_load((REPO_ROOT / "config.example.yaml").read_text())
    raw["drata"].update(connectionId=1, resourceId=2)
    raw["runtime"]["dryRun"] = True
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("OCI_DRATA_CONFIG", str(path))
    return path


def test_handler_stops_collecting_and_delivering_before_the_function_times_out(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict = {}

    def fake_run(app_config, **kwargs):
        seen.update(kwargs)
        return RunResult(exit_code=EXIT_OK, uploaded=False, report=_report(dryRun=True), records=[])

    monkeypatch.setattr(lambda_handler, "run", fake_run)
    before = time.monotonic()

    summary = lambda_handler.handler({}, _Context(900))

    function_timeout = before + 900
    assert before < seen["deadline"] < seen["delivery_deadline"] < function_timeout
    assert function_timeout - seen["deadline"] >= 100  # room to finish in-flight calls, gate, and deliver
    assert seen["dry_run"] is True and summary["uploadDecision"] == "uploaded"

    metrics_line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith('{"_aws"'))
    emf = json.loads(metrics_line)
    declared = [m["Name"] for m in emf["_aws"]["CloudWatchMetrics"][0]["Metrics"]]
    assert declared and all(name in emf for name in declared)  # EMF: every declared metric is a root member
    assert emf["RecordsDelivered"] == 0  # dry run: nothing was uploaded


def test_handler_raises_when_the_run_delivered_nothing(config_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    blocked = _report(uploadDecision="blocked", blockedReasons=["discovery incomplete"], recordCountDelivered=0)
    monkeypatch.setattr(
        lambda_handler, "run", lambda *a, **k: RunResult(exit_code=EXIT_BLOCKED, uploaded=False, report=blocked, records=[])
    )

    with pytest.raises(lambda_handler.RunFailed, match="discovery incomplete"):
        lambda_handler.handler({"dryRun": True}, _Context(900))
