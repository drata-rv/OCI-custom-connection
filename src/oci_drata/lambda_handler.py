"""AWS Lambda entry point: one scheduled collection run per invocation.

Configuration is the packaged config.yaml (``OCI_DRATA_CONFIG``, default ``config.yaml`` in
the Lambda task root) plus ``OCI_DRATA__*`` environment overrides. Credentials are read from
AWS Secrets Manager through ``aws_secretsmanager`` secretRefs, so nothing sensitive lives in
the package or the function's environment.

Event (all optional): ``{"dryRun": true}`` collects and reports without contacting Drata.

Lambda gives no graceful shutdown on timeout, so the run watches the clock itself: collection
stops starting new OCI calls ``COLLECT_MARGIN_SECONDS`` before the function would time out
(any domain it cut short is withheld, not delivered partial) and delivery stops sending
``DELIVERY_MARGIN_SECONDS`` before. The handler raises when the run could not deliver, so
Lambda's ``Errors`` metric and the on-failure destination fire; a run that delivered only part
of the evidence succeeds and says so in its ``DomainsWithheld`` metric.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from oci_drata.config import AppConfig, ConfigError, load_config
from oci_drata.logging import configure_logging
from oci_drata.oci_auth import AuthError
from oci_drata.runner import EXIT_OK, RunResult, run

logger = logging.getLogger(__name__)

# Reserved for: in-flight OCI requests finishing (SDK read timeout is 60 s), transform/gating, and
# delivery to Drata. Capped to a fraction of short test timeouts so a console test still works.
COLLECT_MARGIN_SECONDS = float(os.environ.get("OCI_DRATA_COLLECT_MARGIN_SECONDS", "150"))
DELIVERY_MARGIN_SECONDS = float(os.environ.get("OCI_DRATA_DELIVERY_MARGIN_SECONDS", "25"))

METRICS_NAMESPACE = "OciDrata"


class RunFailed(Exception):
    """The run delivered nothing (blocked, or delivery failed)."""


def _config_path() -> str:
    task_root = os.environ.get("LAMBDA_TASK_ROOT", ".")
    return os.environ.get("OCI_DRATA_CONFIG") or os.path.join(task_root, "config.yaml")


def _dry_run(event: Any, app_config: AppConfig) -> bool:
    if isinstance(event, dict) and isinstance(event.get("dryRun"), bool):
        return event["dryRun"]
    return app_config.runtime.dry_run


def _summary(app_config: AppConfig, result: RunResult) -> dict[str, Any]:
    report = result.report
    return {
        "deployment": app_config.deployment.name,
        "dryRun": report["dryRun"],
        "uploaded": result.uploaded,
        "uploadDecision": report["uploadDecision"],
        "recordCount": report["recordCount"],
        "recordCountDelivered": report["recordCountDelivered"],
        "recordCountWithheld": report["recordCountWithheld"],
        "domainsWithheld": report["domainsWithheld"],
        "deadlineExceeded": report["deadlineExceeded"],
        "staleRecordsDeleted": report.get("staleRecordsDeleted", 0),
        "operationsFailed": report["operationsFailed"],
        "elapsedSeconds": report["elapsedSeconds"],
    }


def _emit_metrics(summary: dict[str, Any], *, succeeded: bool) -> None:
    """One CloudWatch Embedded Metric Format line: metrics with no PutMetricData call or extra
    IAM. Printed as a bare JSON line (not via ``logging``) because EMF requires the whole log
    event to be the JSON object."""

    metrics = {
        "RunSucceeded": (int(succeeded), "Count"),
        "RecordsDelivered": (summary["recordCountDelivered"] if summary["uploaded"] else 0, "Count"),
        "RecordsWithheld": (summary["recordCountWithheld"], "Count"),
        "DomainsWithheld": (len(summary["domainsWithheld"]), "Count"),
        "DeadlineExceeded": (int(summary["deadlineExceeded"]), "Count"),
        "OperationsFailed": (summary["operationsFailed"], "Count"),
        "StaleRecordsDeleted": (summary["staleRecordsDeleted"], "Count"),
        "ElapsedSeconds": (summary["elapsedSeconds"], "Seconds"),
    }
    print(
        json.dumps(
            {
                "_aws": {
                    "Timestamp": int(time.time() * 1000),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": METRICS_NAMESPACE,
                            # Per deployment, and one dimensionless aggregate for a single alarm.
                            "Dimensions": [["Deployment"], []],
                            "Metrics": [{"Name": name, "Unit": unit} for name, (_, unit) in metrics.items()],
                        }
                    ],
                },
                "Deployment": summary["deployment"],
                **{name: value for name, (value, _) in metrics.items()},
            }
        ),
        flush=True,
    )


def handler(event: Any, context: Any) -> dict[str, Any]:
    started = time.monotonic()
    remaining = context.get_remaining_time_in_millis() / 1000.0
    configure_logging("INFO")  # replaces the runtime's own log handler with our JSON one

    try:
        app_config = load_config(_config_path())
        configure_logging(app_config.runtime.log_level)
        dry_run = _dry_run(event, app_config)
        if not dry_run:
            # Fail before spending minutes on OCI collection, same as the CLI.
            app_config.drata.api_token_secret_ref.resolve()
        result = run(
            app_config,
            dry_run=dry_run,
            deadline=started + remaining - min(COLLECT_MARGIN_SECONDS, 0.2 * remaining),
            delivery_deadline=started + remaining - min(DELIVERY_MARGIN_SECONDS, 0.05 * remaining),
        )
    except (ConfigError, AuthError) as exc:
        logger.error("run failed before collection", extra={"errorType": type(exc).__name__, "error": str(exc)})
        raise

    summary = _summary(app_config, result)
    logger.info("run report", extra={"report": result.report})
    succeeded = result.exit_code == EXIT_OK
    _emit_metrics(summary, succeeded=succeeded)
    if not succeeded:
        report = result.report
        detail = report.get("blockedReasons") or report.get("deliveryErrorClasses") or report.get("deliveryError")
        raise RunFailed(f"{summary['uploadDecision']}: {detail}")
    return summary
