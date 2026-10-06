"""CLI entry point: ``oci-drata [--config PATH] [--dry-run] [--out-dir DIR] [--test]``.

Never accepts secrets as CLI arguments. Owns the process boundary -- argument parsing, local
output files, exit codes; the collection run itself is :func:`oci_drata.runner.run`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from oci_drata.config import ConfigError, load_config
from oci_drata.logging import configure_logging
from oci_drata.oci_auth import AuthError
from oci_drata.runner import (
    EXIT_BLOCKED,
    EXIT_CONFIG_ERROR,
    EXIT_OK,
    EXIT_UNEXPECTED,
    TEST_MODE_TIME_BUDGET_SECONDS,
    run,
)

__all__ = ["EXIT_BLOCKED", "EXIT_CONFIG_ERROR", "EXIT_OK", "EXIT_UNEXPECTED", "main"]

logger = logging.getLogger(__name__)


def _prepare_restricted_output_dir(out_dir: Path) -> None:
    """Output holds OCI inventory (OCIDs, topology, IP/security rules) -- operationally
    sensitive though not secret, so owner-only permissions rather than the process
    umask's default. Refuses a pre-existing symlink here instead of following it."""

    if out_dir.is_symlink():
        raise RuntimeError(f"refusing to use {out_dir} as an output directory: it is a symlink")
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out_dir, 0o700)  # mkdir's mode is only applied on creation, not to a pre-existing dir


def _write_restricted(path: Path, data: bytes) -> None:
    """Creates the file with owner-only permissions from the moment it exists -- no
    write-then-chmod window where it's briefly at the process umask's default -- and
    refuses to follow a pre-existing symlink at this path."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _write_failure_report(
    out_dir: Path, *, dry_run: bool, error_type: str, error_message: str
) -> None:
    """Best-effort trace for a run that raised before run() could return a RunResult at
    all (auth/config error, or a genuine bug) -- so a failure this early still leaves
    something on disk instead of nothing. Never raises itself: a failure here must not
    mask the original error already being logged/returned by the caller."""

    try:
        _prepare_restricted_output_dir(out_dir)
        _write_restricted(
            out_dir / "collection-report.json",
            json.dumps(
                {
                    "dryRun": dry_run,
                    "uploadDecision": "failed",
                    "errorType": error_type,
                    "error": error_message,
                },
                indent=2, sort_keys=True,
            ).encode("utf-8"),
        )
    except Exception:
        logger.exception("failed to write failure report to out_dir")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="oci-drata",
        description="Collect read-only OCI configuration evidence and upsert it to a Drata "
        "Custom Connection.",
    )
    parser.add_argument(
        "--config", default="config.yaml", help="deployment configuration YAML (default: config.yaml)"
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=None,
        help="write sanitized aggregate JSON locally and never contact Drata, overriding "
        "runtime.dryRun",
    )
    parser.add_argument(
        "--out-dir",
        default="out",
        help="directory for dry-run output and the collection report (default: out)",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help=f"sample mode: stop collecting after {TEST_MODE_TIME_BUDGET_SECONDS}s instead of "
        "scanning the whole tenancy, keeping whatever real data was gathered by then. Records "
        "still upload normally if runtime.dryRun is false (each record is standalone evidence, "
        "honest at any sample size) -- for building/testing a Custom Test against live data. "
        "Stale-record cleanup is skipped in this mode, since a sampled run's absences aren't "
        "confirmed deletions.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        app_config = load_config(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    configure_logging(app_config.runtime.log_level)
    dry_run = app_config.runtime.dry_run if args.dry_run is None else args.dry_run

    if not dry_run:
        # Fail fast on a missing/misconfigured Drata token before spending possibly tens of
        # minutes on OCI collection: api_token_secret_ref.resolve() is otherwise only called
        # at the point of actually POSTing, deep inside upsert_records/delete_records -- by
        # then a real run has already thrown away a full collection pass with no artifact
        # written, since this exception unwinds straight out of main() before the
        # report-writing step below ever runs. Dry runs never resolve the token at all
        # (nothing is ever sent to Drata), so this check is skipped for them.
        try:
            app_config.drata.api_token_secret_ref.resolve()
        except ConfigError as exc:
            logger.error("configuration error: Drata API token", extra={"error": str(exc)})
            return EXIT_CONFIG_ERROR

    out_dir = Path(args.out_dir)

    try:
        result = run(app_config, dry_run=dry_run, test_mode=args.test)
    except AuthError as exc:
        logger.error("authentication failed", extra={"error": str(exc)})
        _write_failure_report(out_dir, dry_run=dry_run, error_type="AuthError", error_message=str(exc))
        return EXIT_CONFIG_ERROR
    except ConfigError as exc:
        logger.error("configuration error", extra={"error": str(exc)})
        _write_failure_report(out_dir, dry_run=dry_run, error_type="ConfigError", error_message=str(exc))
        return EXIT_CONFIG_ERROR
    except Exception as exc:
        logger.exception("unexpected failure during collection run")
        _write_failure_report(
            out_dir, dry_run=dry_run, error_type=type(exc).__name__, error_message=str(exc)
        )
        return EXIT_UNEXPECTED

    _prepare_restricted_output_dir(out_dir)
    _write_restricted(
        out_dir / "collection-report.json",
        json.dumps(result.report, indent=2, sort_keys=True).encode("utf-8"),
    )
    # Always written, not just on dry runs -- whatever this run actually collected stays on
    # disk regardless of what happened to it afterward (upload succeeded, failed, or was
    # never attempted), so a delivery failure never means the collected evidence itself is
    # unrecoverable.
    _write_restricted(
        out_dir / "flat-records.json",
        json.dumps(result.records, indent=2, sort_keys=True).encode("utf-8"),
    )

    print(json.dumps(result.report, indent=2, sort_keys=True))
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
