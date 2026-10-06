"""Invoke the Lambda handler on this machine with a fake Lambda context -- no AWS needed.

    python deploy/invoke_local.py --config config.yaml [--timeout 900] [--live]

Sends ``{"dryRun": true}`` unless ``--live`` is given, so by default nothing is sent to Drata.
Credentials resolve exactly as in Lambda: aws_secretsmanager secretRefs need AWS credentials in
your environment (``pip install boto3``); env/file secretRefs and ~/.oci config files also work.
"""

from __future__ import annotations

import argparse
import json
import os
import time


class FakeContext:
    """The one Lambda context member the handler uses."""

    def __init__(self, timeout_seconds: float) -> None:
        self._deadline = time.monotonic() + timeout_seconds

    def get_remaining_time_in_millis(self) -> int:
        return max(0, int((self._deadline - time.monotonic()) * 1000))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--timeout", type=float, default=900, help="simulated function timeout, seconds")
    parser.add_argument("--live", action="store_true", help="deliver to Drata instead of a dry run")
    args = parser.parse_args()

    os.environ["OCI_DRATA_CONFIG"] = args.config
    from oci_drata.lambda_handler import handler  # imported after the env var is set

    summary = handler({"dryRun": not args.live}, FakeContext(args.timeout))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
