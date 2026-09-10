"""Drata Custom Connection upsert client.

POSTs ``{"data": record}`` to
``{baseUrl}/custom-connections/{connectionId}/resources/{resourceId}/records``;
200/201 both mean success (upsert by the record's own ``id`` field inside
``data``). Failures never raise -- returned as ``DeliveryResult`` with
``error_class``: auth/validation are non-retryable, 429/5xx get bounded retry.
"""

from __future__ import annotations

import dataclasses
import logging
import random
import time
from typing import Any

import requests

from oci_drata.config import DrataConfig

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_AUTH_STATUS = frozenset({401, 403})
_VALIDATION_STATUS = frozenset({400, 404, 409, 422})


@dataclasses.dataclass(frozen=True)
class DeliveryResult:
    uploaded: bool
    created: bool | None  # True on 201, False on 200, None when not uploaded
    status_code: int | None
    attempts: int
    error_class: str | None = None  # "auth" | "validation" | "transport" | "unexpected"
    error_message: str | None = None

    @property
    def ok(self) -> bool:
        return self.uploaded


def upsert_record(
    drata_config: DrataConfig,
    record: dict[str, Any],
    *,
    max_attempts: int = 5,
    base_delay_seconds: float = 1.0,
    max_delay_seconds: float = 30.0,
    session: requests.Session | None = None,
) -> DeliveryResult:
    token = drata_config.api_token_secret_ref.resolve()
    url = (
        f"{drata_config.base_url.rstrip('/')}/custom-connections/"
        f"{drata_config.connection_id}/resources/{drata_config.resource_id}/records"
    )
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"data": record}
    http = session if session is not None else requests.Session()

    attempt = 0
    while True:
        attempt += 1
        try:
            response = http.post(url, json=body, headers=headers, timeout=30)
        except requests.RequestException as exc:
            if attempt >= max_attempts:
                logger.warning(
                    "drata upload transport failure exhausted retries",
                    extra={"attempts": attempt},
                )
                return DeliveryResult(
                    uploaded=False,
                    created=None,
                    status_code=None,
                    attempts=attempt,
                    error_class="transport",
                    error_message=str(exc),
                )
            _sleep_with_jitter(base_delay_seconds, max_delay_seconds, attempt)
            continue

        if response.status_code in (200, 201):
            logger.info(
                "drata upload succeeded",
                extra={"status_code": response.status_code, "attempts": attempt},
            )
            return DeliveryResult(
                uploaded=True,
                created=response.status_code == 201,
                status_code=response.status_code,
                attempts=attempt,
            )

        if response.status_code in _AUTH_STATUS:
            logger.warning(
                "drata upload rejected: authentication/authorization",
                extra={"status_code": response.status_code},
            )
            return DeliveryResult(
                uploaded=False,
                created=None,
                status_code=response.status_code,
                attempts=attempt,
                error_class="auth",
                error_message=_safe_body(response),
            )

        if response.status_code in _VALIDATION_STATUS:
            logger.warning(
                "drata upload rejected: validation error",
                extra={"status_code": response.status_code},
            )
            return DeliveryResult(
                uploaded=False,
                created=None,
                status_code=response.status_code,
                attempts=attempt,
                error_class="validation",
                error_message=_safe_body(response),
            )

        if response.status_code in _RETRYABLE_STATUS and attempt < max_attempts:
            _sleep_with_jitter(base_delay_seconds, max_delay_seconds, attempt)
            continue

        logger.warning(
            "drata upload failed with unexpected status",
            extra={"status_code": response.status_code, "attempts": attempt},
        )
        return DeliveryResult(
            uploaded=False,
            created=None,
            status_code=response.status_code,
            attempts=attempt,
            error_class="unexpected",
            error_message=_safe_body(response),
        )


def _safe_body(response: requests.Response) -> str:
    try:
        return response.text[:500]
    except Exception:
        return "<unreadable response body>"


def _sleep_with_jitter(base: float, cap: float, attempt: int) -> None:
    upper = min(cap, base * (2**attempt))
    time.sleep(random.uniform(0, upper))
