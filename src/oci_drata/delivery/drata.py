"""Drata Custom Connection upsert/delete client.

Upsert POSTs ``{"data": [...]}`` batches to
``{baseUrl}/custom-connections/{connectionId}/resources/{resourceId}/records``;
200/201 both mean success (upsert by each record's own ``id``). Delete issues one
``DELETE .../records/{recordId}`` per id (204 or 404 both mean success -- already gone is
the goal). Failures never raise -- returned as ``DeliveryResult``, with auth/validation
non-retryable and 429/5xx retried with backoff.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime
import email.utils
import json
import logging
import random
import time
import urllib.parse
from collections.abc import Iterator
from typing import Any

import requests

from oci_drata.config import DrataConfig

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_AUTH_STATUS = frozenset({401, 403})
_VALIDATION_STATUS = frozenset({400, 404, 409, 422})
_REQUEST_ID_HEADERS = ("X-Request-Id", "X-Request-ID", "Request-Id", "X-Correlation-Id")
_BATCH_SIZE = 500


@dataclasses.dataclass(frozen=True)
class DeliveryResult:
    uploaded: bool
    created: bool | None  # True on 201, False on 200, None when not uploaded
    status_code: int | None
    attempts: int
    error_class: str | None = None  # "auth" | "validation" | "transport" | "unexpected"
    error_message: str | None = None
    request_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.uploaded


def _records_url(drata_config: DrataConfig) -> str:
    return (
        f"{drata_config.base_url.rstrip('/')}/custom-connections/"
        f"{drata_config.connection_id}/resources/{drata_config.resource_id}/records"
    )


@contextlib.contextmanager
def _http_session(session: requests.Session | None) -> Iterator[requests.Session]:
    """The caller's session untouched, or a private one closed on exit."""

    if session is not None:
        yield session
        return
    owned = requests.Session()
    try:
        yield owned
    finally:
        owned.close()


def _request_id(response: requests.Response) -> str | None:
    for header in _REQUEST_ID_HEADERS:
        value = response.headers.get(header)
        if value:
            return value
    return None


def _retry_after_seconds(response: requests.Response, *, max_delay_seconds: float) -> float | None:
    """Retry-After is seconds or an HTTP-date (RFC 9110 §10.2.3); None if unparseable, so
    caller falls back to jitter. Capped at max_delay_seconds regardless of the server's
    ask, so a misbehaving or compromised server can't stall retries indefinitely."""

    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    raw = raw.strip()
    if raw.isdigit():
        return min(float(raw), max_delay_seconds)
    try:
        target = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if target.tzinfo is None:
        return None
    delay = (target - datetime.datetime.now(tz=datetime.UTC)).total_seconds()
    return max(0.0, min(delay, max_delay_seconds))


def upsert_records(
    drata_config: DrataConfig,
    records: list[dict[str, Any]],
    *,
    max_attempts: int = 5,
    base_delay_seconds: float = 1.0,
    max_delay_seconds: float = 30.0,
    timeout_seconds: float = 30.0,
    max_payload_bytes: int | None = None,
    session: requests.Session | None = None,
) -> list[DeliveryResult]:
    """Upserts ``records`` in batches of up to ``_BATCH_SIZE``, POSTing ``{"data": [...]}``
    per batch. When ``max_payload_bytes`` is set, a batch whose serialized body would
    exceed it is halved repeatedly until each piece fits (or is down to one record, which
    is sent regardless -- a single oversized record isn't ours to truncate). Returns one
    DeliveryResult per batch actually sent, in order; a failed batch doesn't stop the rest."""

    if not records:
        return []

    token = drata_config.api_token_secret_ref.resolve()
    url = _records_url(drata_config)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    batches = _split_batches_by_size(records, max_payload_bytes=max_payload_bytes)

    with _http_session(session) as http:
        return [
            _upsert_with_retry(
                http, url, {"data": batch}, headers,
                max_attempts=max_attempts, base_delay_seconds=base_delay_seconds,
                max_delay_seconds=max_delay_seconds, timeout_seconds=timeout_seconds,
            )
            for batch in batches
        ]


def _batch_body_size(batch: list[dict[str, Any]]) -> int:
    return len(json.dumps({"data": batch}, separators=(",", ":")).encode("utf-8"))


def _shrink_batch_to_fit(
    batch: list[dict[str, Any]], *, max_payload_bytes: int
) -> list[list[dict[str, Any]]]:
    if len(batch) <= 1 or _batch_body_size(batch) <= max_payload_bytes:
        return [batch]
    mid = len(batch) // 2
    return (
        _shrink_batch_to_fit(batch[:mid], max_payload_bytes=max_payload_bytes)
        + _shrink_batch_to_fit(batch[mid:], max_payload_bytes=max_payload_bytes)
    )


def _split_batches_by_size(
    records: list[dict[str, Any]], *, max_payload_bytes: int | None
) -> list[list[dict[str, Any]]]:
    batches = [records[i : i + _BATCH_SIZE] for i in range(0, len(records), _BATCH_SIZE)]
    if max_payload_bytes is None:
        return batches
    return [
        piece
        for batch in batches
        for piece in _shrink_batch_to_fit(batch, max_payload_bytes=max_payload_bytes)
    ]


def delete_records(
    drata_config: DrataConfig,
    record_ids: list[str],
    *,
    max_attempts: int = 5,
    base_delay_seconds: float = 1.0,
    max_delay_seconds: float = 30.0,
    timeout_seconds: float = 30.0,
    session: requests.Session | None = None,
) -> list[DeliveryResult]:
    """Deletes each id in ``record_ids`` via one ``DELETE .../records/{recordId}`` call
    per id -- best-effort cleanup of records whose underlying OCI resource is gone.
    A failed delete doesn't stop the rest, and stale evidence lingering one more cycle
    is far cheaper than a bad delete: callers should only pass ids they're certain are
    gone (see transform.aggregate.FlatRecordsResult.excluded_ids)."""

    if not record_ids:
        return []

    token = drata_config.api_token_secret_ref.resolve()
    base_url = _records_url(drata_config)
    headers = {"Authorization": f"Bearer {token}"}

    with _http_session(session) as http:
        return [
            _delete_with_retry(
                http, f"{base_url}/{urllib.parse.quote(record_id, safe='')}", headers,
                max_attempts=max_attempts, base_delay_seconds=base_delay_seconds,
                max_delay_seconds=max_delay_seconds, timeout_seconds=timeout_seconds,
            )
            for record_id in record_ids
        ]


def _delete_with_retry(
    http: requests.Session,
    url: str,
    headers: dict[str, str],
    *,
    max_attempts: int,
    base_delay_seconds: float,
    max_delay_seconds: float,
    timeout_seconds: float,
) -> DeliveryResult:
    attempt = 0
    while True:
        attempt += 1
        try:
            response = http.delete(url, headers=headers, timeout=timeout_seconds)
        except requests.RequestException as exc:
            if attempt >= max_attempts:
                return DeliveryResult(
                    uploaded=False, created=None, status_code=None, attempts=attempt,
                    error_class="transport", error_message=str(exc),
                )
            _sleep_with_jitter(base_delay_seconds, max_delay_seconds, attempt)
            continue

        # 404 means the goal state (record absent) already holds -- e.g. a retry of a
        # delete that landed but whose response was lost. Treat it as success, not error.
        if response.status_code in (204, 404):
            return DeliveryResult(
                uploaded=True, created=None, status_code=response.status_code, attempts=attempt,
                request_id=_request_id(response),
            )

        if response.status_code in _AUTH_STATUS:
            return DeliveryResult(
                uploaded=False, created=None, status_code=response.status_code, attempts=attempt,
                error_class="auth", error_message=_safe_body(response), request_id=_request_id(response),
            )

        if response.status_code in _RETRYABLE_STATUS and attempt < max_attempts:
            retry_after = _retry_after_seconds(response, max_delay_seconds=max_delay_seconds)
            if retry_after is not None:
                time.sleep(retry_after)
            else:
                _sleep_with_jitter(base_delay_seconds, max_delay_seconds, attempt)
            continue

        return DeliveryResult(
            uploaded=False, created=None, status_code=response.status_code, attempts=attempt,
            error_class="unexpected" if response.status_code not in _VALIDATION_STATUS else "validation",
            error_message=_safe_body(response), request_id=_request_id(response),
        )


def _upsert_with_retry(
    http: requests.Session,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    max_attempts: int,
    base_delay_seconds: float,
    max_delay_seconds: float,
    timeout_seconds: float,
) -> DeliveryResult:
    attempt = 0
    while True:
        attempt += 1
        try:
            response = http.post(url, json=body, headers=headers, timeout=timeout_seconds)
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
            # Drata's batch endpoint can return 200 even when individual records fail
            # their own schema validation (per-record "error" field) -- 200/201 here
            # proves the request was accepted, not that anything was stored.
            per_record_error = _first_per_record_error(response)
            if per_record_error is not None:
                logger.warning(
                    "drata upload returned 200 but at least one record failed "
                    "per-record validation -- nothing in this batch is confirmed stored",
                    extra={"status_code": response.status_code, "error": per_record_error},
                )
                return DeliveryResult(
                    uploaded=False,
                    created=None,
                    status_code=response.status_code,
                    attempts=attempt,
                    error_class="validation",
                    error_message=per_record_error,
                    request_id=_request_id(response),
                )
            logger.info(
                "drata upload succeeded",
                extra={"status_code": response.status_code, "attempts": attempt},
            )
            return DeliveryResult(
                uploaded=True,
                created=response.status_code == 201,
                status_code=response.status_code,
                attempts=attempt,
                request_id=_request_id(response),
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
                request_id=_request_id(response),
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
                request_id=_request_id(response),
            )

        if response.status_code in _RETRYABLE_STATUS and attempt < max_attempts:
            retry_after = _retry_after_seconds(response, max_delay_seconds=max_delay_seconds)
            if retry_after is not None:
                logger.info(
                    "drata upload throttled/unavailable, honoring Retry-After",
                    extra={"status_code": response.status_code, "retry_after_seconds": retry_after},
                )
                time.sleep(retry_after)
            else:
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
            request_id=_request_id(response),
        )


def _first_per_record_error(response: requests.Response) -> str | None:
    """Body is a list of per-record results, or a single such object for a single-record
    call; each optionally carries {"error": {"message", "code"}}. Returns a bounded
    summary of every failed record's id + message, or None if none failed or the body
    isn't JSON/shaped as expected -- best-effort on top of the HTTP status, not a
    replacement for it."""

    try:
        payload = response.json()
    except ValueError:
        return None

    items = payload if isinstance(payload, list) else [payload]
    failures = []
    for item in items:
        if not isinstance(item, dict):
            continue
        error = item.get("error")
        if not error:
            continue
        record_id = None
        data = item.get("data")
        if isinstance(data, dict):
            record_id = data.get("id")
        message = error.get("message") if isinstance(error, dict) else str(error)
        failures.append(f"{record_id!r}: {message}")

    if not failures:
        return None
    shown = failures[:5]
    summary = "; ".join(shown)
    if len(failures) > len(shown):
        summary += f"; and {len(failures) - len(shown)} more"
    return f"{len(failures)}/{len(items)} record(s) failed per-record validation: {summary}"


def _safe_body(response: requests.Response) -> str:
    try:
        return response.text[:500]
    except Exception:
        return "<unreadable response body>"


def _sleep_with_jitter(base: float, cap: float, attempt: int) -> None:
    upper = min(cap, base * (2**attempt))
    time.sleep(random.uniform(0, upper))
