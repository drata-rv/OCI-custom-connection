"""Reusable OCI list/get-operation execution: pagination, bounded retry with
backoff+jitter, and a per-operation result feeding ``manifest.operations``.
Every OCI SDK call goes through :func:`paginate` (``list_*``) or
:func:`call_once` (``get_*``).
"""

from __future__ import annotations

import dataclasses
import logging
import random
import time
from typing import Any, Callable, Iterable, TypeVar

import oci

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Retryable: throttling, transient server errors, 409 (OCI eventual-consistency conflicts).
RETRYABLE_STATUS_CODES = frozenset({409, 429, 500, 502, 503, 504})

OperationStatus = str  # "success" | "failed" | "unsupported" | "skipped"


@dataclasses.dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 20.0

    def delay_seconds(self, attempt: int) -> float:
        """Full-jitter exponential backoff: uniform(0, min(cap, base*2^attempt))."""
        upper = min(self.max_delay_seconds, self.base_delay_seconds * (2**attempt))
        return random.uniform(0, upper)


@dataclasses.dataclass
class OperationResult:
    """Outcome of one OCI operation, including every page collected.

    ``items`` is excluded from the manifest (only counts/request IDs
    serialized there, see transform/aggregate.py); collectors consume
    ``items`` directly.
    """

    service: str
    operation: str
    region: str | None
    compartment_id: str | None
    status: OperationStatus
    page_count: int = 0
    item_count: int = 0
    request_ids: list[str] = dataclasses.field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    items: list[Any] = dataclasses.field(default_factory=list, repr=False)

    @property
    def ok(self) -> bool:
        return self.status == "success"


def stamp_region(items: Iterable[Any], region: str) -> list[Any]:
    """Set ``.region`` on every item to the queried region, overriding any
    same-named field the OCI model carries -- most resource types have no
    reliable region field of their own.
    """

    stamped = list(items)
    for item in stamped:
        item.region = region
    return stamped


def operations_complete(operations: Iterable["OperationResult"]) -> bool:
    """Domain is complete when nothing in it failed or was unsupported. ``skipped`` is not a
    failure -- it means the whole service was disabled by configuration, a deliberate scope
    decision, not missing evidence. ``unsupported`` means OCI/the SDK didn't return what an
    assertion needs and is treated as a blocking gap, same as ``failed`` -- fail-closed, since
    no operation in this collector is currently classified as optional/enrichment-only with a
    defined force-unknown fallback for its dependent findings."""

    return all(op.status not in ("failed", "unsupported") for op in operations)


class _RetryExhausted(Exception):
    def __init__(self, error_code: str, error_message: str, request_ids: list[str]) -> None:
        super().__init__(error_message)
        self.error_code = error_code
        self.error_message = error_message
        self.request_ids = request_ids


def _invoke_with_retry(
    call: Callable[..., Any], policy: RetryPolicy, call_kwargs: dict[str, Any]
) -> tuple[Any, list[str]]:
    request_ids: list[str] = []
    attempt = 0
    while True:
        try:
            response = call(**call_kwargs)
        except oci.exceptions.ServiceError as exc:
            request_id = getattr(exc, "request_id", None)
            if request_id:
                request_ids.append(request_id)
            retryable = exc.status in RETRYABLE_STATUS_CODES
            if not retryable or attempt >= policy.max_attempts - 1:
                raise _RetryExhausted(
                    error_code=str(getattr(exc, "code", exc.status)),
                    error_message=str(getattr(exc, "message", str(exc))),
                    request_ids=request_ids,
                ) from exc
        except (oci.exceptions.ConnectTimeout, oci.exceptions.RequestException) as exc:
            if attempt >= policy.max_attempts - 1:
                raise _RetryExhausted(
                    error_code="transport_error",
                    error_message=str(exc),
                    request_ids=request_ids,
                ) from exc
        else:
            request_id = None
            headers = getattr(response, "headers", None)
            if headers:
                request_id = headers.get("opc-request-id")
            if request_id:
                request_ids.append(request_id)
            return response, request_ids

        time.sleep(policy.delay_seconds(attempt))
        attempt += 1


def paginate(
    *,
    service: str,
    operation: str,
    call: Callable[..., Any],
    region: str | None = None,
    compartment_id: str | None = None,
    retry_policy: RetryPolicy | None = None,
    **call_kwargs: Any,
) -> OperationResult:
    """Execute an OCI SDK ``list_*`` bound method, paginating via
    ``opc-next-page``. Never raises for a well-formed ``ServiceError`` or
    transport failure -- returns ``status="failed"`` instead; only a
    programmer error propagates.
    """

    policy = retry_policy or RetryPolicy()
    result = OperationResult(
        service=service,
        operation=operation,
        region=region,
        compartment_id=compartment_id,
        status="success",
    )

    page_token: str | None = None
    while True:
        kwargs = dict(call_kwargs)
        # compartment_id captured separately for the manifest; forwarded here
        # since most list_*/get_* ops require it (e.g. get_tenancy doesn't).
        if compartment_id is not None:
            kwargs.setdefault("compartment_id", compartment_id)
        if page_token is not None:
            kwargs["page"] = page_token
        try:
            response, request_ids = _invoke_with_retry(call, policy, kwargs)
        except _RetryExhausted as exc:
            result.status = "failed"
            result.error_code = exc.error_code
            result.error_message = exc.error_message
            result.request_ids.extend(exc.request_ids)
            logger.warning(
                "operation failed after retry exhaustion",
                extra={
                    "service": service,
                    "operation": operation,
                    "region": region,
                    "compartment_id": compartment_id,
                    "error_code": exc.error_code,
                },
            )
            return result

        result.request_ids.extend(request_ids)
        page_items = response.data or []
        result.items.extend(page_items)
        result.item_count += len(page_items)
        result.page_count += 1

        headers = getattr(response, "headers", None)
        page_token = headers.get("opc-next-page") if headers else None
        if not page_token:
            break

    return result


def call_once(
    *,
    service: str,
    operation: str,
    call: Callable[..., Any],
    region: str | None = None,
    compartment_id: str | None = None,
    retry_policy: RetryPolicy | None = None,
    **call_kwargs: Any,
) -> OperationResult:
    """Execute a single (non-paginated) OCI SDK ``get_*`` bound method with
    the same bounded retry/backoff-with-jitter behavior as :func:`paginate`.
    """

    policy = retry_policy or RetryPolicy()
    result = OperationResult(
        service=service,
        operation=operation,
        region=region,
        compartment_id=compartment_id,
        status="success",
    )
    try:
        response, request_ids = _invoke_with_retry(call, policy, dict(call_kwargs))
    except _RetryExhausted as exc:
        result.status = "failed"
        result.error_code = exc.error_code
        result.error_message = exc.error_message
        result.request_ids.extend(exc.request_ids)
        return result

    result.request_ids.extend(request_ids)
    result.page_count = 1
    if response.data is not None:
        result.items.append(response.data)
        result.item_count = 1
    return result
