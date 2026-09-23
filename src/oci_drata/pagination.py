"""Reusable OCI list/get-operation execution: pagination, bounded retry with
backoff+jitter, and a per-operation result feeding ``manifest.operations``.
Every ``list_*``/``get_*`` call in ``collection/`` goes through :func:`paginate`
or :func:`call_once`, with one exception:
``collection/compute.py::_lookup_public_ip`` implements its own retry loop
to treat a 404 (no public IP assigned) as a synthetic success rather than a
domain failure, a case neither wrapper supports.
"""

from __future__ import annotations

import dataclasses
import logging
import random
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

import oci

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Mirrors the OCI Python SDK's own default classification
# (oci.retry.retry_checkers.TimeoutConnectionAndServiceErrorRetryChecker.RETRYABLE_STATUSES_AND_CODES /
# retry_any_5xx=True): a blanket "retry every 409" is wrong -- OCI's 409 covers many
# non-transient conflicts (e.g. a real naming/state conflict) alongside the two genuinely
# transient ones. 501 (Not Implemented) is deliberately excluded from the 5xx retry --
# retrying an operation the service doesn't implement can't ever succeed.
RETRYABLE_409_CODES = frozenset({"IncorrectState", "LockConflict"})


def is_retryable_service_error(exc: oci.exceptions.ServiceError) -> bool:
    status = exc.status
    code = getattr(exc, "code", None)
    if status == 409:
        return code in RETRYABLE_409_CODES
    if status == 429:
        return True
    if status >= 500 and status != 501:
        return True
    return False


OperationStatus = str  # "success" | "failed" | "unsupported" | "skipped"

# error_code used when RetryPolicy.deadline cuts an operation short (see --test in
# cli.py) -- a real, honest failure classification, not a silent partial success:
# operations_complete() must see this domain as incomplete, same as any other failure.
TEST_MODE_DEADLINE_ERROR_CODE = "TestModeDeadlineExceeded"


@dataclasses.dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 20.0
    # time.monotonic() timestamp; unset means no deadline. Set by cli.py's --test to
    # bound wall-clock time instead of guessing which compartments have data --
    # checked once per operation (paginate/call_once) and once per page, so a run
    # winds down within roughly this budget instead of an arbitrary resource cap.
    deadline: float | None = None

    def delay_seconds(self, attempt: int) -> float:
        """Full-jitter exponential backoff: uniform(0, min(cap, base*2^attempt))."""
        upper = min(self.max_delay_seconds, self.base_delay_seconds * (2**attempt))
        return random.uniform(0, upper)

    def deadline_exceeded(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline


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
    retry_delays_seconds: list[float] = dataclasses.field(default_factory=list)
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


R = TypeVar("R")


def run_concurrently(items: list[T], fn: Callable[[T], R], *, max_workers: int) -> list[R]:
    """Bounded concurrent map, for the N+1 per-item enrichment calls within one
    collector (get_vnic/list_private_ips/get_public_ip_by_private_ip_id per VNIC
    attachment, list_*_backups/_dataguard_associations per database, etc.) that a
    cross-collector ThreadPoolExecutor (see cli.py::_run_independent_collectors) doesn't
    touch -- that pool bounds concurrency *between* compute/storage/networking/database/
    vpn, not the serial per-item loop *within* one of them.

    Each `fn(item)` must be self-contained (build its own OperationResult(s), return
    them alongside whatever data the caller needs) and must not mutate shared state --
    the caller merges every result back into shared dicts/lists sequentially on the
    calling thread after every future completes, so no lock is needed anywhere in this
    module or its callers. ThreadPoolExecutor.map() does return results in the same
    order as `items` regardless of completion order -- callers just don't need to rely
    on that, since each result already carries everything needed to merge it back."""

    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(len(items), max_workers))) as pool:
        return list(pool.map(fn, items))


def operations_complete(operations: Iterable[OperationResult]) -> bool:
    """Domain is complete when nothing in it failed or was unsupported. ``skipped`` is not a
    failure -- it means the whole service was disabled by configuration, a deliberate scope
    decision, not missing evidence. ``unsupported`` means OCI/the SDK didn't return what an
    assertion needs and is treated as a blocking gap, same as ``failed`` -- fail-closed, since
    no operation in this collector is currently classified as optional/enrichment-only with a
    defined force-unknown fallback for its dependent findings."""

    return all(op.status not in ("failed", "unsupported") for op in operations)


class _RetryExhausted(Exception):
    def __init__(
        self, error_code: str, error_message: str, request_ids: list[str], retry_delays: list[float]
    ) -> None:
        super().__init__(error_message)
        self.error_code = error_code
        self.error_message = error_message
        self.request_ids = request_ids
        self.retry_delays = retry_delays


def _invoke_with_retry(
    call: Callable[..., Any], policy: RetryPolicy, call_kwargs: dict[str, Any]
) -> tuple[Any, list[str], list[float]]:
    request_ids: list[str] = []
    retry_delays: list[float] = []
    attempt = 0
    while True:
        try:
            response = call(**call_kwargs)
        except oci.exceptions.ServiceError as exc:
            request_id = getattr(exc, "request_id", None)
            if request_id:
                request_ids.append(request_id)
            retryable = is_retryable_service_error(exc)
            if not retryable or attempt >= policy.max_attempts - 1:
                raise _RetryExhausted(
                    error_code=str(getattr(exc, "code", exc.status)),
                    error_message=str(getattr(exc, "message", str(exc))),
                    request_ids=request_ids,
                    retry_delays=retry_delays,
                ) from exc
        except (oci.exceptions.ConnectTimeout, oci.exceptions.RequestException) as exc:
            if attempt >= policy.max_attempts - 1:
                raise _RetryExhausted(
                    error_code="transport_error",
                    error_message=str(exc),
                    request_ids=request_ids,
                    retry_delays=retry_delays,
                ) from exc
        else:
            request_id = None
            headers = getattr(response, "headers", None)
            if headers:
                request_id = headers.get("opc-request-id")
            if request_id:
                request_ids.append(request_id)
            return response, request_ids, retry_delays

        delay = policy.delay_seconds(attempt)
        retry_delays.append(delay)
        time.sleep(delay)
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
        if policy.deadline_exceeded():
            # Whatever pages already landed in result.items stay -- real, partial
            # data is still useful (e.g. for --test); the operation is still marked
            # failed, since operations_complete() must see this domain as incomplete.
            result.status = "failed"
            result.error_code = TEST_MODE_DEADLINE_ERROR_CODE
            logger.warning(
                "test mode: time budget exceeded, stopping here",
                extra={
                    "service": service, "operation": operation,
                    "region": region, "compartment_id": compartment_id,
                    "pagesCollected": result.page_count,
                },
            )
            break
        kwargs = dict(call_kwargs)
        # compartment_id captured separately for the manifest; forwarded here
        # since most list_*/get_* ops require it (e.g. get_tenancy doesn't).
        if compartment_id is not None:
            kwargs.setdefault("compartment_id", compartment_id)
        if page_token is not None:
            kwargs["page"] = page_token
        try:
            response, request_ids, retry_delays = _invoke_with_retry(call, policy, kwargs)
        except _RetryExhausted as exc:
            result.status = "failed"
            result.error_code = exc.error_code
            result.error_message = exc.error_message
            result.request_ids.extend(exc.request_ids)
            result.retry_delays_seconds.extend(exc.retry_delays)
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
        result.retry_delays_seconds.extend(retry_delays)
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

    Unlike :func:`paginate`, ``compartment_id`` here is metadata-only and never
    auto-forwarded to ``call`` -- most ``get_*`` operations take a specific
    resource id (``instance_id``, ``tenancy_id``, ...), not a compartment filter,
    so silently injecting one could shadow a caller's own same-named argument
    for an operation where it means something else. A ``get_*`` call whose real
    parameter genuinely is named ``compartment_id`` (e.g. Cloud Guard's
    ``get_configuration``) should bind it via a closure over ``call`` instead of
    relying on this parameter -- see ``collection/cloud_guard.py``.
    """

    policy = retry_policy or RetryPolicy()
    result = OperationResult(
        service=service,
        operation=operation,
        region=region,
        compartment_id=compartment_id,
        status="success",
    )
    if policy.deadline_exceeded():
        result.status = "failed"
        result.error_code = TEST_MODE_DEADLINE_ERROR_CODE
        logger.warning(
            "test mode: time budget exceeded, skipping operation",
            extra={"service": service, "operation": operation, "region": region, "compartment_id": compartment_id},
        )
        return result
    try:
        response, request_ids, retry_delays = _invoke_with_retry(call, policy, dict(call_kwargs))
    except _RetryExhausted as exc:
        result.status = "failed"
        result.error_code = exc.error_code
        result.error_message = exc.error_message
        result.request_ids.extend(exc.request_ids)
        result.retry_delays_seconds.extend(exc.retry_delays)
        return result

    result.request_ids.extend(request_ids)
    result.retry_delays_seconds.extend(retry_delays)
    result.page_count = 1
    if response.data is not None:
        result.items.append(response.data)
        result.item_count = 1
    return result
