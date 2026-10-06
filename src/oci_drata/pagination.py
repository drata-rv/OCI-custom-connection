"""Reusable OCI list/get-operation execution: pagination, bounded retry with
backoff+jitter, a run-wide cap on concurrent in-flight requests, a wall-clock deadline,
and a per-operation result feeding the run report's operation counts. Every
``list_*``/``get_*`` call goes through :func:`paginate` or :func:`call_once`.
"""

from __future__ import annotations

import collections
import contextlib
import dataclasses
import functools
import logging
import random
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

import oci

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Mirrors OCI SDK's default classification (retry_checkers.
# TimeoutConnectionAndServiceErrorRetryChecker.RETRYABLE_STATUSES_AND_CODES,
# retry_any_5xx=True). 409 retries only these two transient codes -- most 409s
# are real conflicts. 501 is excluded: retrying an unimplemented op can't succeed.
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

class FairSemaphore:
    """Counting semaphore that serves waiters strictly in arrival order. ``threading.Semaphore``
    wakes an arbitrary waiter, so with hundreds of queued threads some requests starve for
    seconds while newer ones overtake them -- which spreads a deadline's casualties over every
    domain instead of finishing the early ones, and stretches the gap between listing a
    compartment's instances and its VNIC attachments. A releasing thread hands its slot straight
    to the longest waiter."""

    def __init__(self, value: int) -> None:
        self._lock = threading.Lock()
        self._value = value
        self._waiters: collections.deque[threading.Event] = collections.deque()

    def acquire(self) -> None:
        with self._lock:
            if self._value > 0 and not self._waiters:
                self._value -= 1
                return
            turn = threading.Event()
            self._waiters.append(turn)
        turn.wait()  # release() passed this thread the slot

    def release(self) -> None:
        with self._lock:
            if self._waiters:
                self._waiters.popleft().set()
            else:
                self._value += 1

    def __enter__(self) -> None:
        self.acquire()

    def __exit__(self, *exc_info: object) -> None:
        self.release()


# error_code for RetryPolicy.deadline cutting an operation short (--test, or a hosting
# time limit such as Lambda's); operations_complete() treats it as incomplete, same as any
# other failure, so the affected domain is withheld rather than delivered partial.
DEADLINE_EXCEEDED_ERROR_CODE = "DeadlineExceeded"


@dataclasses.dataclass(frozen=True)
class RetryPolicy:
    """How every OCI call of a run is executed: bounded retry with backoff, an optional
    wall-clock deadline, and a cap on concurrent in-flight requests."""

    max_attempts: int = 6
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    # time.monotonic() timestamp; unset means no deadline. Checked once per operation
    # (paginate/call_once), once per page, before each retry sleep, and again after
    # winning a request slot, so a run winds down within roughly this budget.
    deadline: float | None = None
    # Caps concurrent in-flight OCI requests across every collector of the run (one
    # semaphore shared by all of them); None means unbounded. Held only for the request
    # itself, never while sleeping between retries.
    call_slots: FairSemaphore | None = None
    # Tighter caps for services with documented per-tenancy rate limits (e.g. Monitoring, KMS:
    # 10 requests/s), keyed by the ``service`` label of the operation.
    service_slots: Mapping[str, FairSemaphore] = dataclasses.field(default_factory=dict)
    # Threads per fan-out stage. call_slots, not this, bounds real concurrency; this only
    # needs to be enough to keep every slot busy.
    fanout: int = 8

    def delay_seconds(self, attempt: int) -> float:
        """Full-jitter exponential backoff: uniform(0, min(cap, base*2^attempt))."""
        upper = min(self.max_delay_seconds, self.base_delay_seconds * (2**attempt))
        return random.uniform(0, upper)

    def deadline_exceeded(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline

    def run(self, tasks: Sequence[Callable[[], R]]) -> list[R]:
        """Runs zero-argument tasks (typically ``functools.partial(paginate, ...)``)
        concurrently and returns their results in input order."""

        return run_concurrently(list(tasks), _call_task, max_workers=self.fanout)


@dataclasses.dataclass
class OperationResult:
    """Outcome of one OCI operation, including every page collected. Collectors consume
    ``items`` directly; the run report carries only counts and request IDs.
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
    """Set ``.region`` on every item, overriding any same-named field the OCI
    model carries -- most resource types have no reliable region field of their own.
    """

    stamped = list(items)
    for item in stamped:
        item.region = region
    return stamped


R = TypeVar("R")


def run_concurrently(items: list[T], fn: Callable[[T], R], *, max_workers: int) -> list[R]:
    """Bounded concurrent map; results come back in input order.

    Each `fn(item)` must be self-contained and not mutate shared state -- the caller
    merges every result back sequentially afterwards, so no lock is needed anywhere in
    this module or its callers. Must not be called from inside another fan-out's `fn`
    that shares its pool -- each call here owns a fresh pool, so nesting is safe, just
    thread-hungry."""

    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(len(items), max_workers))) as pool:
        return list(pool.map(fn, items))


def _call_task(task: Callable[[], R]) -> R:
    return task()


def operations_complete(operations: Iterable[OperationResult]) -> bool:
    """Domain is complete when nothing failed or was unsupported. ``skipped`` means the
    service was disabled by configuration, not missing evidence. ``unsupported`` is
    treated as a blocking failure like ``failed`` -- fail-closed, since no operation here
    has a defined fallback for the evidence that depends on it."""

    return all(op.status not in ("failed", "unsupported") for op in operations)


class _RetryExhausted(Exception):
    def __init__(
        self,
        error_code: str,
        error_message: str,
        request_ids: list[str],
        retry_delays: list[float],
        status: int | None = None,
    ) -> None:
        super().__init__(error_message)
        self.error_code = error_code
        self.error_message = error_message
        self.request_ids = request_ids
        self.retry_delays = retry_delays
        self.status = status  # HTTP status of the final ServiceError; None for transport/deadline


class _DeadlineExceeded(Exception):
    """Raised inside a held request slot when the deadline passed while waiting for it."""


def _send(call: Callable[..., Any], policy: RetryPolicy, call_kwargs: dict[str, Any], service: str) -> Any:
    # Service slot first, then the run-wide slot: a thread queued behind a scarce per-service
    # limit holds nothing, so it can't starve every other service of run-wide slots.
    with contextlib.ExitStack() as stack:
        for slots in (policy.service_slots.get(service), policy.call_slots):
            if slots is not None:
                stack.enter_context(slots)
        # A thread can queue for a slot for a long time; don't spend one after the deadline.
        if policy.deadline_exceeded():
            raise _DeadlineExceeded
        return call(**call_kwargs)


def _invoke_with_retry(
    call: Callable[..., Any], policy: RetryPolicy, call_kwargs: dict[str, Any], service: str
) -> tuple[Any, list[str], list[float]]:
    request_ids: list[str] = []
    retry_delays: list[float] = []
    attempt = 0
    while True:
        try:
            response = _send(call, policy, call_kwargs, service)
        except _DeadlineExceeded as exc:
            raise _RetryExhausted(
                error_code=DEADLINE_EXCEEDED_ERROR_CODE,
                error_message="time budget exceeded while waiting for a request slot",
                request_ids=request_ids,
                retry_delays=retry_delays,
            ) from exc
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
                    status=exc.status,
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

        if policy.deadline_exceeded():
            # Checked inside the retry loop too: a single call retrying 429/5xx could
            # otherwise sleep through several backoff delays past the deadline before
            # paginate()/call_once()'s own check runs again.
            raise _RetryExhausted(
                error_code=DEADLINE_EXCEEDED_ERROR_CODE,
                error_message="time budget exceeded during retry backoff",
                request_ids=request_ids,
                retry_delays=retry_delays,
            )
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
    ``opc-next-page``. Never raises for a ``ServiceError`` or transport
    failure -- returns ``status="failed"`` instead; only a programmer error propagates.
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
            # Partial pages already in result.items stay, but status stays failed so
            # operations_complete() sees this domain as incomplete.
            result.status = "failed"
            result.error_code = DEADLINE_EXCEEDED_ERROR_CODE
            logger.debug(
                "time budget exceeded, stopping here",
                extra={
                    "service": service, "operation": operation,
                    "region": region, "compartment_id": compartment_id,
                    "pagesCollected": result.page_count,
                },
            )
            break
        kwargs = dict(call_kwargs)
        # compartment_id captured separately for the run report; forwarded here
        # since most list_*/get_* ops require it (e.g. get_tenancy doesn't).
        if compartment_id is not None:
            kwargs.setdefault("compartment_id", compartment_id)
        if page_token is not None:
            kwargs["page"] = page_token
        try:
            response, request_ids, retry_delays = _invoke_with_retry(call, policy, kwargs, service)
        except _RetryExhausted as exc:
            result.status = "failed"
            result.error_code = exc.error_code
            result.error_message = exc.error_message
            result.request_ids.extend(exc.request_ids)
            result.retry_delays_seconds.extend(exc.retry_delays)
            # DEBUG, not WARNING -- a tenancy with many compartments repeats the same
            # (service, operation, error_code) failure once per compartment/region;
            # runner.py logs one aggregated WARNING per distinct combination instead.
            logger.debug(
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
    missing_ok: bool = False,
    **call_kwargs: Any,
) -> OperationResult:
    """Execute a single (non-paginated) OCI SDK ``get_*`` bound method with the
    same bounded retry/backoff as :func:`paginate`. ``missing_ok`` makes a 404 a success
    with no items (e.g. a private IP with no public IP assigned) instead of a failure.

    ``compartment_id`` is metadata-only, never auto-forwarded -- most ``get_*``
    ops take a resource id, not a compartment filter, so forwarding could shadow
    a caller's own same-named argument. A call whose real parameter is genuinely
    ``compartment_id`` (e.g. Cloud Guard's ``get_configuration``) should bind it
    via closure over ``call`` -- see ``collection/cloud_guard.py``.
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
        result.error_code = DEADLINE_EXCEEDED_ERROR_CODE
        return result
    try:
        response, request_ids, retry_delays = _invoke_with_retry(call, policy, dict(call_kwargs), service)
    except _RetryExhausted as exc:
        result.request_ids.extend(exc.request_ids)
        result.retry_delays_seconds.extend(exc.retry_delays)
        if missing_ok and exc.status == 404:
            result.page_count = 1
            return result
        result.status = "failed"
        result.error_code = exc.error_code
        result.error_message = exc.error_message
        return result

    result.request_ids.extend(request_ids)
    result.retry_delays_seconds.extend(retry_delays)
    result.page_count = 1
    if response.data is not None:
        result.items.append(response.data)
        result.item_count = 1
    return result


def list_in_scope(
    policy: RetryPolicy,
    scope: Sequence[tuple[str, str]],
    listings: Sequence[tuple[str, str, Mapping[str, Any]]],
    **call_kwargs: Any,
) -> list[list[OperationResult]]:
    """For each ``(service, operation, clients_by_region)`` in ``listings``, one paginated
    listing per ``(region, compartment_id)`` in ``scope`` -- every listing of every
    operation in one concurrent pass. Returns one result list per listing, each in scope
    order, so callers zip it back against ``scope``."""

    # Scope-major, so every listing of one compartment is issued back to back (instances and
    # their VNIC attachments are then a consistent snapshot, not seconds apart).
    results = policy.run(
        [
            functools.partial(
                paginate,
                service=service,
                operation=operation,
                call=getattr(clients[region], operation),
                region=region,
                compartment_id=compartment_id,
                retry_policy=policy,
                **call_kwargs,
            )
            for region, compartment_id in scope
            for service, operation, clients in listings
        ]
    )
    return [results[i :: len(listings)] for i in range(len(listings))]
