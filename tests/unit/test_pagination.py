from __future__ import annotations

import functools
import time
from unittest.mock import MagicMock

import oci

from oci_drata.pagination import FairSemaphore, RetryPolicy, operations_complete, paginate


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _fast_policy() -> RetryPolicy:
    return RetryPolicy(max_attempts=3, base_delay_seconds=0.001, max_delay_seconds=0.002)


def test_paginate_exhausts_multiple_pages_including_empty_page_with_token() -> None:
    call = MagicMock(
        side_effect=[
            _response(["a", "b"], headers={"opc-next-page": "tok1", "opc-request-id": "r1"}),
            _response([], headers={"opc-next-page": "tok2", "opc-request-id": "r2"}),
            _response(["c"], headers={"opc-request-id": "r3"}),
        ]
    )
    result = paginate(service="compute", operation="list_instances", call=call, region="us-ashburn-1")
    assert result.status == "success"
    assert result.page_count == 3
    assert result.item_count == 3
    assert result.items == ["a", "b", "c"]
    assert result.request_ids == ["r1", "r2", "r3"]


def test_paginate_retries_throttling_then_succeeds() -> None:
    throttle_error = oci.exceptions.ServiceError(429, "TooManyRequests", {}, {"message": "slow down"})
    call = MagicMock(side_effect=[throttle_error, _response(["x"])])
    result = paginate(
        service="compute", operation="list_instances", call=call, retry_policy=_fast_policy()
    )
    assert result.status == "success"
    assert result.item_count == 1
    assert call.call_count == 2


def test_paginate_retry_exhaustion_marks_failed_not_raise() -> None:
    throttle_error = oci.exceptions.ServiceError(429, "TooManyRequests", {}, {"message": "slow down"})
    call = MagicMock(side_effect=[throttle_error, throttle_error, throttle_error])
    result = paginate(
        service="compute", operation="list_instances", call=call, retry_policy=_fast_policy()
    )
    assert result.status == "failed"
    assert result.error_code == "TooManyRequests"
    assert call.call_count == 3


def test_paginate_non_retryable_error_fails_immediately() -> None:
    auth_error = oci.exceptions.ServiceError(401, "NotAuthenticated", {}, {"message": "bad key"})
    call = MagicMock(side_effect=[auth_error])
    result = paginate(
        service="compute", operation="list_instances", call=call, retry_policy=_fast_policy()
    )
    assert result.status == "failed"
    assert call.call_count == 1  # no retry burned on a non-retryable status


def test_operations_complete_ignores_skipped_but_blocks_on_unsupported() -> None:
    """skipped (whole service disabled by config) is not a gap. unsupported (OCI/SDK didn't
    return what an assertion needs) is fail-closed, same as failed -- it must not silently
    count as complete."""

    from oci_drata.pagination import OperationResult

    ops = [
        OperationResult(service="s", operation="a", region=None, compartment_id=None, status="success"),
        OperationResult(service="s", operation="b", region=None, compartment_id=None, status="skipped"),
    ]
    assert operations_complete(ops) is True

    ops.append(
        OperationResult(service="s", operation="c", region=None, compartment_id=None, status="unsupported")
    )
    assert operations_complete(ops) is False

    ops[-1] = OperationResult(
        service="s", operation="c", region=None, compartment_id=None, status="failed"
    )
    assert operations_complete(ops) is False


def test_call_slots_bound_in_flight_requests_across_threads() -> None:
    import threading

    in_flight = 0
    peak = 0
    lock = threading.Lock()

    def slow_call(**kwargs):
        nonlocal in_flight, peak
        with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        threading.Event().wait(0.01)  # conftest no-ops time.sleep; really yield to the other threads
        with lock:
            in_flight -= 1
        return _response([])

    policy = RetryPolicy(call_slots=FairSemaphore(3), fanout=12)
    results = policy.run(
        [
            functools.partial(paginate, service="s", operation="list_x", call=slow_call, retry_policy=policy)
            for _ in range(24)
        ]
    )

    assert all(r.status == "success" for r in results)
    assert 1 < peak <= 3


def test_expired_deadline_fails_the_operation_without_calling() -> None:
    call = MagicMock()
    policy = RetryPolicy(deadline=time.monotonic() - 1)

    result = paginate(service="s", operation="list_x", call=call, retry_policy=policy)

    assert (result.status, result.error_code) == ("failed", "DeadlineExceeded")
    call.assert_not_called()


def test_fair_semaphore_hands_slots_to_waiters_in_arrival_order() -> None:
    import threading

    slots = FairSemaphore(1)
    slots.acquire()
    order: list[int] = []
    threads = []
    for n in range(6):
        thread = threading.Thread(target=lambda n=n: (slots.acquire(), order.append(n), slots.release()))
        thread.start()
        threads.append(thread)
        while len(slots._waiters) < n + 1:  # wait until this thread is queued before starting the next
            threading.Event().wait(0.001)

    slots.release()
    for thread in threads:
        thread.join(timeout=5)

    assert order == [0, 1, 2, 3, 4, 5]
