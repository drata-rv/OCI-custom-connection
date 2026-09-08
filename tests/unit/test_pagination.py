from __future__ import annotations

from unittest.mock import MagicMock

import oci

from oci_drata.pagination import RetryPolicy, call_once, operations_complete, paginate


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


def test_paginate_forwards_compartment_id_into_call_kwargs() -> None:
    call = MagicMock(return_value=_response([]))
    paginate(
        service="compute",
        operation="list_instances",
        call=call,
        region="us-ashburn-1",
        compartment_id="ocid1.compartment.oc1..x",
    )
    assert call.call_args.kwargs["compartment_id"] == "ocid1.compartment.oc1..x"


def test_paginate_does_not_double_pass_explicit_compartment_id() -> None:
    call = MagicMock(return_value=_response([]))
    paginate(
        service="compute",
        operation="list_instances",
        call=call,
        compartment_id="ocid1.compartment.oc1..x",
        compartment_id_in_subtree=True,
    )
    assert call.call_args.kwargs["compartment_id"] == "ocid1.compartment.oc1..x"
    assert call.call_args.kwargs["compartment_id_in_subtree"] is True


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


def test_paginate_409_incorrect_state_is_retried() -> None:
    """P1-5: 409 is not blanket-retryable -- only OCI's own documented transient codes are."""
    conflict = oci.exceptions.ServiceError(409, "IncorrectState", {}, {"message": "resource busy"})
    call = MagicMock(side_effect=[conflict, _response(["x"])])
    result = paginate(service="compute", operation="list_instances", call=call, retry_policy=_fast_policy())
    assert result.status == "success"
    assert call.call_count == 2


def test_paginate_409_other_code_is_not_retried() -> None:
    """A 409 that isn't IncorrectState/LockConflict is a real conflict, not a transient one --
    retrying it can't help and previously burned the full retry budget for nothing."""
    conflict = oci.exceptions.ServiceError(
        409, "NotAuthorizedOrResourceAlreadyExists", {}, {"message": "already exists"}
    )
    call = MagicMock(side_effect=[conflict])
    result = paginate(service="compute", operation="list_instances", call=call, retry_policy=_fast_policy())
    assert result.status == "failed"
    assert call.call_count == 1


def test_paginate_501_not_implemented_is_not_retried() -> None:
    """5xx is retryable except 501 -- retrying an operation the service doesn't implement
    can never succeed."""
    not_implemented = oci.exceptions.ServiceError(501, "NotImplemented", {}, {"message": "nope"})
    call = MagicMock(side_effect=[not_implemented])
    result = paginate(service="compute", operation="list_instances", call=call, retry_policy=_fast_policy())
    assert result.status == "failed"
    assert call.call_count == 1


def test_paginate_502_is_retried() -> None:
    bad_gateway = oci.exceptions.ServiceError(502, "BadGateway", {}, {"message": "upstream"})
    call = MagicMock(side_effect=[bad_gateway, _response(["x"])])
    result = paginate(service="compute", operation="list_instances", call=call, retry_policy=_fast_policy())
    assert result.status == "success"
    assert call.call_count == 2


def test_paginate_records_retry_delays_in_manifest() -> None:
    """P1-5: backoff decisions must be visible in the manifest, not just applied silently."""
    throttle_error = oci.exceptions.ServiceError(429, "TooManyRequests", {}, {"message": "slow down"})
    call = MagicMock(side_effect=[throttle_error, throttle_error, _response(["x"])])
    result = paginate(service="compute", operation="list_instances", call=call, retry_policy=_fast_policy())
    assert result.status == "success"
    assert len(result.retry_delays_seconds) == 2
    assert all(d >= 0 for d in result.retry_delays_seconds)


def test_paginate_records_retry_delays_even_on_exhaustion() -> None:
    throttle_error = oci.exceptions.ServiceError(429, "TooManyRequests", {}, {"message": "slow down"})
    call = MagicMock(side_effect=[throttle_error, throttle_error, throttle_error])
    result = paginate(service="compute", operation="list_instances", call=call, retry_policy=_fast_policy())
    assert result.status == "failed"
    assert len(result.retry_delays_seconds) == 2  # 3 attempts total, 2 retries between them


def test_call_once_success() -> None:
    call = MagicMock(return_value=_response("single-item", headers={"opc-request-id": "r1"}))
    result = call_once(service="compute", operation="get_instance", call=call, instance_id="ocid1...")
    assert result.status == "success"
    assert result.items == ["single-item"]
    assert result.item_count == 1
    assert result.request_ids == ["r1"]


def test_call_once_does_not_auto_forward_compartment_id() -> None:
    call = MagicMock(return_value=_response("x"))
    call_once(
        service="compute",
        operation="get_instance",
        call=call,
        compartment_id="ocid1.compartment.oc1..x",  # metadata only
        instance_id="ocid1.instance.oc1..y",
    )
    assert "compartment_id" not in call.call_args.kwargs
    assert call.call_args.kwargs["instance_id"] == "ocid1.instance.oc1..y"


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
