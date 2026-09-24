from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from oci_drata.config import DrataConfig, SecretRef
from oci_drata.delivery.drata import upsert_record, upsert_records


@pytest.fixture
def drata_config(monkeypatch: pytest.MonkeyPatch) -> DrataConfig:
    monkeypatch.setenv("DRATA_API_TOKEN", "fake-token-value")
    return DrataConfig(
        base_url="https://public-api.drata.com/public/v2",
        connection_id=1,
        resource_id=2,
        record_id="oci-snapshot-abc",
        api_token_secret_ref=SecretRef(provider="env", name="DRATA_API_TOKEN"),
    )


def _response(
    status_code: int, text: str = "{}", headers: dict | None = None, json_body: object = None
) -> MagicMock:
    """headers defaults to a real (empty) dict, not an unset MagicMock attribute --
    response.headers.get(...) on an unconfigured MagicMock returns another MagicMock,
    which is truthy and even survives float() (MagicMock's __float__ default is 1.0),
    silently masking what response.headers.get(...) actually does on a real
    requests.Response (returns None for an absent header). json_body left unset means
    .json() returns another MagicMock, same "not a dict/list" fallthrough a real
    non-JSON body would hit in _first_per_record_error."""

    mock = MagicMock(status_code=status_code, text=text, headers=headers or {})
    if json_body is not None:
        mock.json.return_value = json_body
    return mock


def test_initial_upsert_201_is_created(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.uploaded is True
    assert result.created is True
    assert result.attempts == 1


def test_subsequent_upsert_200_is_updated_not_created(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(200)
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.uploaded is True
    assert result.created is False


def test_auth_error_is_not_retried(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(401, "unauthorized")
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.uploaded is False
    assert result.error_class == "auth"
    assert session.post.call_count == 1


def test_schema_validation_error_is_not_retried_as_transport_failure(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(422, "schema violation")
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.uploaded is False
    assert result.error_class == "validation"
    assert session.post.call_count == 1


def test_429_is_retried_then_succeeds(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.side_effect = [_response(429, "slow down"), _response(201)]
    result = upsert_record(
        drata_config, {"id": "x"}, session=session, base_delay_seconds=0.001, max_delay_seconds=0.002
    )
    assert result.uploaded is True
    assert result.attempts == 2


def test_retry_exhaustion_on_5xx_returns_unexpected_error(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(503, "down")
    result = upsert_record(
        drata_config,
        {"id": "x"},
        session=session,
        max_attempts=3,
        base_delay_seconds=0.001,
        max_delay_seconds=0.002,
    )
    assert result.uploaded is False
    assert session.post.call_count == 3


def test_authorization_header_never_appears_in_result(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert "fake-token-value" not in repr(result)


def test_403_forbidden_is_classified_as_auth_not_validation(drata_config: DrataConfig) -> None:
    """403 (valid token, insufficient permission) is a distinct real-world case from 401
    (bad token) -- both are classified "auth" by this client, but each status is its own
    branch of _AUTH_STATUS and deserves its own regression coverage."""
    session = MagicMock()
    session.post.return_value = _response(403, "forbidden")
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.uploaded is False
    assert result.error_class == "auth"
    assert session.post.call_count == 1


def test_400_and_404_and_409_are_classified_as_validation(drata_config: DrataConfig) -> None:
    for status in (400, 404, 409):
        session = MagicMock()
        session.post.return_value = _response(status, "rejected")
        result = upsert_record(drata_config, {"id": "x"}, session=session)
        assert result.uploaded is False
        assert result.error_class == "validation", f"status {status}"
        assert session.post.call_count == 1


def test_unexpected_status_is_not_retried_and_classified_unexpected(drata_config: DrataConfig) -> None:
    """A status in none of the known sets (not 2xx, not auth, not validation, not the
    retryable 429/5xx set) must fail immediately, not be silently retried or misclassified."""
    session = MagicMock()
    session.post.return_value = _response(418, "teapot")
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.uploaded is False
    assert result.error_class == "unexpected"
    assert session.post.call_count == 1


def test_transport_exception_is_retried_then_succeeds(drata_config: DrataConfig) -> None:
    """The except requests.RequestException branch (connection reset, DNS failure, etc.) had
    no test coverage at all -- only the retryable-status-code path (429/5xx) was exercised."""
    session = MagicMock()
    session.post.side_effect = [requests.ConnectionError("reset"), _response(201)]
    result = upsert_record(
        drata_config, {"id": "x"}, session=session, base_delay_seconds=0.001, max_delay_seconds=0.002
    )
    assert result.uploaded is True
    assert result.attempts == 2


def test_transport_exception_exhaustion_returns_transport_error(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError("reset")
    result = upsert_record(
        drata_config, {"id": "x"}, session=session,
        max_attempts=3, base_delay_seconds=0.001, max_delay_seconds=0.002,
    )
    assert result.uploaded is False
    assert result.error_class == "transport"
    assert result.attempts == 3
    assert session.post.call_count == 3


def test_retry_after_seconds_form_is_honored(drata_config: DrataConfig, monkeypatch: pytest.MonkeyPatch) -> None:
    """P2: a 429 with Retry-After must sleep for (approximately) that long, not the
    generic jitter policy -- honoring the server's own throttling guidance."""

    sleeps: list[float] = []
    monkeypatch.setattr("oci_drata.delivery.drata.time.sleep", lambda s: sleeps.append(s))

    session = MagicMock()
    session.post.side_effect = [
        _response(429, "slow down", headers={"Retry-After": "7"}),
        _response(201),
    ]
    result = upsert_record(drata_config, {"id": "x"}, session=session, max_delay_seconds=30.0)
    assert result.uploaded is True
    assert sleeps == [7.0]


def test_retry_after_capped_at_max_delay_seconds(drata_config: DrataConfig, monkeypatch: pytest.MonkeyPatch) -> None:
    """A server-directed delay longer than our own safety cap must be capped, not
    obeyed verbatim -- a misbehaving or compromised server shouldn't be able to stall
    this indefinitely."""

    sleeps: list[float] = []
    monkeypatch.setattr("oci_drata.delivery.drata.time.sleep", lambda s: sleeps.append(s))

    session = MagicMock()
    session.post.side_effect = [
        _response(429, "slow down", headers={"Retry-After": "9999"}),
        _response(201),
    ]
    result = upsert_record(drata_config, {"id": "x"}, session=session, max_delay_seconds=5.0)
    assert result.uploaded is True
    assert sleeps == [5.0]


def test_malformed_retry_after_falls_back_to_jitter(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.side_effect = [
        _response(429, "slow down", headers={"Retry-After": "not-a-number-or-date"}),
        _response(201),
    ]
    result = upsert_record(
        drata_config, {"id": "x"}, session=session,
        base_delay_seconds=0.001, max_delay_seconds=0.002,
    )
    assert result.uploaded is True
    assert result.attempts == 2


def test_retry_after_http_date_form_is_honored(drata_config: DrataConfig, monkeypatch: pytest.MonkeyPatch) -> None:
    import datetime
    import email.utils

    fixed_now = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)

    class _FixedDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr("oci_drata.delivery.drata.datetime.datetime", _FixedDatetime)
    sleeps: list[float] = []
    monkeypatch.setattr("oci_drata.delivery.drata.time.sleep", lambda s: sleeps.append(s))

    retry_at = fixed_now + datetime.timedelta(seconds=10)
    session = MagicMock()
    session.post.side_effect = [
        _response(429, "slow down", headers={"Retry-After": email.utils.format_datetime(retry_at, usegmt=True)}),
        _response(201),
    ]
    result = upsert_record(drata_config, {"id": "x"}, session=session, max_delay_seconds=30.0)
    assert result.uploaded is True
    assert sleeps == [pytest.approx(10.0, abs=0.01)]


def test_request_id_captured_from_response_header(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201, headers={"X-Request-Id": "req-abc123"})
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.request_id == "req-abc123"


def test_request_id_none_when_header_absent(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.request_id is None


def test_caller_provided_session_is_never_closed(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    upsert_record(drata_config, {"id": "x"}, session=session)
    session.close.assert_not_called()


def test_internally_created_session_is_closed(drata_config: DrataConfig, monkeypatch: pytest.MonkeyPatch) -> None:
    created_session = MagicMock()
    created_session.post.return_value = _response(201)
    monkeypatch.setattr("oci_drata.delivery.drata.requests.Session", lambda: created_session)
    upsert_record(drata_config, {"id": "x"})
    created_session.close.assert_called_once()


def test_timeout_seconds_is_passed_through_to_post(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    upsert_record(drata_config, {"id": "x"}, session=session, timeout_seconds=45.0)
    assert session.post.call_args.kwargs["timeout"] == 45.0


def test_upsert_records_empty_list_makes_no_request(drata_config: DrataConfig) -> None:
    session = MagicMock()
    result = upsert_records(drata_config, [], session=session)
    assert result == []
    session.post.assert_not_called()


def test_upsert_records_single_batch_posts_array_body(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    records = [{"id": "a"}, {"id": "b"}]
    result = upsert_records(drata_config, records, session=session)
    assert len(result) == 1
    assert result[0].uploaded is True
    assert session.post.call_args.kwargs["json"] == {"data": records}


def test_upsert_records_200_with_per_record_errors_is_not_uploaded(drata_config: DrataConfig) -> None:
    """Confirmed live against a real connection: Drata's batch endpoint can return
    HTTP 200 for the call while every individual record inside failed its own schema
    validation -- nothing in that batch was actually stored, even though the naive
    status-code check that used to be here would have reported uploaded=True."""

    session = MagicMock()
    session.post.return_value = _response(
        200,
        json_body=[
            {
                "statusCode": 201,
                "error": {"message": "must have required property 'region'", "code": 28022},
                "data": {"id": "a"},
            },
            {
                "statusCode": 201,
                "error": {"message": "must have required property 'region'", "code": 28022},
                "data": {"id": "b"},
            },
        ],
    )
    result = upsert_records(drata_config, [{"id": "a"}, {"id": "b"}], session=session)
    assert len(result) == 1
    assert result[0].uploaded is False
    assert result[0].error_class == "validation"
    assert "'a'" in result[0].error_message
    assert "'b'" in result[0].error_message
    assert "region" in result[0].error_message


def test_upsert_records_200_with_partial_per_record_errors_is_not_uploaded(
    drata_config: DrataConfig,
) -> None:
    """Even one bad record in an otherwise-clean batch means the batch as a whole
    isn't confirmed fully stored -- callers shouldn't have to guess which subset
    landed from an "uploaded: true" that covers a mix."""

    session = MagicMock()
    session.post.return_value = _response(
        200,
        json_body=[
            {"statusCode": 200, "data": {"id": "good"}},
            {"statusCode": 201, "error": {"message": "bad record"}, "data": {"id": "bad"}},
        ],
    )
    result = upsert_records(drata_config, [{"id": "good"}, {"id": "bad"}], session=session)
    assert result[0].uploaded is False
    assert "1/2 record(s) failed" in result[0].error_message


def test_upsert_records_200_with_no_per_record_errors_is_uploaded(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(
        200, json_body=[{"statusCode": 200, "data": {"id": "a"}}]
    )
    result = upsert_records(drata_config, [{"id": "a"}], session=session)
    assert result[0].uploaded is True


def test_upsert_record_200_with_single_object_per_record_error_is_not_uploaded(
    drata_config: DrataConfig,
) -> None:
    """The single-record endpoint's response is one object, not a list of them --
    the same per-record error shape must still be caught, not just the batch case."""

    session = MagicMock()
    session.post.return_value = _response(
        200,
        json_body={
            "statusCode": 200,
            "error": {"message": "must have required property 'region'"},
            "data": {"id": "x"},
        },
    )
    result = upsert_record(drata_config, {"id": "x"}, session=session)
    assert result.uploaded is False
    assert result.error_class == "validation"


def test_upsert_records_non_json_200_body_falls_back_to_status_code(
    drata_config: DrataConfig,
) -> None:
    """A best-effort check layered on top of the HTTP status, not a replacement for
    it -- an unparseable/unexpected body must not turn a real success into a false
    failure."""

    session = MagicMock()
    session.post.return_value = _response(200)  # json_body unset: .json() isn't real JSON
    result = upsert_records(drata_config, [{"id": "a"}], session=session)
    assert result[0].uploaded is True


def test_upsert_records_splits_into_batches_of_500(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    records = [{"id": str(i)} for i in range(1200)]
    result = upsert_records(drata_config, records, session=session)
    assert len(result) == 3
    assert session.post.call_count == 3
    sizes = [len(call.kwargs["json"]["data"]) for call in session.post.call_args_list]
    assert sizes == [500, 500, 200]
    assert all(r.uploaded for r in result)


def test_upsert_records_one_failed_batch_does_not_block_others(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.side_effect = [_response(422, "bad batch"), _response(201)]
    records = [{"id": str(i)} for i in range(600)]
    result = upsert_records(drata_config, records, session=session)
    assert len(result) == 2
    assert result[0].uploaded is False
    assert result[0].error_class == "validation"
    assert result[1].uploaded is True


def test_upsert_records_caller_provided_session_is_never_closed(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    upsert_records(drata_config, [{"id": "a"}], session=session)
    session.close.assert_not_called()


def test_upsert_records_internally_created_session_is_closed(
    drata_config: DrataConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    created_session = MagicMock()
    created_session.post.return_value = _response(201)
    monkeypatch.setattr("oci_drata.delivery.drata.requests.Session", lambda: created_session)
    upsert_records(drata_config, [{"id": "a"}])
    created_session.close.assert_called_once()
