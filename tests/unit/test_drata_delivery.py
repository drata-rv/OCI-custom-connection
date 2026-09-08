from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from oci_drata.config import DrataConfig, SecretRef
from oci_drata.delivery.drata import upsert_record


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


def _response(status_code: int, text: str = "{}") -> MagicMock:
    return MagicMock(status_code=status_code, text=text)


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
