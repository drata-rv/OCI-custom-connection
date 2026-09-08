from __future__ import annotations

from unittest.mock import MagicMock

import pytest

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
