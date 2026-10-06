from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from oci_drata.config import DrataConfig, SecretRef
from oci_drata.delivery.drata import delete_records, upsert_records


@pytest.fixture
def drata_config(monkeypatch: pytest.MonkeyPatch) -> DrataConfig:
    monkeypatch.setenv("DRATA_API_TOKEN", "fake-token-value")
    return DrataConfig(
        base_url="https://public-api.drata.com/public/v2",
        connection_id=1,
        resource_id=2,
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


def test_429_is_retried_then_succeeds(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.side_effect = [_response(429, "slow down"), _response(201)]
    (result,) = upsert_records(drata_config, [{"id": "x"}], session=session)
    assert result.uploaded is True
    assert result.attempts == 2


def test_authorization_header_never_appears_in_result(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.return_value = _response(201)
    results = upsert_records(drata_config, [{"id": "x"}], session=session)
    assert "fake-token-value" not in repr(results)


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


def test_upsert_records_one_failed_batch_does_not_block_others(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.post.side_effect = [_response(422, "bad batch"), _response(201)]
    records = [{"id": str(i)} for i in range(600)]
    result = upsert_records(drata_config, records, session=session)
    assert len(result) == 2
    assert result[0].uploaded is False
    assert result[0].error_class == "validation"
    assert result[1].uploaded is True


def test_upsert_records_splits_oversized_batch_to_fit_budget(drata_config: DrataConfig) -> None:
    """500-record batching is count-based only; max_payload_bytes is a separate,
    independent ceiling on the serialized body actually sent."""

    session = MagicMock()
    session.post.return_value = _response(201)
    records = [{"id": str(i), "blob": "x" * 100} for i in range(10)]
    one_batch_bytes = len(str(records))  # comfortably bigger than any per-record share
    result = upsert_records(
        drata_config, records, session=session, max_payload_bytes=one_batch_bytes // 3
    )
    assert len(result) > 1
    assert all(r.uploaded for r in result)
    sent_ids = {
        record["id"] for call in session.post.call_args_list for record in call.kwargs["json"]["data"]
    }
    assert sent_ids == {r["id"] for r in records}


def test_delete_records_404_counts_as_success_already_gone(drata_config: DrataConfig) -> None:
    session = MagicMock()
    session.delete.return_value = _response(404, text="not found")
    result = delete_records(drata_config, ["rec-1"], session=session)
    assert result[0].uploaded is True
    assert result[0].status_code == 404


def test_delete_records_url_encodes_ids_with_embedded_slash(drata_config: DrataConfig) -> None:
    """api_key ids are "user_id/fingerprint" -- the slash is part of the id, not a path
    separator, and must be percent-encoded so the id stays one path segment."""

    session = MagicMock()
    session.delete.return_value = _response(204, text="")
    delete_records(drata_config, ["ocid1.user.oc1..u1/aa:bb:cc"], session=session)
    called_url = session.delete.call_args.args[0]
    assert "ocid1.user.oc1..u1/aa:bb:cc" not in called_url
    assert called_url.endswith("aa%3Abb%3Acc") or "%2F" in called_url


