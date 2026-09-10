from __future__ import annotations

from oci_drata.validation.size import check_payload_size, serialize_deterministic


def test_serialize_deterministic_is_byte_stable_across_calls() -> None:
    record = {"b": 1, "a": [1, 2, 3], "c": {"nested": True}}
    assert serialize_deterministic(record) == serialize_deterministic(record)


def test_serialize_deterministic_preserves_insertion_key_order() -> None:
    record = {"z": 1, "a": 2}
    serialized = serialize_deterministic(record).decode("utf-8")
    assert serialized.index('"z"') < serialized.index('"a"')


def test_payload_within_budget() -> None:
    result = check_payload_size({"id": "x"}, max_bytes=1000)
    assert result.within_budget
    assert result.byte_size < 1000


def test_payload_exceeds_budget_boundary() -> None:
    record = {"data": "x" * 100}
    exact = check_payload_size(record, max_bytes=len(serialize_deterministic(record)))
    assert exact.within_budget  # exactly at budget is allowed

    over = check_payload_size(record, max_bytes=len(serialize_deterministic(record)) - 1)
    assert not over.within_budget


def test_near_budget_is_false_when_comfortably_under() -> None:
    result = check_payload_size({"id": "x"}, max_bytes=10_000)
    assert result.near_budget is False


def test_near_budget_is_true_when_close_but_still_within() -> None:
    """P2-2: an early warning before the hard ceiling blocks upload outright."""
    record = {"data": "x" * 850}
    size = len(serialize_deterministic(record))
    result = check_payload_size(record, max_bytes=int(size / 0.9))  # ~90% of budget used
    assert result.within_budget
    assert result.near_budget is True


def test_near_budget_is_false_once_actually_over_budget() -> None:
    """Over budget is already surfaced via within_budget=False -- near_budget is
    specifically the "not yet over, but should be watched" signal, not a superset."""
    record = {"data": "x" * 850}
    size = len(serialize_deterministic(record))
    result = check_payload_size(record, max_bytes=size - 1)
    assert result.within_budget is False
    assert result.near_budget is False
