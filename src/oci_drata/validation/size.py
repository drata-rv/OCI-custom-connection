"""Deterministic serialization and payload-size budget enforcement."""

from __future__ import annotations

import dataclasses
import json
from typing import Any


def serialize_deterministic(record: dict[str, Any]) -> bytes:
    """Serialize record to deterministic bytes (stable key order, fixed separators).
    Caller must pre-sort arrays; this function does not sort them."""

    return json.dumps(record, sort_keys=False, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


@dataclasses.dataclass(frozen=True)
class PayloadSizeResult:
    """One aggregate record per tenancy has a hard size ceiling (`max_bytes`).
    near_budget warns early via the collection report/logs, not the record itself
    (which would change its own measured size). If a tenancy outgrows the ceiling,
    split into per-resource-type or per-domain records — either needs a distinct
    recordId per split and updates to any Custom Test spanning types/domains."""

    byte_size: int
    max_bytes: int
    near_budget_threshold: float = 0.8

    @property
    def within_budget(self) -> bool:
        return self.byte_size <= self.max_bytes

    @property
    def near_budget(self) -> bool:
        return self.within_budget and self.byte_size >= self.max_bytes * self.near_budget_threshold


def check_payload_size(
    record: dict[str, Any], max_bytes: int, *, near_budget_threshold: float = 0.8
) -> PayloadSizeResult:
    serialized = serialize_deterministic(record)
    return PayloadSizeResult(
        byte_size=len(serialized), max_bytes=max_bytes, near_budget_threshold=near_budget_threshold
    )
