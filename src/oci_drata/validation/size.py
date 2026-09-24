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
    """Size-check result for one tenancy's aggregate record, which has a hard ceiling (`max_bytes`).
    near_budget only warns externally (report/logs) — folding it into the record would change
    the record's own measured size."""

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
