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
    byte_size: int
    max_bytes: int

    @property
    def within_budget(self) -> bool:
        return self.byte_size <= self.max_bytes


def check_payload_size(record: dict[str, Any], max_bytes: int) -> PayloadSizeResult:
    serialized = serialize_deterministic(record)
    return PayloadSizeResult(byte_size=len(serialized), max_bytes=max_bytes)
