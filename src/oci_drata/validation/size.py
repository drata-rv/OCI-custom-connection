"""Deterministic serialization and payload-size budget enforcement
(spec section 7.1 step 10, section 9: "budget is 4.5 MB").
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any


def serialize_deterministic(record: dict[str, Any]) -> bytes:
    """Serialize with stable key order (Python dicts preserve insertion
    order; every ``to_dict()`` in :mod:`oci_drata.models` emits keys in a
    fixed order) and stable array order (arrays are sorted by the aggregate
    builder before this is called, never here) -- the same record always
    produces the same bytes."""

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
