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
    """P2-2: a single aggregate record has a hard scaling ceiling by design (one Drata
    Custom Connection record per tenancy). near_budget is an early warning, surfaced in
    the local collection report/logs (not baked into the uploaded record itself, which
    would change its own measured size) so an operator sees the tenancy approaching the
    ceiling before it becomes a hard failure. See TRACEABILITY.md for the documented
    migration path (per-resource or multiple domain records) if this is ever reached."""

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
