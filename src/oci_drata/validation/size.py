"""Deterministic record serialization (used for the report's byte totals)."""

from __future__ import annotations

import json
from typing import Any


def serialize_deterministic(record: dict[str, Any]) -> bytes:
    """Serialize record to deterministic bytes (stable key order, fixed separators).
    Caller must pre-sort arrays; this function does not sort them."""

    return json.dumps(record, sort_keys=False, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
