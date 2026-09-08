"""JSON Schema validation of the aggregate record against
``schemas/oci-snapshot-1.0.0.json`` (spec section 8).

Uses Python's ``jsonschema`` Draft-07 validator. The spec's own section 8
note flags a possible ``allOf``/``additionalProperties`` interaction risk
between AJV (what Drata uses) and other validators; this module is the
single place that would need to change if a flattened schema variant ever
becomes necessary -- callers only see "valid" or a list of structured
errors, never the schema mechanics.
"""

from __future__ import annotations

import dataclasses
import importlib.resources
import json
from pathlib import Path
from typing import Any

import jsonschema

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent.parent / "schemas" / "oci-snapshot-1.0.0.json"


@dataclasses.dataclass(frozen=True)
class SchemaValidationError:
    path: str  # JSON Pointer-ish dotted path to the offending value
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message}


@dataclasses.dataclass(frozen=True)
class SchemaValidationResult:
    valid: bool
    errors: tuple[SchemaValidationError, ...]


def load_schema(path: Path | str = DEFAULT_SCHEMA_PATH) -> dict[str, Any]:
    schema_path = Path(path)
    with schema_path.open("r", encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft7Validator.check_schema(schema)
    return schema


def validate_record(record: dict[str, Any], schema: dict[str, Any] | None = None) -> SchemaValidationResult:
    active_schema = schema if schema is not None else load_schema()
    validator = jsonschema.Draft7Validator(active_schema)
    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))
    if not errors:
        return SchemaValidationResult(valid=True, errors=())

    structured = tuple(
        SchemaValidationError(
            path=".".join(str(part) for part in error.absolute_path) or "$",
            message=error.message,
        )
        for error in errors
    )
    return SchemaValidationResult(valid=False, errors=structured)
