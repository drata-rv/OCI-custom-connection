"""Validates aggregate record against oci_drata/schemas/oci-snapshot-1.0.0.json via jsonschema Draft-07.

Every resource definition is a single flat object (no allOf/$ref composition):
additionalProperties: false only reliably rejects unexpected fields within one schema's own
local properties, not across allOf branches -- composing over commonResource via allOf let
type-specific branches silently accept fields outside their own declared set, and
commonResource itself had to stay additionalProperties: true for that composition to
validate at all, so every resource type was permissive to arbitrary extra fields. Flattening
(duplicating commonResource's fields directly into each concrete definition) avoids the
allOf/additionalProperties interaction entirely rather than depending on validator-specific
allOf semantics (AJV and Draft-07 differ here) or a newer draft's unevaluatedProperties.
"""

from __future__ import annotations

import dataclasses
import importlib.resources
import json
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_RESOURCE_PACKAGE = "oci_drata.schemas"
SCHEMA_RESOURCE_NAME = "oci-snapshot-1.0.0.json"


@dataclasses.dataclass(frozen=True)
class SchemaValidationError:
    path: str  # dotted path to offending value
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message}


@dataclasses.dataclass(frozen=True)
class SchemaValidationResult:
    valid: bool
    errors: tuple[SchemaValidationError, ...]


def load_schema(path: Path | str | None = None) -> dict[str, Any]:
    if path is not None:
        with Path(path).open("r", encoding="utf-8") as fh:
            schema = json.load(fh)
    else:
        resource = importlib.resources.files(SCHEMA_RESOURCE_PACKAGE).joinpath(SCHEMA_RESOURCE_NAME)
        schema = json.loads(resource.read_text(encoding="utf-8"))
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
