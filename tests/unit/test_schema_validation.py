from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from oci_drata.validation.schema import load_schema, validate_record

SPEC_PATH = Path(__file__).resolve().parent.parent.parent / "oci_to_drata_mvp_build_spec.md"


@pytest.fixture(scope="module")
def schema() -> dict:
    return load_schema()


@pytest.fixture(scope="module")
def sample_record() -> dict:
    spec_text = SPEC_PATH.read_text()
    match = re.search(r"Body:\n\n```json\n(.*?)\n```", spec_text, re.S)
    assert match is not None, "sample record not found in spec"
    body = json.loads(match.group(1))
    return body["data"]


def test_schema_is_valid_draft7(schema: dict) -> None:
    import jsonschema

    jsonschema.Draft7Validator.check_schema(schema)


def test_spec_sample_record_validates(schema: dict, sample_record: dict) -> None:
    result = validate_record(sample_record, schema)
    assert result.valid, result.errors


def test_missing_required_top_level_field_fails(schema: dict, sample_record: dict) -> None:
    broken = copy.deepcopy(sample_record)
    del broken["snapshotStatus"]
    result = validate_record(broken, schema)
    assert not result.valid


def test_unknown_top_level_field_fails(schema: dict, sample_record: dict) -> None:
    broken = copy.deepcopy(sample_record)
    broken["unexpectedField"] = "nope"
    result = validate_record(broken, schema)
    assert not result.valid


def test_invalid_enum_value_fails(schema: dict, sample_record: dict) -> None:
    broken = copy.deepcopy(sample_record)
    broken["snapshotStatus"] = "not-a-real-status"
    result = validate_record(broken, schema)
    assert not result.valid


def test_empty_resource_arrays_are_valid(schema: dict, sample_record: dict) -> None:
    # Distinguishing an empty (but successful) inventory from a failed
    # collection is a hard functional requirement -- an all-empty resources
    # object must still be schema-valid.
    result = validate_record(sample_record, schema)
    assert result.valid
    assert sample_record["resources"]["instances"] == []
