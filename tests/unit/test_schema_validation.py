from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from oci_drata.validation.schema import load_schema, validate_record

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "sample-record.json"


@pytest.fixture(scope="module")
def schema() -> dict:
    return load_schema()


@pytest.fixture(scope="module")
def sample_record() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


def test_schema_is_valid_draft7(schema: dict) -> None:
    import jsonschema

    jsonschema.Draft7Validator.check_schema(schema)


def test_sample_record_validates(schema: dict, sample_record: dict) -> None:
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
    result = validate_record(sample_record, schema)
    assert result.valid
    assert sample_record["resources"]["instances"] == []
