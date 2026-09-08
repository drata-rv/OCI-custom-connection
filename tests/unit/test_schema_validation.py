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


def test_unexpected_field_on_a_flattened_composed_resource_fails(schema: dict, sample_record: dict) -> None:
    """P2-4 regression: instance is a flattened definition (commonResource's fields merged
    directly in, no allOf/$ref composition) specifically so additionalProperties: false is
    enforceable at all -- allOf composition over commonResource previously let a
    type-specific branch accept any field outside its own declared set, and commonResource
    itself had to stay permissive for the composition to validate. An accidental/typo'd/
    drifted field on any concrete resource type must be caught, not silently accepted."""

    from oci_drata.models import Instance

    valid_instance = Instance(
        id="ocid1.instance.oc1..i1", source_type="compute_instance", region="us-ashburn-1",
        compartment_id="ocid1.compartment.oc1..c1", display_name="vm1", lifecycle_state="RUNNING",
    ).to_dict()

    broken = copy.deepcopy(sample_record)
    broken["resources"]["instances"] = [{**valid_instance, "thisFieldShouldNotExist": "drift"}]
    result = validate_record(broken, schema)
    assert not result.valid

    fixed = copy.deepcopy(sample_record)
    fixed["resources"]["instances"] = [valid_instance]
    assert validate_record(fixed, schema).valid


def test_unexpected_field_on_a_plain_common_resource_fails(schema: dict, sample_record: dict) -> None:
    """Same as above for a resource type that is a direct $ref to commonResource (no
    type-specific fields of its own) -- commonResource itself must also reject drift now
    that nothing depends on it staying permissive for allOf composition."""

    from oci_drata.models import CommonResource

    valid_compartment = CommonResource(
        id="ocid1.compartment.oc1..c1", source_type="compartment", region="us-ashburn-1",
        compartment_id="ocid1.tenancy.oc1..root", display_name="prod", lifecycle_state="ACTIVE",
    ).to_dict()

    broken = copy.deepcopy(sample_record)
    broken["resources"]["compartments"] = [{**valid_compartment, "unexpectedField": "drift"}]
    result = validate_record(broken, schema)
    assert not result.valid
