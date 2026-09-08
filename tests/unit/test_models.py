from __future__ import annotations

from oci_drata.models import (
    METRIC_KEYS,
    RESOURCE_COLLECTION_KEYS,
    Finding,
    Instance,
    IpsecConnection,
    Message,
    OperationRecord,
)


def test_instance_to_dict_has_every_schema_key_and_no_extra() -> None:
    inst = Instance(
        id="ocid1.instance.oc1..a",
        source_type="compute_instance",
        region="us-ashburn-1",
        compartment_id="ocid1.compartment.oc1..x",
        display_name="vm1",
        lifecycle_state="RUNNING",
    )
    expected_keys = {
        "id", "sourceType", "region", "compartmentId", "displayName", "lifecycleState",
        "timeCreated", "definedTags", "freeformTags", "imageId", "osClassification",
        "hasPublicAddress", "effectiveIngressExposure", "exposedAdministrativePorts",
        "vnicIds", "volumeIds",
    }
    assert set(inst.to_dict().keys()) == expected_keys


def test_instance_defaults_are_unknown_not_omitted() -> None:
    inst = Instance(
        id="i", source_type="compute_instance", region="us-ashburn-1",
        compartment_id="c", display_name=None, lifecycle_state=None,
    )
    d = inst.to_dict()
    assert d["osClassification"] == "unknown"
    assert d["effectiveIngressExposure"] == "unknown"
    assert d["hasPublicAddress"] is None
    assert d["vnicIds"] == []


def test_ipsec_connection_defaults() -> None:
    conn = IpsecConnection(
        id="i", source_type="ipsec_connection", region="us-ashburn-1",
        compartment_id="c", display_name=None, lifecycle_state=None,
    )
    d = conn.to_dict()
    assert d["redundancyStatus"] == "unknown"
    assert d["tunnelCount"] == 0


def test_finding_to_dict_matches_schema_shape() -> None:
    finding = Finding(
        assertion_id="OCI-COMPUTE-PUBLIC-EXPOSURE",
        status="fail",
        resource_type="compute_instance",
        resource_id="ocid1.instance.oc1..a",
        resource_name="vm1",
        region="us-ashburn-1",
        compartment_id="ocid1.compartment.oc1..x",
        observed="exposed",
        expected="not_exposed",
        reason="public address with permissive ingress on port 3389",
        source_ids=("ocid1.instance.oc1..a", "ocid1.vnic.oc1..v"),
        derivation_version="1.0.0",
    )
    d = finding.to_dict()
    assert d["status"] == "fail"
    assert d["sourceIds"] == ["ocid1.instance.oc1..a", "ocid1.vnic.oc1..v"]


def test_message_default_resource_ids_empty_list() -> None:
    msg = Message(code="UNSUPPORTED_EXADATA_DETECTED", message="Exadata detected", severity="warning")
    assert msg.to_dict()["resourceIds"] == []


def test_operation_record_to_dict() -> None:
    op = OperationRecord(
        service="compute", operation="list_instances", region="us-ashburn-1",
        status="success", page_count=2, item_count=15, request_ids=("r1", "r2"),
        compartment_id="ocid1.compartment.oc1..x",
    )
    d = op.to_dict()
    assert d["pageCount"] == 2
    assert d["requestIds"] == ["r1", "r2"]
    assert d["errorCode"] is None


def test_metric_and_resource_key_lists_match_schema_counts() -> None:
    # guards against drift from schemas/oci-snapshot-1.0.0.json
    from oci_drata.validation.schema import load_schema

    schema = load_schema()
    assert set(METRIC_KEYS) == set(schema["definitions"]["metrics"]["required"])
    assert set(RESOURCE_COLLECTION_KEYS) == set(schema["definitions"]["resources"]["required"])
