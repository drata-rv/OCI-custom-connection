from __future__ import annotations

from oci_drata.models import Instance


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


