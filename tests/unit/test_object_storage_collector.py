from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.object_storage import collect_object_storage
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
        identity=False, object_storage=False,
    )
    base.update(overrides)
    return OciServicesConfig(**base)


@pytest.fixture
def discovery() -> SimpleNamespace:
    return SimpleNamespace(
        approved_regions=("us-ashburn-1",),
        approved_compartment_ids=("ocid1.compartment.oc1..c1",),
    )


def test_disabled_by_default_never_calls_oci(monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace) -> None:
    client = MagicMock()
    monkeypatch.setattr(
        "oci_drata.collection.object_storage.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_object_storage(signer=MagicMock(), discovery=discovery, services=_services())

    assert result.buckets == []
    assert result.complete
    client.get_namespace.assert_not_called()


def test_collect_object_storage_lists_then_drills_down_per_bucket(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """list_buckets only returns BucketSummary (no public_access_type/kms_key_id/
    versioning) -- collect_object_storage must fetch the full Bucket via get_bucket
    per summary, not just pass the summary through."""

    summary1 = oci.object_storage.models.BucketSummary(name="bucket-1", namespace="ns1", compartment_id="c1")
    summary2 = oci.object_storage.models.BucketSummary(name="bucket-2", namespace="ns1", compartment_id="c1")
    full1 = oci.object_storage.models.Bucket(
        id="ocid1.bucket.oc1..b1", name="bucket-1", namespace="ns1", compartment_id="c1",
        public_access_type="NoPublicAccess", kms_key_id="ocid1.key.oc1..key1", versioning="Enabled",
    )
    full2 = oci.object_storage.models.Bucket(
        id="ocid1.bucket.oc1..b2", name="bucket-2", namespace="ns1", compartment_id="c1",
        public_access_type="ObjectRead", versioning="Disabled",
    )

    client = MagicMock()
    client.get_namespace.return_value = _response(data="ns1")
    client.list_buckets.return_value = _response(data=[summary1, summary2])

    def get_bucket_side_effect(**kwargs):
        return _response(data={"bucket-1": full1, "bucket-2": full2}[kwargs["bucket_name"]])

    client.get_bucket.side_effect = get_bucket_side_effect

    monkeypatch.setattr(
        "oci_drata.collection.object_storage.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_object_storage(signer=MagicMock(), discovery=discovery, services=_services(object_storage=True))

    assert {b.id for b in result.buckets} == {"ocid1.bucket.oc1..b1", "ocid1.bucket.oc1..b2"}
    by_id = {b.id: b for b in result.buckets}
    assert by_id["ocid1.bucket.oc1..b1"].kms_key_id == "ocid1.key.oc1..key1"
    assert by_id["ocid1.bucket.oc1..b2"].public_access_type == "ObjectRead"
    assert result.complete
    client.list_buckets.assert_called_once_with(
        compartment_id="ocid1.compartment.oc1..c1", namespace_name="ns1"
    )


def test_namespace_failure_skips_region_without_crashing(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    client = MagicMock()
    client.get_namespace.side_effect = oci.exceptions.ServiceError(
        status=404, code="NamespaceNotFound", headers={}, message="not found"
    )
    monkeypatch.setattr(
        "oci_drata.collection.object_storage.regional_client", lambda client_cls, signer, *, region: client
    )

    result = collect_object_storage(signer=MagicMock(), discovery=discovery, services=_services(object_storage=True))

    assert result.buckets == []
    assert not result.complete
    client.list_buckets.assert_not_called()
