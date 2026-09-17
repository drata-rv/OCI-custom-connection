from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import oci
import pytest

from oci_drata.collection.compute import collect_compute
from oci_drata.config import OciServicesConfig


def _response(data, headers=None):
    return MagicMock(data=data, headers=headers or {})


def _services(**overrides) -> OciServicesConfig:
    base = dict(
        compute=False, network_exposure=False, block_storage=False, base_database=False,
        autonomous_database=False, exadata_detection=False, site_to_site_vpn=False,
    )
    base.update(overrides)
    return OciServicesConfig(**base)


@pytest.fixture
def discovery() -> SimpleNamespace:
    return SimpleNamespace(
        approved_regions=("us-ashburn-1",), approved_compartment_ids=("ocid1.compartment.oc1..c1",)
    )


def test_collect_compute_merges_concurrent_vnic_attachment_results(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """the per-attachment get_vnic/list_private_ips/get_public_ip
    enrichment loop was parallelized. Every attachment's data (across two here, one with
    a public IP and one without) must still be correctly merged into the shared
    vnics/private_ips/public_ips_by_private_ip_id structures regardless of which worker
    thread produced it."""

    attachment1 = oci.core.models.VnicAttachment(
        id="att1", instance_id="i1", vnic_id="v1", compartment_id="c1"
    )
    attachment2 = oci.core.models.VnicAttachment(
        id="att2", instance_id="i2", vnic_id="v2", compartment_id="c1"
    )
    vnic1 = oci.core.models.Vnic(id="v1", compartment_id="c1", subnet_id="sub1")
    vnic2 = oci.core.models.Vnic(id="v2", compartment_id="c1", subnet_id="sub1")
    private_ip1 = oci.core.models.PrivateIp(id="pip1", vnic_id="v1", ip_address="10.0.0.1")
    private_ip2 = oci.core.models.PrivateIp(id="pip2", vnic_id="v2", ip_address="10.0.0.2")
    public_ip1 = oci.core.models.PublicIp(id="pub1", ip_address="203.0.113.1")

    compute_client = MagicMock()
    compute_client.list_instances.return_value = _response(data=[])
    compute_client.list_vnic_attachments.return_value = _response(data=[attachment1, attachment2])

    def get_vnic_side_effect(**kwargs):
        vnic = {"v1": vnic1, "v2": vnic2}[kwargs["vnic_id"]]
        return _response(data=vnic)

    def list_private_ips_side_effect(**kwargs):
        ip = {"v1": private_ip1, "v2": private_ip2}[kwargs["vnic_id"]]
        return _response(data=[ip])

    def get_public_ip_side_effect(*, get_public_ip_by_private_ip_id_details):
        if get_public_ip_by_private_ip_id_details.private_ip_id == "pip1":
            return _response(data=public_ip1)
        raise oci.exceptions.ServiceError(404, "NotFound", {}, {"message": "no public ip"})

    vnet_client = MagicMock()
    vnet_client.get_vnic.side_effect = get_vnic_side_effect
    vnet_client.list_private_ips.side_effect = list_private_ips_side_effect
    vnet_client.get_public_ip_by_private_ip_id.side_effect = get_public_ip_side_effect

    clients_by_cls = {oci.core.ComputeClient: compute_client, oci.core.VirtualNetworkClient: vnet_client}
    monkeypatch.setattr(
        "oci_drata.collection.compute.regional_client",
        lambda client_cls, signer, *, region: clients_by_cls[client_cls],
    )

    result = collect_compute(signer=MagicMock(), discovery=discovery, services=_services(compute=True))

    assert set(result.vnics.keys()) == {"v1", "v2"}
    assert result.vnics["v1"].id == "v1"
    assert result.vnics["v2"].id == "v2"
    assert {p.id for p in result.private_ips} == {"pip1", "pip2"}
    assert set(result.public_ips_by_private_ip_id.keys()) == {"pip1"}
    assert result.public_ips_by_private_ip_id["pip1"].id == "pub1"
    assert result.complete


def test_collect_compute_vnic_cache_avoids_duplicate_get_vnic_call(
    monkeypatch: pytest.MonkeyPatch, discovery: SimpleNamespace
) -> None:
    """Two attachments sharing the same vnic_id (not the normal case, but the cache-check
    exists for a reason) must only fetch it once when processed across separate batches --
    the within-batch race is a documented, accepted, harmless trade-off, not what this
    covers."""

    discovery.approved_compartment_ids = ("c1", "c2")  # two sequential batches, not concurrent with each other
    attachment_c1 = oci.core.models.VnicAttachment(id="att1", instance_id="i1", vnic_id="v1", compartment_id="c1")
    attachment_c2 = oci.core.models.VnicAttachment(id="att2", instance_id="i2", vnic_id="v1", compartment_id="c2")
    vnic1 = oci.core.models.Vnic(id="v1", compartment_id="c1", subnet_id="sub1")

    compute_client = MagicMock()
    compute_client.list_instances.return_value = _response(data=[])

    def list_vnic_attachments_side_effect(**kwargs):
        attachment = attachment_c1 if kwargs["compartment_id"] == "c1" else attachment_c2
        return _response(data=[attachment])

    compute_client.list_vnic_attachments.side_effect = list_vnic_attachments_side_effect

    vnet_client = MagicMock()
    vnet_client.get_vnic.return_value = _response(data=vnic1)
    vnet_client.list_private_ips.return_value = _response(data=[])

    clients_by_cls = {oci.core.ComputeClient: compute_client, oci.core.VirtualNetworkClient: vnet_client}
    monkeypatch.setattr(
        "oci_drata.collection.compute.regional_client",
        lambda client_cls, signer, *, region: clients_by_cls[client_cls],
    )

    collect_compute(signer=MagicMock(), discovery=discovery, services=_services(compute=True))

    assert vnet_client.get_vnic.call_count == 1
