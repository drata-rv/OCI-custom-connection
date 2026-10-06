"""The collection stages that decide which OCI calls are made (and which are skipped), against a
recording fake client: no network, no SDK models beyond plain data."""

from __future__ import annotations

from types import SimpleNamespace

import oci

from oci_drata.collection import compute, storage
from oci_drata.config import OciServicesConfig
from oci_drata.pagination import RetryPolicy, list_in_scope

SCOPE = [("r1", "c1"), ("r1", "c2")]
DISCOVERY = SimpleNamespace(scope=SCOPE, approved_regions=("r1",), approved_compartment_ids=("c1", "c2"))


class Recorder:
    """Fake OCI client: records every call; answers by operation name (a dict by compartment_id)."""

    def __init__(self, answers: dict) -> None:
        self.answers = answers
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, operation: str):
        def call(**kwargs):
            self.calls.append((operation, kwargs))
            answer = self.answers.get(operation, [])
            if isinstance(answer, dict):
                answer = answer.get(kwargs.get("compartment_id"), [])
            return SimpleNamespace(data=answer, headers={})

        return call

    def called(self, operation: str) -> list[dict]:
        return [kwargs for name, kwargs in self.calls if name == operation]


def _services(**on: bool) -> OciServicesConfig:
    off = dict(compute=False, network_exposure=False, block_storage=False, base_database=False,
               autonomous_database=False, site_to_site_vpn=False)
    return OciServicesConfig(**{**off, **on})


def test_list_in_scope_issues_a_compartments_listings_back_to_back_and_returns_each_in_scope_order() -> None:
    client = Recorder({})
    policy = RetryPolicy(fanout=1)  # one worker: call order is task order

    list_a, list_b = list_in_scope(policy, SCOPE, [("s", "list_a", {"r1": client}), ("s", "list_b", {"r1": client})])

    assert [(name, kw["compartment_id"]) for name, kw in client.calls] == [
        ("list_a", "c1"), ("list_b", "c1"), ("list_a", "c2"), ("list_b", "c2"),
    ]
    assert [op.compartment_id for op in list_a] == ["c1", "c2"]
    assert [(op.operation, op.compartment_id) for op in list_b] == [("list_b", "c1"), ("list_b", "c2")]


def test_compute_skips_vnic_lookups_for_detached_attachments_and_terminated_instances_and_dedupes(
    monkeypatch,
) -> None:
    def instance(instance_id, state, image_id):
        return oci.core.models.Instance(id=instance_id, lifecycle_state=state, image_id=image_id, compartment_id="c1")

    def attachment(attachment_id, instance_id, vnic_id, state):
        return oci.core.models.VnicAttachment(
            id=attachment_id, instance_id=instance_id, vnic_id=vnic_id, lifecycle_state=state, compartment_id="c1"
        )

    client = Recorder(
        {
            "list_instances": {"c1": [instance("i-live", "RUNNING", "img-live"), instance("i-gone", "TERMINATED", "img-gone")]},
            "list_vnic_attachments": {
                "c1": [
                    attachment("a1", "i-live", "v-live", "ATTACHED"),
                    attachment("a2", "i-live", "v-live", "ATTACHED"),  # same VNIC listed twice
                    attachment("a3", "i-live", "v-old", "DETACHED"),
                    attachment("a4", "i-gone", "v-gone", "ATTACHED"),
                ]
            },
            "get_image": oci.core.models.Image(id="img-live", operating_system="Linux"),
            "get_vnic": oci.core.models.Vnic(id="v-live", subnet_id="sub"),
        }
    )
    monkeypatch.setattr(compute, "regional_client", lambda cls, signer, *, region: client)

    result = compute.collect_compute(None, DISCOVERY, _services(compute=True))  # type: ignore[arg-type]

    assert [kw["image_id"] for kw in client.called("get_image")] == ["img-live"]  # not the terminated one's
    assert [kw["vnic_id"] for kw in client.called("get_vnic")] == ["v-live"]  # once; not detached/terminated
    assert set(result.vnics) == {"v-live"}
    assert result.complete


def test_storage_lists_boot_volume_attachments_only_in_availability_domains_that_hold_a_boot_volume(
    monkeypatch,
) -> None:
    client = Recorder(
        {"list_boot_volumes": {"c1": [oci.core.models.BootVolume(id="bv1", availability_domain="AD-2")]}}
    )
    monkeypatch.setattr(storage, "regional_client", lambda cls, signer, *, region: client)

    result = storage.collect_storage(None, DISCOVERY, _services(block_storage=True))  # type: ignore[arg-type]

    attachment_calls = client.called("list_boot_volume_attachments")
    assert sorted((kw["compartment_id"], kw["availability_domain"]) for kw in attachment_calls) == [
        ("c1", "AD-2"), ("c2", "AD-2"),
    ]  # every compartment (an attachment can live elsewhere than its volume), but only the AD in use
    assert result.complete
