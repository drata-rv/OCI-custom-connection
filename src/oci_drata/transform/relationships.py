"""Joins raw attachment/reference tables onto already-normalized resources; an unmatched
parent/child pair gets an :class:`~oci_drata.models.UnresolvedRelationship` record."""

from __future__ import annotations

import dataclasses
from typing import Any

from oci_drata.models import Instance, UnresolvedRelationship, Vnic


def classify_windows(instances: list[Instance], images: dict[str, Any]) -> list[Instance]:
    """Classifies windows/non_windows/unknown; never assumes non-Windows.
    Unknown covers missing image_id and failed/unauthorized lookup alike."""

    classified = []
    for instance in instances:
        classification = "unknown"
        if instance.image_id and instance.image_id in images:
            operating_system = getattr(images[instance.image_id], "operating_system", None) or ""
            classification = "windows" if "windows" in operating_system.lower() else "non_windows"
        classified.append(dataclasses.replace(instance, os_classification=classification))
    return classified


def resolve_instance_vnics(
    instances: list[Instance], *, vnic_attachments: list[Any]
) -> tuple[list[Instance], list[UnresolvedRelationship]]:
    vnic_ids_by_instance: dict[str, list[str]] = {}
    for attachment in vnic_attachments:
        instance_id = getattr(attachment, "instance_id", None)
        vnic_id = getattr(attachment, "vnic_id", None)
        if instance_id and vnic_id:
            vnic_ids_by_instance.setdefault(instance_id, []).append(vnic_id)

    resolved = [
        dataclasses.replace(
            instance, vnic_ids=tuple(sorted(set(vnic_ids_by_instance.get(instance.id, []))))
        )
        for instance in instances
    ]

    known_instance_ids = {i.id for i in instances}
    unresolved = [
        UnresolvedRelationship(
            source_type="vnic_attachment",
            source_id=getattr(attachment, "id", "unknown"),
            target_type="compute_instance",
            target_id=getattr(attachment, "instance_id"),
            reason="vnic_attachment.instance_id does not match any collected instance",
        )
        for attachment in vnic_attachments
        if getattr(attachment, "instance_id", None)
        and attachment.instance_id not in known_instance_ids
    ]

    return resolved, unresolved


def resolve_vnic_addresses(
    vnics: list[Vnic],
    *,
    private_ips: list[Any],
    public_ips_by_private_ip_id: dict[str, Any],
) -> tuple[list[Vnic], list[UnresolvedRelationship]]:
    public_by_vnic: dict[str, list[str]] = {}
    unresolved: list[UnresolvedRelationship] = []
    known_vnic_ids = {v.id for v in vnics}

    for private_ip in private_ips:
        vnic_id = getattr(private_ip, "vnic_id", None)
        if not vnic_id or not getattr(private_ip, "ip_address", None):
            continue
        if vnic_id not in known_vnic_ids:
            unresolved.append(
                UnresolvedRelationship(
                    source_type="private_ip",
                    source_id=getattr(private_ip, "id", "unknown"),
                    target_type="vnic",
                    target_id=vnic_id,
                    reason="private_ip.vnic_id does not match any collected VNIC",
                )
            )
            continue

        private_ip_id = getattr(private_ip, "id", None)
        public_ip = public_ips_by_private_ip_id.get(private_ip_id) if private_ip_id else None
        public_address = getattr(public_ip, "ip_address", None) if public_ip is not None else None
        if public_address:
            public_by_vnic.setdefault(vnic_id, []).append(public_address)

    resolved = [
        dataclasses.replace(vnic, public_addresses=tuple(sorted(set(public_by_vnic.get(vnic.id, [])))))
        for vnic in vnics
    ]
    return resolved, unresolved
