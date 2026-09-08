"""OCID-based relationship resolution (spec 7.1 steps 3-5): join raw
attachment/reference tables onto already-normalized resources, and record
an :class:`~oci_drata.models.UnresolvedRelationship` instead of silently
dropping a child whose parent (or vice versa) can't be found.

Every function here is a pure transform: normalized resources in, updated
resources (via ``dataclasses.replace``, since the models are frozen) plus
any newly-discovered unresolved relationships out.

The Base/Autonomous Database join functions correlate a normalized list
with its raw source list positionally (``zip(raw_list, normalized_list)``):
callers must normalize each raw list into its normalized counterpart with a
single order-preserving pass (a list comprehension, not a dict rebuild) so
this invariant holds -- see :mod:`oci_drata.transform.aggregate`.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from oci_drata.models import DatabaseResource, Instance, UnresolvedRelationship, Vnic, Volume


def classify_windows(instances: list[Instance], images: dict[str, Any]) -> list[Instance]:
    """spec 5.2: windows | non_windows | unknown, never assumed
    non-Windows. Unknown covers a missing image_id and a failed/unauthorized
    image lookup identically -- both mean "we cannot prove this either way".
    """

    classified = []
    for instance in instances:
        classification = "unknown"
        if instance.image_id and instance.image_id in images:
            operating_system = getattr(images[instance.image_id], "operating_system", None) or ""
            classification = "windows" if "windows" in operating_system.lower() else "non_windows"
        classified.append(dataclasses.replace(instance, os_classification=classification))
    return classified


def resolve_instance_network_and_storage(
    instances: list[Instance],
    *,
    vnic_attachments: list[Any],
    boot_volume_attachments: list[Any],
    volume_attachments: list[Any],
) -> tuple[list[Instance], list[UnresolvedRelationship]]:
    vnic_ids_by_instance: dict[str, list[str]] = {}
    for attachment in vnic_attachments:
        instance_id = getattr(attachment, "instance_id", None)
        vnic_id = getattr(attachment, "vnic_id", None)
        if instance_id and vnic_id:
            vnic_ids_by_instance.setdefault(instance_id, []).append(vnic_id)

    volume_ids_by_instance: dict[str, list[str]] = {}
    for attachment in boot_volume_attachments:
        instance_id = getattr(attachment, "instance_id", None)
        boot_volume_id = getattr(attachment, "boot_volume_id", None)
        if instance_id and boot_volume_id:
            volume_ids_by_instance.setdefault(instance_id, []).append(boot_volume_id)
    for attachment in volume_attachments:
        instance_id = getattr(attachment, "instance_id", None)
        volume_id = getattr(attachment, "volume_id", None)
        if instance_id and volume_id:
            volume_ids_by_instance.setdefault(instance_id, []).append(volume_id)

    resolved = [
        dataclasses.replace(
            instance,
            vnic_ids=tuple(sorted(set(vnic_ids_by_instance.get(instance.id, [])))),
            volume_ids=tuple(sorted(set(volume_ids_by_instance.get(instance.id, [])))),
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
    vnic_attachments: list[Any],
    private_ips: list[Any],
    public_ips_by_private_ip_id: dict[str, Any],
) -> tuple[list[Vnic], list[UnresolvedRelationship]]:
    instance_id_by_vnic: dict[str, str] = {
        attachment.vnic_id: attachment.instance_id
        for attachment in vnic_attachments
        if getattr(attachment, "vnic_id", None) and getattr(attachment, "instance_id", None)
    }

    private_by_vnic: dict[str, list[str]] = {}
    public_by_vnic: dict[str, list[str]] = {}
    unresolved: list[UnresolvedRelationship] = []
    known_vnic_ids = {v.id for v in vnics}

    for private_ip in private_ips:
        vnic_id = getattr(private_ip, "vnic_id", None)
        address = getattr(private_ip, "ip_address", None)
        if not vnic_id or not address:
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
        private_by_vnic.setdefault(vnic_id, []).append(address)

        private_ip_id = getattr(private_ip, "id", None)
        public_ip = public_ips_by_private_ip_id.get(private_ip_id) if private_ip_id else None
        public_address = getattr(public_ip, "ip_address", None) if public_ip is not None else None
        if public_address:
            public_by_vnic.setdefault(vnic_id, []).append(public_address)

    resolved = [
        dataclasses.replace(
            vnic,
            instance_id=instance_id_by_vnic.get(vnic.id),
            private_addresses=tuple(sorted(set(private_by_vnic.get(vnic.id, ())))),
            public_addresses=tuple(sorted(set(public_by_vnic.get(vnic.id, ())))),
        )
        for vnic in vnics
    ]
    return resolved, unresolved


def resolve_volume_attachments(
    volumes: list[Volume],
    *,
    attachments: list[Any],
    attachment_volume_id_field: str,
) -> list[Volume]:
    """Shared by boot volumes (attachment_volume_id_field="boot_volume_id")
    and block volumes (attachment_volume_id_field="volume_id")."""

    instance_ids_by_volume: dict[str, list[str]] = {}
    for attachment in attachments:
        volume_id = getattr(attachment, attachment_volume_id_field, None)
        instance_id = getattr(attachment, "instance_id", None)
        if volume_id and instance_id:
            instance_ids_by_volume.setdefault(volume_id, []).append(instance_id)

    return [
        dataclasses.replace(
            volume,
            attached_instance_ids=tuple(sorted(set(instance_ids_by_volume.get(volume.id, [])))),
        )
        for volume in volumes
    ]


def _link(
    resources_by_id: dict[str, DatabaseResource],
    child_id: str,
    parent_id: str | None,
    *,
    child_type: str,
    parent_type: str,
    unresolved: list[UnresolvedRelationship],
) -> None:
    """Bidirectional relatedResourceIds link, mutating resources_by_id in
    place. Records an UnresolvedRelationship instead of dropping the child
    when the parent isn't in the collected set (e.g. a database whose
    parent DB home failed to page)."""

    if not parent_id:
        return
    if child_id in resources_by_id:
        child = resources_by_id[child_id]
        resources_by_id[child_id] = dataclasses.replace(
            child, related_resource_ids=tuple(sorted(set(child.related_resource_ids) | {parent_id}))
        )
    if parent_id in resources_by_id:
        parent = resources_by_id[parent_id]
        resources_by_id[parent_id] = dataclasses.replace(
            parent, related_resource_ids=tuple(sorted(set(parent.related_resource_ids) | {child_id}))
        )
    else:
        unresolved.append(
            UnresolvedRelationship(
                source_type=child_type,
                source_id=child_id,
                target_type=parent_type,
                target_id=parent_id,
                reason=f"{child_type}'s parent {parent_type} was not found in the collected set",
            )
        )


def resolve_base_database_relationships(
    *,
    raw_db_systems: list[Any],
    db_systems: list[DatabaseResource],
    raw_db_homes: list[Any],
    db_homes: list[DatabaseResource],
    raw_databases: list[Any],
    databases: list[DatabaseResource],
    raw_backups: list[Any],
    backups: list[DatabaseResource],
    raw_data_guard_associations: list[Any],
    data_guard_associations: list[DatabaseResource],
) -> tuple[
    list[DatabaseResource],
    list[DatabaseResource],
    list[DatabaseResource],
    list[DatabaseResource],
    list[DatabaseResource],
    list[UnresolvedRelationship],
]:
    unresolved: list[UnresolvedRelationship] = []
    by_id: dict[str, DatabaseResource] = {
        r.id: r
        for r in (*db_systems, *db_homes, *databases, *backups, *data_guard_associations)
    }

    for raw_home, home in zip(raw_db_homes, db_homes):
        _link(
            by_id,
            home.id,
            getattr(raw_home, "db_system_id", None),
            child_type="db_home",
            parent_type="db_system",
            unresolved=unresolved,
        )
    for raw_database, database in zip(raw_databases, databases):
        _link(
            by_id,
            database.id,
            getattr(raw_database, "db_home_id", None),
            child_type="database",
            parent_type="db_home",
            unresolved=unresolved,
        )
    for raw_backup, backup in zip(raw_backups, backups):
        _link(
            by_id,
            backup.id,
            getattr(raw_backup, "database_id", None),
            child_type="backup",
            parent_type="database",
            unresolved=unresolved,
        )
    for raw_dg, dg in zip(raw_data_guard_associations, data_guard_associations):
        database_id = getattr(raw_dg, "database_id", None)
        # DataGuardAssociation has no compartment_id of its own -- backfill
        # from the parent database now that the join is known.
        if database_id in by_id:
            dg = dataclasses.replace(dg, compartment_id=by_id[database_id].compartment_id)
            by_id[dg.id] = dg
        _link(
            by_id,
            dg.id,
            database_id,
            child_type="data_guard_association",
            parent_type="database",
            unresolved=unresolved,
        )

    def _resolved(originals: list[DatabaseResource]) -> list[DatabaseResource]:
        return [by_id.get(r.id, r) for r in originals]

    return (
        _resolved(db_systems),
        _resolved(db_homes),
        _resolved(databases),
        _resolved(backups),
        _resolved(data_guard_associations),
        unresolved,
    )


def resolve_autonomous_database_relationships(
    *,
    autonomous_databases: list[DatabaseResource],
    raw_autonomous_database_backups: list[Any],
    autonomous_database_backups: list[DatabaseResource],
    raw_autonomous_database_dataguard_associations: list[Any],
    autonomous_database_dataguard_associations: list[DatabaseResource],
    autonomous_database_peers_by_adb_id: dict[str, list[Any]],
) -> tuple[
    list[DatabaseResource],
    list[DatabaseResource],
    list[DatabaseResource],
    list[UnresolvedRelationship],
]:
    unresolved: list[UnresolvedRelationship] = []
    by_id: dict[str, DatabaseResource] = {
        r.id: r
        for r in (
            *autonomous_databases,
            *autonomous_database_backups,
            *autonomous_database_dataguard_associations,
        )
    }

    for raw_backup, backup in zip(raw_autonomous_database_backups, autonomous_database_backups):
        _link(
            by_id,
            backup.id,
            getattr(raw_backup, "autonomous_database_id", None),
            child_type="autonomous_database_backup",
            parent_type="autonomous_database",
            unresolved=unresolved,
        )
    for raw_dg, dg in zip(
        raw_autonomous_database_dataguard_associations, autonomous_database_dataguard_associations
    ):
        database_id = getattr(raw_dg, "autonomous_database_id", None) or getattr(
            raw_dg, "database_id", None
        )
        if database_id in by_id:
            dg = dataclasses.replace(dg, compartment_id=by_id[database_id].compartment_id)
            by_id[dg.id] = dg
        _link(
            by_id,
            dg.id,
            database_id,
            child_type="autonomous_database_dataguard_association",
            parent_type="autonomous_database",
            unresolved=unresolved,
        )

    # Peers are id/region pointers only (no separate resource row exists to
    # link to -- see normalize.py) -- fold each peer's id directly into the
    # owning ADB's relatedResourceIds. Already keyed by owning ADB id at
    # collection time (AutonomousDatabasePeerSummary carries no back-
    # reference of its own), so no join/unresolved-tracking is needed here.
    for adb_id, raw_peers in autonomous_database_peers_by_adb_id.items():
        peer_ids = {p.id for p in raw_peers if getattr(p, "id", None)}
        if adb_id in by_id and peer_ids:
            adb = by_id[adb_id]
            by_id[adb_id] = dataclasses.replace(
                adb, related_resource_ids=tuple(sorted(set(adb.related_resource_ids) | peer_ids))
            )

    def _resolved(originals: list[DatabaseResource]) -> list[DatabaseResource]:
        return [by_id.get(r.id, r) for r in originals]

    return (
        _resolved(autonomous_databases),
        _resolved(autonomous_database_backups),
        _resolved(autonomous_database_dataguard_associations),
        unresolved,
    )
