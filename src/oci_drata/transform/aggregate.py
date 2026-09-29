"""Builds the flat-record set: one record per collected resource, POSTed as
{"data": [...]} to a single flat schema/resourceId. Records carry raw OCI facts
only, no precomputed compliance verdict (no `status`, no port list pre-filtered
by admin-ports policy) -- the Drata Custom Test evaluates compliance against
these facts (e.g. `publicIngressPorts intersectsAny [22, 3389]`). Extend by
adding evidenceTypes here, not by restructuring the module.
"""

from __future__ import annotations

import dataclasses
import datetime
from typing import Any

from oci_drata.collection.cloud_guard import CloudGuardCollectionResult
from oci_drata.collection.compute import ComputeCollectionResult
from oci_drata.collection.database_autonomous import AutonomousDatabaseCollectionResult
from oci_drata.collection.database_base import DatabaseBaseCollectionResult
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.identity import IdentityCollectionResult
from oci_drata.collection.kms_vault import KmsVaultCollectionResult
from oci_drata.collection.load_balancer import LoadBalancerCollectionResult
from oci_drata.collection.monitoring import MonitoringCollectionResult
from oci_drata.collection.networking import NetworkingCollectionResult
from oci_drata.collection.object_storage import ObjectStorageCollectionResult
from oci_drata.collection.storage import StorageCollectionResult
from oci_drata.collection.vpn import VpnCollectionResult
from oci_drata.collection.waf import WafCollectionResult
from oci_drata.config import DecisionsConfig
from oci_drata.models import DatabaseResource, Instance
from oci_drata.transform import normalize, relationships
from oci_drata.transform.exposure import PublicIngressFacts, derive_public_ingress_facts
from oci_drata.transform.lifecycle import (
    exclude_lifecycle_cascade,
    exclude_referencing,
    split_by_lifecycle,
)

# evidenceType -> the domain_complete key(s) (FlatRecordsResult.domain_complete) that must
# all be True before a record of that type is safe to deliver/reconcile this run. "instance"
# depends on both compute (its own collection) and networking (feeds derive_public_ingress_facts).
EVIDENCE_TYPE_REQUIRED_DOMAINS: dict[str, tuple[str, ...]] = {
    "instance": ("compute", "networking"),
    "boot_volume": ("blockStorage",),
    "block_volume": ("blockStorage",),
    "db_system": ("baseDatabase",),
    "database": ("baseDatabase",),
    "autonomous_database": ("autonomousDatabase",),
    "ipsec_connection": ("vpn",),
    "iam_user": ("identity",),
    "api_key": ("identity",),
    "iam_policy": ("identity",),
    "bucket": ("objectStorage",),
    "cloud_guard_configuration": ("cloudGuard",),
    "monitoring_alarm": ("monitoring",),
    "load_balancer": ("loadBalancer",),
    "load_balancer_backend_set": ("loadBalancer",),
    "waf": ("waf",),
    "kms_key": ("kmsVault",),
}


@dataclasses.dataclass(frozen=True)
class FlatRecordsResult:
    records: list[dict[str, Any]]
    domain_complete: dict[str, bool]
    discovery_complete: bool
    # Per-evidenceType count of lifecycle-excluded (deleted/terminated) resources.
    # No warnings[] equivalent on this path, so this is what distinguishes "all
    # terminated" from "nothing collected" when recordCount is 0.
    excluded_counts: dict[str, int]
    # Per-evidenceType record ids that used to be in Drata but are gone this run
    # (lifecycle-excluded -- terminated/deleted in OCI). The caller deletes these by id
    # so a resource's flat record doesn't outlive the resource itself. Only populated for
    # evidenceTypes whose OCI list API still returns a deleted item (with a terminal
    # lifecycle_state) for some retention window -- "bucket" has no such state and so has
    # no entry here; a deleted bucket simply stops appearing in either list, with no
    # local signal to reconcile against (see delivery/drata.py's delete_records caller).
    excluded_ids: dict[str, list[str]]
    # Unresolved instance<->vnic/storage joins (relationships.py); tracked but not
    # enforced -- this path has no completeness gate on unresolved relationships.
    unresolved_relationship_count: int


# All evidenceTypes share one flat Drata schema. Drata's importer marks every
# top-level property required regardless of what's submitted, and
# `additionalProperties: true` doesn't cover missing required fields -- so every
# _flatten_* must emit every field, even irrelevant ones, or the record fails
# validation despite the batch endpoint still reporting HTTP 200 (see
# delivery/drata.py). Array fields default to `[]`, not `None`: the schema
# declares plain `"type": "array"` with no `"null"` option.
_FLAT_RECORD_FIELD_DEFAULTS: dict[str, Any] = {
    "id": None, "evidenceType": None, "name": None, "timestamp": None,
    "region": None, "compartmentId": None, "osClassification": None,
    "hasPublicAddress": None, "publicIngressPorts": [], "hasRangedPublicIngress": None,
    "kmsKeyId": None, "publicEndpointHostname": None, "mfaActivated": None,
    "userId": None, "keyCreatedAt": None, "statements": [],
    "publicAccessType": None, "versioning": None, "cloudGuardStatus": None,
    "alarmEnabled": None, "alarmNamespace": None, "alarmQuery": None,
    "isPrivate": None, "loadBalancerId": None, "backendSetHealthStatus": None,
    "vaultId": None, "autoRotationEnabled": None, "lastRotationAt": None,
    "attachedInstanceIds": [], "shape": None, "version": None,
    "diskRedundancy": None, "nodeCount": None, "backupStatus": None,
    "patchVersion": None, "recoveryWindowDays": None, "dataGuardRole": None,
    "tunnelCount": None, "upTunnelCount": None,
}


def _flatten_instance(
    instance: Instance, ingress: PublicIngressFacts, *, timestamp: str | None
) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": instance.id,
        "evidenceType": "instance",
        "name": instance.display_name,
        "timestamp": timestamp,
        "region": instance.region,
        "compartmentId": instance.compartment_id,
        "osClassification": instance.os_classification,
        "hasPublicAddress": ingress.has_public_address,
        "publicIngressPorts": list(ingress.public_ingress_ports),
        "hasRangedPublicIngress": ingress.has_ranged_public_ingress,
    }


def _flatten_autonomous_database(resource: DatabaseResource, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": resource.id,
        "evidenceType": "autonomous_database",
        "name": resource.display_name,
        "timestamp": timestamp,
        "region": resource.region,
        "compartmentId": resource.compartment_id,
        "kmsKeyId": resource.kms_key_id,
        "publicEndpointHostname": resource.public_endpoint_hostname,
    }


def _flatten_boot_volume(
    volume: Any, *, attached_instance_ids: tuple[str, ...], timestamp: str | None
) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": volume.id,
        "evidenceType": "boot_volume",
        "name": getattr(volume, "display_name", None),
        "timestamp": timestamp,
        "region": getattr(volume, "region", None),
        "compartmentId": volume.compartment_id,
        "kmsKeyId": getattr(volume, "kms_key_id", None),
        "attachedInstanceIds": list(attached_instance_ids),
    }


def _flatten_block_volume(
    volume: Any, *, attached_instance_ids: tuple[str, ...], timestamp: str | None
) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": volume.id,
        "evidenceType": "block_volume",
        "name": getattr(volume, "display_name", None),
        "timestamp": timestamp,
        "region": getattr(volume, "region", None),
        "compartmentId": volume.compartment_id,
        "kmsKeyId": getattr(volume, "kms_key_id", None),
        "attachedInstanceIds": list(attached_instance_ids),
    }


def _flatten_db_system(db_system: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": db_system.id,
        "evidenceType": "db_system",
        "name": getattr(db_system, "display_name", None),
        "timestamp": timestamp,
        "region": getattr(db_system, "region", None),
        "compartmentId": db_system.compartment_id,
        "shape": getattr(db_system, "shape", None),
        "version": getattr(db_system, "version", None),
        "diskRedundancy": getattr(db_system, "disk_redundancy", None),
        "nodeCount": getattr(db_system, "node_count", None),
    }


def _flatten_database(
    database: Any, *, data_guard_role: str | None, timestamp: str | None
) -> dict[str, Any]:
    backup_config = getattr(database, "db_backup_config", None)
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": database.id,
        "evidenceType": "database",
        "name": getattr(database, "db_name", None),
        "timestamp": timestamp,
        "region": getattr(database, "region", None),
        "compartmentId": database.compartment_id,
        "kmsKeyId": getattr(database, "kms_key_id", None),
        "backupStatus": normalize.normalize_db_backup_status(database),
        "patchVersion": getattr(database, "patch_version", None),
        "recoveryWindowDays": (
            getattr(backup_config, "recovery_window_in_days", None) if backup_config else None
        ),
        "dataGuardRole": data_guard_role,
    }


def _flatten_ipsec_connection(
    connection: Any, *, tunnel_count: int, up_tunnel_count: int, timestamp: str | None
) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": connection.id,
        "evidenceType": "ipsec_connection",
        "name": getattr(connection, "display_name", None),
        "timestamp": timestamp,
        "region": getattr(connection, "region", None),
        "compartmentId": connection.compartment_id,
        "tunnelCount": tunnel_count,
        "upTunnelCount": up_tunnel_count,
    }


def _flatten_iam_user(user: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": user.id,
        "evidenceType": "iam_user",
        "name": user.name,
        "timestamp": timestamp,
        "compartmentId": user.compartment_id,
        "mfaActivated": user.is_mfa_activated,
    }


def _flatten_api_key(api_key: Any, *, timestamp: str | None) -> dict[str, Any]:
    # api_key.key_id ("TENANCY_OCID/USER_OCID/FINGERPRINT") can exceed an undocumented
    # length limit Drata enforces on id platform-side (not visible in the schema).
    # The tenancy segment is redundant here (one tenancy per resource), so
    # user_id/fingerprint keeps the same uniqueness at roughly half the length.
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": f"{api_key.user_id}/{api_key.fingerprint}",
        "evidenceType": "api_key",
        "name": api_key.fingerprint,
        "timestamp": timestamp,
        "userId": api_key.user_id,
        "keyCreatedAt": normalize.normalize_timestamp(api_key.time_created),
    }


def _flatten_bucket(bucket: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": bucket.id,
        "evidenceType": "bucket",
        "name": bucket.name,
        "timestamp": timestamp,
        "region": getattr(bucket, "region", None),
        "compartmentId": bucket.compartment_id,
        "kmsKeyId": bucket.kms_key_id,
        "publicAccessType": bucket.public_access_type,
        "versioning": bucket.versioning,
    }


def _flatten_iam_policy(policy: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": policy.id,
        "evidenceType": "iam_policy",
        "name": policy.name,
        "timestamp": timestamp,
        "compartmentId": policy.compartment_id,
        "statements": list(policy.statements or ()),
    }


def _flatten_cloud_guard_configuration(
    configuration: Any, *, tenancy_id: str | None, timestamp: str | None
) -> dict[str, Any]:
    # Cloud Guard Configuration is a tenancy-wide singleton with no id/compartmentId
    # of its own; tenancy OCID is the only stable unique id for upsert-by-id.
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": tenancy_id or "cloud-guard-configuration",
        "evidenceType": "cloud_guard_configuration",
        "name": "Cloud Guard",
        "timestamp": timestamp,
        "compartmentId": tenancy_id,
        "cloudGuardStatus": configuration.status,
    }


def _flatten_alarm(alarm: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": alarm.id,
        "evidenceType": "monitoring_alarm",
        "name": alarm.display_name,
        "timestamp": timestamp,
        "region": getattr(alarm, "region", None),
        "compartmentId": alarm.compartment_id,
        "alarmEnabled": alarm.is_enabled,
        "alarmNamespace": alarm.namespace,
        "alarmQuery": alarm.query,
    }


def _flatten_load_balancer(lb: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": lb.id,
        "evidenceType": "load_balancer",
        "name": lb.display_name,
        "timestamp": timestamp,
        "region": getattr(lb, "region", None),
        "compartmentId": lb.compartment_id,
        "isPrivate": lb.is_private,
    }


def _flatten_backend_set_health(
    lb: Any, backend_set_name: str, health: Any, *, timestamp: str | None
) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        # A backend set name is only unique within its own load balancer, not
        # tenancy-wide -- composite id to keep upsert-by-id meaningful.
        "id": f"{lb.id}:{backend_set_name}",
        "evidenceType": "load_balancer_backend_set",
        "name": backend_set_name,
        "timestamp": timestamp,
        "region": getattr(lb, "region", None),
        "compartmentId": lb.compartment_id,
        "loadBalancerId": lb.id,
        "backendSetHealthStatus": health.status,
    }


def _flatten_waf(waf: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": waf.id,
        "evidenceType": "waf",
        "name": waf.display_name,
        "timestamp": timestamp,
        "region": getattr(waf, "region", None),
        "compartmentId": waf.compartment_id,
        "loadBalancerId": waf.load_balancer_id,
    }


def _flatten_kms_key(key: Any, *, timestamp: str | None) -> dict[str, Any]:
    rotation_details = getattr(key, "auto_key_rotation_details", None)
    return {
        **_FLAT_RECORD_FIELD_DEFAULTS,
        "id": key.id,
        "evidenceType": "kms_key",
        "name": key.display_name,
        "timestamp": timestamp,
        "region": getattr(key, "region", None),
        "compartmentId": key.compartment_id,
        "vaultId": key.vault_id,
        "autoRotationEnabled": key.is_auto_rotation_enabled,
        "lastRotationAt": normalize.normalize_timestamp(
            getattr(rotation_details, "time_of_last_rotation", None)
        ),
    }


def build_flat_records(
    *,
    decisions: DecisionsConfig,
    discovery: DiscoveryResult,
    compute: ComputeCollectionResult,
    storage: StorageCollectionResult,
    networking: NetworkingCollectionResult,
    database_base: DatabaseBaseCollectionResult,
    autonomous_database: AutonomousDatabaseCollectionResult,
    vpn: VpnCollectionResult,
    identity: IdentityCollectionResult,
    object_storage: ObjectStorageCollectionResult,
    cloud_guard: CloudGuardCollectionResult,
    monitoring: MonitoringCollectionResult,
    load_balancer: LoadBalancerCollectionResult,
    waf: WafCollectionResult,
    kms_vault: KmsVaultCollectionResult,
    completed_at: datetime.datetime,
) -> FlatRecordsResult:
    """Raw per-resource facts only, no precomputed compliance verdict -- see module
    docstring. The Drata Custom Test applies policy (e.g. an administrativePorts
    allowlist) against these facts itself."""

    kept_instances_raw, excluded_instances_raw = split_by_lifecycle(compute.instances)
    excluded_instance_ids = {i.id for i in excluded_instances_raw}
    vnic_attachments = exclude_referencing(
        compute.vnic_attachments, excluded_ids=excluded_instance_ids, id_field="instance_id"
    )

    instances = [normalize.normalize_instance(i) for i in kept_instances_raw]
    instances = relationships.classify_windows(instances, compute.images)
    instances, unresolved_storage = relationships.resolve_instance_network_and_storage(
        instances,
        vnic_attachments=vnic_attachments,
        boot_volume_attachments=[],
        volume_attachments=[],
    )

    vnics = [normalize.normalize_vnic(v) for v in compute.vnics.values()]
    vnics, unresolved_vnic = relationships.resolve_vnic_addresses(
        vnics,
        vnic_attachments=vnic_attachments,
        private_ips=compute.private_ips,
        public_ips_by_private_ip_id=compute.public_ips_by_private_ip_id,
    )

    ingress_by_instance_id = derive_public_ingress_facts(
        instances,
        vnics_by_id={v.id: v for v in vnics},
        subnets_by_id={s.id: s for s in networking.subnets},
        route_tables_by_id={r.id: r for r in networking.route_tables},
        security_lists_by_id={s.id: s for s in networking.security_lists},
        nsg_security_rules_by_nsg_id=networking.nsg_security_rules_by_nsg_id,
        internet_gateway_ids={g.id for g in networking.internet_gateways},
        public_source_cidrs=decisions.public_source_cidrs,
    )

    kept_adb_raw, excluded_adb_raw = exclude_lifecycle_cascade(
        autonomous_database.autonomous_databases, parent_excluded_ids=set(), parent_id_field=None
    )
    autonomous_databases = [
        normalize.normalize_database_resource(
            a, database_type="autonomous_database", source_type="autonomous_database",
            backup_status="not_applicable",
            detail_fields=normalize.normalize_autonomous_database_posture(a),
        )
        for a in kept_adb_raw
    ]

    # -- Block storage: boot/block volumes, joined to their attached instance(s) --
    kept_boot_volumes_raw, excluded_boot_volumes_raw = split_by_lifecycle(storage.boot_volumes)
    kept_block_volumes_raw, excluded_block_volumes_raw = split_by_lifecycle(storage.block_volumes)
    instance_ids_by_boot_volume_id: dict[str, list[str]] = {}
    for attachment in storage.boot_volume_attachments:
        volume_id = getattr(attachment, "boot_volume_id", None)
        instance_id = getattr(attachment, "instance_id", None)
        if volume_id and instance_id:
            instance_ids_by_boot_volume_id.setdefault(volume_id, []).append(instance_id)
    instance_ids_by_block_volume_id: dict[str, list[str]] = {}
    for attachment in storage.volume_attachments:
        volume_id = getattr(attachment, "volume_id", None)
        instance_id = getattr(attachment, "instance_id", None)
        if volume_id and instance_id:
            instance_ids_by_block_volume_id.setdefault(volume_id, []).append(instance_id)

    # -- Base Database Service: lifecycle exclusion cascades db_system -> db_home ->
    # database, so a database under a terminated db_system is excluded too, not left
    # orphaned. Data Guard role is a direct per-database join (leaf, no cascade needed).
    kept_db_systems_raw, excluded_db_systems_raw = exclude_lifecycle_cascade(
        database_base.db_systems, parent_excluded_ids=set(), parent_id_field=None
    )
    excluded_db_system_ids = {s.id for s in excluded_db_systems_raw}
    kept_db_homes_raw, excluded_db_homes_raw = exclude_lifecycle_cascade(
        database_base.db_homes, parent_excluded_ids=excluded_db_system_ids, parent_id_field="db_system_id"
    )
    excluded_db_home_ids = {h.id for h in excluded_db_homes_raw}
    kept_databases_raw, excluded_databases_raw = exclude_lifecycle_cascade(
        database_base.databases, parent_excluded_ids=excluded_db_home_ids, parent_id_field="db_home_id"
    )
    kept_data_guard_raw, _ = split_by_lifecycle(database_base.data_guard_associations)
    data_guard_role_by_database_id = {
        dg.database_id: getattr(dg, "role", None)
        for dg in kept_data_guard_raw
        if getattr(dg, "database_id", None)
    }

    # -- Site-to-Site VPN: tunnel counts are raw facts (no redundancy verdict --
    # decisions.minimum(Up)?VpnTunnelCount is a policy threshold for the Custom Test) --
    kept_connections_raw, excluded_connections_raw = split_by_lifecycle(vpn.ip_sec_connections)

    def _tunnel_counts(connection_id: str) -> tuple[int, int]:
        kept_tunnels, _ = split_by_lifecycle(vpn.tunnels_by_connection_id.get(connection_id, []))
        up_count = sum(1 for t in kept_tunnels if getattr(t, "status", None) == "UP")
        return len(kept_tunnels), up_count

    # Identity uses OCI's DELETED/DELETING vocabulary, not split_by_lifecycle's
    # TERMINATED/TERMINATING default -- override explicitly, or its "keep if
    # unknown" rule silently keeps deleted users/policies.
    _IDENTITY_DELETED_STATES = frozenset({"DELETED", "DELETING"})
    kept_users, excluded_users = split_by_lifecycle(
        identity.users, exclude_states=_IDENTITY_DELETED_STATES
    )
    kept_policies, excluded_policies = split_by_lifecycle(
        identity.policies, exclude_states=_IDENTITY_DELETED_STATES
    )
    # An api_key is excluded either because its own user was excluded above, or because
    # the key itself carries a deleted-state lifecycle while its user is still active --
    # both must be tracked so a revoked/rotated key's stale record still gets cleaned up.
    kept_api_keys = [
        key
        for user in kept_users
        for key in identity.api_keys_by_user_id.get(user.id, [])
        if getattr(key, "lifecycle_state", None) not in _IDENTITY_DELETED_STATES
    ]
    excluded_api_keys = [
        key
        for user in kept_users
        for key in identity.api_keys_by_user_id.get(user.id, [])
        if getattr(key, "lifecycle_state", None) in _IDENTITY_DELETED_STATES
    ] + [
        key
        for user in excluded_users
        for key in identity.api_keys_by_user_id.get(user.id, [])
    ]

    # Monitoring alarms: same DELETED/DELETING convention as identity above;
    # AlarmSummary exposes no LIFECYCLE_STATE_* constants to check the assumption
    # against.
    kept_alarms, excluded_alarms = split_by_lifecycle(
        monitoring.alarms, exclude_states=_IDENTITY_DELETED_STATES
    )

    # LoadBalancer's lifecycle enum (DELETED/DELETING/ACTIVE/CREATING/FAILED, per
    # oci.load_balancer.models.LoadBalancer's own LIFECYCLE_STATE_* constants) uses
    # the same DELETED/DELETING exclusion convention as identity/alarms.
    kept_load_balancers, excluded_load_balancers = split_by_lifecycle(
        load_balancer.load_balancers, exclude_states=_IDENTITY_DELETED_STATES
    )

    # Same DELETED/DELETING convention as above; WebAppFirewallLoadBalancerSummary
    # exposes no LIFECYCLE_STATE_* constants to check it against (same caveat as
    # monitoring alarms).
    kept_wafs, excluded_wafs = split_by_lifecycle(
        waf.web_app_firewalls, exclude_states=_IDENTITY_DELETED_STATES
    )

    # Key's lifecycle enum (per oci.key_management.models.Key's own LIFECYCLE_STATE_*
    # constants) includes ENABLED/DISABLED/DELETED/DELETING -- DISABLED keys are
    # still reportable evidence; only DELETED/DELETING are excluded.
    kept_keys, excluded_keys = split_by_lifecycle(
        kms_vault.keys, exclude_states=_IDENTITY_DELETED_STATES
    )

    timestamp = normalize.normalize_timestamp(completed_at)
    backend_set_health_records = [
        _flatten_backend_set_health(lb, backend_set_name, health, timestamp=timestamp)
        for lb in kept_load_balancers
        for backend_set_name in (lb.backend_sets or {})
        for health in [load_balancer.backend_set_health_by_key.get((lb.id, backend_set_name))]
        if health is not None
    ]
    tenancy_id = discovery.tenancy.id if discovery.tenancy is not None else None
    records = sorted(
        [
            _flatten_instance(i, ingress_by_instance_id[i.id], timestamp=timestamp)
            for i in instances
        ]
        + [
            _flatten_boot_volume(
                v, attached_instance_ids=tuple(sorted(set(instance_ids_by_boot_volume_id.get(v.id, [])))),
                timestamp=timestamp,
            )
            for v in kept_boot_volumes_raw
        ]
        + [
            _flatten_block_volume(
                v, attached_instance_ids=tuple(sorted(set(instance_ids_by_block_volume_id.get(v.id, [])))),
                timestamp=timestamp,
            )
            for v in kept_block_volumes_raw
        ]
        + [_flatten_db_system(s, timestamp=timestamp) for s in kept_db_systems_raw]
        + [
            _flatten_database(
                d, data_guard_role=data_guard_role_by_database_id.get(d.id), timestamp=timestamp
            )
            for d in kept_databases_raw
        ]
        + [
            _flatten_autonomous_database(a, timestamp=timestamp)
            for a in autonomous_databases
        ]
        + [
            _flatten_ipsec_connection(
                c, tunnel_count=(counts := _tunnel_counts(c.id))[0], up_tunnel_count=counts[1],
                timestamp=timestamp,
            )
            for c in kept_connections_raw
        ]
        + [_flatten_iam_user(u, timestamp=timestamp) for u in kept_users]
        + [_flatten_api_key(k, timestamp=timestamp) for k in kept_api_keys]
        + [_flatten_iam_policy(p, timestamp=timestamp) for p in kept_policies]
        + [_flatten_bucket(b, timestamp=timestamp) for b in object_storage.buckets]
        + (
            [
                _flatten_cloud_guard_configuration(
                    cloud_guard.configuration, tenancy_id=tenancy_id, timestamp=timestamp
                )
            ]
            if cloud_guard.configuration is not None
            else []
        )
        + [_flatten_alarm(a, timestamp=timestamp) for a in kept_alarms]
        + [_flatten_load_balancer(lb, timestamp=timestamp) for lb in kept_load_balancers]
        + backend_set_health_records
        + [_flatten_waf(w, timestamp=timestamp) for w in kept_wafs]
        + [_flatten_kms_key(k, timestamp=timestamp) for k in kept_keys],
        key=lambda r: r["id"],
    )

    return FlatRecordsResult(
        records=records,
        domain_complete={
            "compute": compute.complete,
            "blockStorage": storage.complete,
            "networking": networking.complete,
            "baseDatabase": database_base.complete,
            "autonomousDatabase": autonomous_database.complete,
            "vpn": vpn.complete,
            "identity": identity.complete,
            "objectStorage": object_storage.complete,
            "cloudGuard": cloud_guard.complete,
            "monitoring": monitoring.complete,
            "loadBalancer": load_balancer.complete,
            "waf": waf.complete,
            "kmsVault": kms_vault.complete,
        },
        discovery_complete=discovery.complete,
        excluded_counts={
            "instance": len(excluded_instances_raw),
            "bootVolume": len(excluded_boot_volumes_raw),
            "blockVolume": len(excluded_block_volumes_raw),
            "dbSystem": len(excluded_db_systems_raw),
            "database": len(excluded_databases_raw),
            "autonomousDatabase": len(excluded_adb_raw),
            "ipsecConnection": len(excluded_connections_raw),
            "iamUser": len(excluded_users),
            "iamPolicy": len(excluded_policies),
            "monitoringAlarm": len(excluded_alarms),
            "loadBalancer": len(excluded_load_balancers),
            "waf": len(excluded_wafs),
            "kmsKey": len(excluded_keys),
        },
        excluded_ids={
            "instance": [i.id for i in excluded_instances_raw],
            "boot_volume": [v.id for v in excluded_boot_volumes_raw],
            "block_volume": [v.id for v in excluded_block_volumes_raw],
            "db_system": [s.id for s in excluded_db_systems_raw],
            "database": [d.id for d in excluded_databases_raw],
            "autonomous_database": [a.id for a in excluded_adb_raw],
            "ipsec_connection": [c.id for c in excluded_connections_raw],
            "iam_user": [u.id for u in excluded_users],
            "api_key": [f"{k.user_id}/{k.fingerprint}" for k in excluded_api_keys],
            "iam_policy": [p.id for p in excluded_policies],
            "monitoring_alarm": [a.id for a in excluded_alarms],
            "load_balancer": [lb.id for lb in excluded_load_balancers],
            "load_balancer_backend_set": [
                f"{lb.id}:{name}" for lb in excluded_load_balancers for name in (lb.backend_sets or {})
            ],
            "waf": [w.id for w in excluded_wafs],
            "kms_key": [k.id for k in excluded_keys],
        },
        unresolved_relationship_count=len(unresolved_storage) + len(unresolved_vnic),
    )
