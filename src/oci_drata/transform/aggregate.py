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
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.identity import IdentityCollectionResult
from oci_drata.collection.kms_vault import KmsVaultCollectionResult
from oci_drata.collection.load_balancer import LoadBalancerCollectionResult
from oci_drata.collection.monitoring import MonitoringCollectionResult
from oci_drata.collection.networking import NetworkingCollectionResult
from oci_drata.collection.object_storage import ObjectStorageCollectionResult
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
    "autonomous_database": ("autonomousDatabase",),
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
    networking: NetworkingCollectionResult,
    autonomous_database: AutonomousDatabaseCollectionResult,
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
            _flatten_autonomous_database(a, timestamp=timestamp)
            for a in autonomous_databases
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
            "networking": networking.complete,
            "autonomousDatabase": autonomous_database.complete,
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
            "autonomousDatabase": len(excluded_adb_raw),
            "iamUser": len(excluded_users),
            "iamPolicy": len(excluded_policies),
            "monitoringAlarm": len(excluded_alarms),
            "loadBalancer": len(excluded_load_balancers),
            "waf": len(excluded_wafs),
            "kmsKey": len(excluded_keys),
        },
        excluded_ids={
            "instance": [i.id for i in excluded_instances_raw],
            "autonomous_database": [a.id for a in excluded_adb_raw],
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
