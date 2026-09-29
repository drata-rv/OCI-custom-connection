"""Normalizes raw OCI SDK objects into allowlisted source-fact models.
Cross-resource joins (Windows classification, network exposure, ID-list
relationships, VPN redundancy) run afterward in relationships/exposure/vpn_posture."""

from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any

from oci_drata.models import DatabaseResource, Instance, Vnic


def normalize_timestamp(value: datetime.datetime | str | None) -> str | None:
    """Normalizes to UTC RFC3339, second precision, Z-suffixed. Re-normalizes
    string input rather than trusting it verbatim."""

    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError(f"naive datetime cannot be normalized to UTC RFC3339: {value!r}")
    return value.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _flatten_defined_tags(defined_tags: Mapping[str, Any] | None) -> dict[str, Any]:
    """Flattens OCI's nested namespace->{key: value} defined_tags to
    "namespace.key" (schema only allows flat scalar values)."""

    if not defined_tags:
        return {}
    flat: dict[str, Any] = {}
    for namespace, entries in defined_tags.items():
        if isinstance(entries, Mapping):
            for key, value in entries.items():
                flat[f"{namespace}.{key}"] = value
        else:
            flat[namespace] = entries
    return flat


def _region(raw: Any) -> str:
    region = getattr(raw, "region", None)
    if not region:
        raise ValueError(f"raw object {raw!r} was not region-stamped before normalization")
    return region


def _common_fields(raw: Any, *, source_type: str) -> dict[str, Any]:
    return {
        "id": raw.id,
        "source_type": source_type,
        "region": _region(raw),
        # compartment_id may be absent entirely (e.g. DataGuardAssociation);
        # callers override via compartment_id param.
        "compartment_id": getattr(raw, "compartment_id", None),
        "display_name": getattr(raw, "display_name", None),
        "lifecycle_state": getattr(raw, "lifecycle_state", None),
        "time_created": normalize_timestamp(getattr(raw, "time_created", None)),
        "defined_tags": _flatten_defined_tags(getattr(raw, "defined_tags", None)),
        "freeform_tags": dict(getattr(raw, "freeform_tags", None) or {}),
    }


def normalize_instance(raw: Any) -> Instance:
    """Copies only image_id. osClassification, exposure fields, vnicIds,
    volumeIds filled in later by transform.relationships/exposure."""

    return Instance(
        **_common_fields(raw, source_type="compute_instance"),
        image_id=getattr(raw, "image_id", None),
    )


def normalize_vnic(raw: Any) -> Vnic:
    """subnet_id required, raises if absent. private/public addresses filled
    in later by transform.relationships (VNIC carries only primary address)."""

    subnet_id = getattr(raw, "subnet_id", None)
    if not subnet_id:
        raise ValueError(f"VNIC {raw.id} has no subnet_id; schema requires one")
    return Vnic(
        **_common_fields(raw, source_type="vnic"),
        instance_id=None,  # filled in by relationships via the attachment join
        subnet_id=subnet_id,
        nsg_ids=tuple(getattr(raw, "nsg_ids", None) or ()),
    )


def normalize_autonomous_database_posture(raw_adb: Any) -> dict[str, Any]:
    """Derives presence facts (endpoint present, access control configured, schedule
    configured) rather than a compressed status, since ADB's raw fields (e.g.
    public_endpoint as a hostname string) aren't clean booleans. None means confirmed
    absence, so these presence facts are always a definite bool, never unknown."""

    public_endpoint_hostname = getattr(raw_adb, "public_endpoint", None) or None
    private_endpoint = getattr(raw_adb, "private_endpoint", None)
    whitelisted_ips = getattr(raw_adb, "whitelisted_ips", None) or ()
    long_term_backup_schedule = getattr(raw_adb, "long_term_backup_schedule", None)

    return {
        "public_endpoint_hostname": public_endpoint_hostname,
        "private_endpoint_configured": bool(private_endpoint),
        "public_endpoint_present": bool(public_endpoint_hostname),
        "access_control_enabled": bool(whitelisted_ips),
        "allowed_source_count": len(whitelisted_ips),
        "mtls_required": getattr(raw_adb, "is_mtls_connection_required", None),
        "network_security_group_ids": tuple(getattr(raw_adb, "nsg_ids", None) or ()),
        "backup_retention_days": getattr(raw_adb, "backup_retention_period_in_days", None),
        "backup_retention_locked": getattr(raw_adb, "is_backup_retention_locked", None),
        "long_term_backup_schedule_configured": long_term_backup_schedule is not None,
    }


def normalize_database_resource(
    raw: Any,
    *,
    database_type: str,
    source_type: str,
    backup_status: str = "not_applicable",
    compartment_id: str | None = None,
    detail_fields: Mapping[str, Any] | None = None,
) -> DatabaseResource:
    fields = _common_fields(raw, source_type=source_type)
    if compartment_id is not None:
        fields["compartment_id"] = compartment_id
    return DatabaseResource(
        **fields,
        database_type=database_type,
        backup_status=backup_status,
        kms_key_id=getattr(raw, "kms_key_id", None),
        # related_resource_ids filled in by transform.relationships.
        **(detail_fields or {}),
    )
