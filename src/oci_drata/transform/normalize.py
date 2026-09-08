"""Normalizes raw OCI SDK objects into allowlisted source-fact models.
Cross-resource joins (Windows classification, network exposure, ID-list
relationships, VPN redundancy) happen in relationships/exposure/vpn_posture,
which run after this module and consume its output."""

from __future__ import annotations

import datetime
from typing import Any, Mapping

from oci_drata.models import (
    CommonResource,
    DatabaseResource,
    Instance,
    IpsecConnection,
    IpsecTunnel,
    Vnic,
    Volume,
)


def normalize_timestamp(value: datetime.datetime | str | None) -> str | None:
    """Normalizes to UTC RFC3339, second precision, Z-suffixed. Accepts a
    bare string defensively and re-normalizes it rather than trusting it
    verbatim."""

    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError(f"naive datetime cannot be normalized to UTC RFC3339: {value!r}")
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        # getattr avoids AttributeError. Callers override via compartment_id param.
        "compartment_id": getattr(raw, "compartment_id", None),
        "display_name": getattr(raw, "display_name", None),
        "lifecycle_state": getattr(raw, "lifecycle_state", None),
        "time_created": normalize_timestamp(getattr(raw, "time_created", None)),
        "defined_tags": _flatten_defined_tags(getattr(raw, "defined_tags", None)),
        "freeform_tags": dict(getattr(raw, "freeform_tags", None) or {}),
    }


def normalize_common(raw: Any, *, source_type: str, compartment_id: str | None = None) -> CommonResource:
    """Normalizes resource kinds needing no fields beyond CommonResource
    (compartments, images, IPs, VCNs, subnets, route tables, gateways,
    security lists, NSGs, attachments, CPEs, DRGs). compartment_id overrides
    raw.compartment_id when the object doesn't carry its own (e.g.
    DataGuardAssociation)."""

    fields = _common_fields(raw, source_type=source_type)
    if compartment_id is not None:
        fields["compartment_id"] = compartment_id
    return CommonResource(**fields)


def normalize_instance(raw: Any) -> Instance:
    """Copies only image_id. osClassification, exposure fields, vnicIds,
    volumeIds filled in later by transform.relationships/exposure."""

    return Instance(
        **_common_fields(raw, source_type="compute_instance"),
        image_id=getattr(raw, "image_id", None),
    )


def normalize_vnic(raw: Any) -> Vnic:
    """subnet_id required, raises if absent. private/public addresses filled
    in later by transform.relationships (VNIC's own fields carry only the
    primary address)."""

    subnet_id = getattr(raw, "subnet_id", None)
    if not subnet_id:
        raise ValueError(f"VNIC {raw.id} has no subnet_id; schema requires one")
    return Vnic(
        **_common_fields(raw, source_type="vnic"),
        instance_id=None,  # filled in by relationships via the attachment join
        subnet_id=subnet_id,
        nsg_ids=tuple(getattr(raw, "nsg_ids", None) or ()),
    )


def normalize_volume(raw: Any, *, source_type: str) -> Volume:
    kms_key_id = getattr(raw, "kms_key_id", None)
    return Volume(
        **_common_fields(raw, source_type=source_type),
        kms_key_id=kms_key_id,
        customer_managed_key_present=(kms_key_id is not None) if kms_key_id is not None else None,
    )


def normalize_ipsec_connection(raw: Any) -> IpsecConnection:
    return IpsecConnection(
        **_common_fields(raw, source_type="ipsec_connection"),
        cpe_id=raw.cpe_id or "",
        drg_id=raw.drg_id or "",
        # tunnel_ids/tunnel_count/up_tunnel_count/redundancy_status filled in by transform.vpn_posture.
    )


def normalize_ipsec_tunnel(
    raw: Any, *, ipsec_connection_id: str, fallback_compartment_id: str
) -> IpsecTunnel:
    # compartment_id not guaranteed populated on tunnel; fall back to parent connection's.
    fields = _common_fields(raw, source_type="ipsec_tunnel")
    if not fields["compartment_id"]:
        fields["compartment_id"] = fallback_compartment_id
    return IpsecTunnel(
        **fields,
        ipsec_connection_id=ipsec_connection_id,
        status=getattr(raw, "status", None),
        routing=getattr(raw, "routing", None),
        ike_version=getattr(raw, "ike_version", None),
        bgp_state=_bgp_state(raw),
    )


def _bgp_state(raw: Any) -> str | None:
    bgp_session_info = getattr(raw, "bgp_session_info", None)
    if bgp_session_info is None:
        return None
    return getattr(bgp_session_info, "bgp_state", None)


def normalize_db_backup_status(raw_database: Any) -> str:
    """Returns enabled/disabled from DbBackupConfig.auto_backup_enabled;
    unknown only if config absent."""

    backup_config = getattr(raw_database, "db_backup_config", None)
    if backup_config is None:
        return "unknown"
    enabled = getattr(backup_config, "auto_backup_enabled", None)
    if enabled is None:
        return "unknown"
    return "enabled" if enabled else "disabled"


def normalize_autonomous_backup_status(raw_adb: Any) -> str:
    """Autonomous DB has no explicit enable/disable flag; derives
    enabled/disabled from backup_retention_period_in_days (>0 = enabled,
    0 = disabled), unknown if absent."""

    retention_days = getattr(raw_adb, "backup_retention_period_in_days", None)
    if retention_days is None:
        return "unknown"
    return "enabled" if retention_days > 0 else "disabled"


def normalize_database_resource(
    raw: Any,
    *,
    database_type: str,
    source_type: str,
    backup_status: str = "not_applicable",
    public_endpoint: bool | None = None,
    compartment_id: str | None = None,
) -> DatabaseResource:
    fields = _common_fields(raw, source_type=source_type)
    if compartment_id is not None:
        fields["compartment_id"] = compartment_id
    return DatabaseResource(
        **fields,
        database_type=database_type,
        public_endpoint=public_endpoint,
        backup_status=backup_status,
        kms_key_id=getattr(raw, "kms_key_id", None),
        # related_resource_ids filled in by transform.relationships.
    )
