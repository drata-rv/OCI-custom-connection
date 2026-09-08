"""Raw OCI SDK model objects -> allowlisted source-fact models (spec 7.1
step 2). Copies only fields the schema knows about, plus the handful of
single-object derivations that need no cross-resource join (e.g. "does this
volume reference a KMS key" from its own kms_key_id field). Anything that
needs another resource's data -- Windows classification, network exposure,
ID-list relationships, VPN redundancy -- happens in
:mod:`oci_drata.transform.relationships`,
:mod:`oci_drata.transform.exposure`, and
:mod:`oci_drata.transform.vpn_posture`, all of which run after this module
and consume its output.
"""

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
    """UTC RFC3339, second precision, always ``Z``-suffixed (spec: "Normalize
    timestamps to UTC RFC3339"). OCI SDK response fields deserialize to
    timezone-aware ``datetime`` objects; a bare string is accepted
    defensively and re-normalized rather than trusted verbatim."""

    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError(f"naive datetime cannot be normalized to UTC RFC3339: {value!r}")
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _flatten_defined_tags(defined_tags: Mapping[str, Any] | None) -> dict[str, Any]:
    """OCI defined_tags nests one level (namespace -> {key: value}); the
    schema's tags definition only allows flat scalar values. Flattened to
    "namespace.key" so real tag data survives instead of being dropped."""

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
        # Not every OCI model declares compartment_id (e.g.
        # DataGuardAssociation has none at all -- an AttributeError, not a
        # None, if accessed directly). Callers that know it can be missing
        # pass an explicit compartment_id override.
        "compartment_id": getattr(raw, "compartment_id", None),
        "display_name": getattr(raw, "display_name", None),
        "lifecycle_state": getattr(raw, "lifecycle_state", None),
        "time_created": normalize_timestamp(getattr(raw, "time_created", None)),
        "defined_tags": _flatten_defined_tags(getattr(raw, "defined_tags", None)),
        "freeform_tags": dict(getattr(raw, "freeform_tags", None) or {}),
    }


def normalize_common(raw: Any, *, source_type: str, compartment_id: str | None = None) -> CommonResource:
    """For resource kinds that need no extra fields beyond CommonResource:
    compartments, images, private IPs, public IPs, VCNs, subnets, route
    tables, internet gateways, security lists, NSGs, boot/volume
    attachments, CPEs, DRGs, DRG attachments.

    ``compartment_id`` overrides ``raw.compartment_id`` for the rare object
    that doesn't carry its own (e.g. a DataGuardAssociation, backfilled by
    the caller from its parent database).
    """

    fields = _common_fields(raw, source_type=source_type)
    if compartment_id is not None:
        fields["compartment_id"] = compartment_id
    return CommonResource(**fields)


def normalize_instance(raw: Any) -> Instance:
    """imageId is the only structural field copied here -- osClassification,
    hasPublicAddress, effectiveIngressExposure, exposedAdministrativePorts,
    vnicIds, and volumeIds are all cross-resource joins/derivations filled
    in later by transform.relationships and transform.exposure."""

    return Instance(
        **_common_fields(raw, source_type="compute_instance"),
        image_id=getattr(raw, "image_id", None),
    )


def normalize_vnic(raw: Any) -> Vnic:
    """instanceId/nsgIds are direct copies; subnetId is required by the
    schema so an absent value fails loudly rather than silently defaulting.
    privateAddresses/publicAddresses are cross-resource joins (a VNIC's
    private_ip/public_ip fields only carry its *primary* address; secondary
    private IPs and any public IP come from the separate list_private_ips/
    get_public_ip_by_private_ip_id collections) -- filled in by
    transform.relationships, not here."""

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
        # tunnel_ids/tunnel_count/up_tunnel_count/redundancy_status are
        # filled in by transform.vpn_posture, which has the tunnel list this
        # module never sees.
    )


def normalize_ipsec_tunnel(
    raw: Any, *, ipsec_connection_id: str, fallback_compartment_id: str
) -> IpsecTunnel:
    # IPSecConnectionTunnel declares its own compartment_id, but it's not
    # guaranteed populated on every SDK/API revision -- fall back to the
    # parent connection's compartment, which a tunnel always belongs to.
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
    """Base Database Service: DbBackupConfig.auto_backup_enabled is a direct
    boolean -- "enabled"/"disabled" copy, "unknown" only when the nested
    config itself is absent."""

    backup_config = getattr(raw_database, "db_backup_config", None)
    if backup_config is None:
        return "unknown"
    enabled = getattr(backup_config, "auto_backup_enabled", None)
    if enabled is None:
        return "unknown"
    return "enabled" if enabled else "disabled"


def normalize_autonomous_backup_status(raw_adb: Any) -> str:
    """Autonomous Database has no explicit enable/disable flag (automatic
    backups are the default for the service) -- retention period is the
    closest direct signal: >0 means backups are being retained, 0 means
    retention is off, absent means we can't tell."""

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
