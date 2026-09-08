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
    InternetGateway,
    IpsecConnection,
    IpsecTunnel,
    NetworkSecurityGroup,
    PortRange,
    RouteRule,
    RouteTable,
    SecurityList,
    SecurityRule,
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


def _port_range(options: Any) -> PortRange | None:
    port_range = getattr(options, "destination_port_range", None)
    if port_range is None:
        return None
    return PortRange(min=getattr(port_range, "min", None), max=getattr(port_range, "max", None))


def normalize_route_rule(raw: Any) -> RouteRule:
    return RouteRule(
        destination=getattr(raw, "destination", None),
        destination_type=getattr(raw, "destination_type", None),
        network_entity_id=getattr(raw, "network_entity_id", None),
        description=getattr(raw, "description", None),
    )


def normalize_route_table(raw: Any) -> RouteTable:
    return RouteTable(
        **_common_fields(raw, source_type="route_table"),
        route_rules=tuple(normalize_route_rule(r) for r in getattr(raw, "route_rules", None) or ()),
    )


def _security_rule(raw: Any, *, direction: str) -> SecurityRule:
    return SecurityRule(
        direction=direction,
        protocol=getattr(raw, "protocol", None),
        source=getattr(raw, "source", None),
        source_type=getattr(raw, "source_type", None),
        destination=getattr(raw, "destination", None),
        destination_type=getattr(raw, "destination_type", None),
        is_stateless=getattr(raw, "is_stateless", None),
        tcp_port_range=_port_range(getattr(raw, "tcp_options", None)),
        udp_port_range=_port_range(getattr(raw, "udp_options", None)),
        description=getattr(raw, "description", None),
    )


def normalize_security_list(raw: Any) -> SecurityList:
    return SecurityList(
        **_common_fields(raw, source_type="security_list"),
        ingress_rules=tuple(
            _security_rule(r, direction="ingress")
            for r in getattr(raw, "ingress_security_rules", None) or ()
        ),
        egress_rules=tuple(
            _security_rule(r, direction="egress")
            for r in getattr(raw, "egress_security_rules", None) or ()
        ),
    )


def normalize_network_security_group(raw: Any, *, security_rules: list[Any]) -> NetworkSecurityGroup:
    return NetworkSecurityGroup(
        **_common_fields(raw, source_type="network_security_group"),
        security_rules=tuple(
            _security_rule(r, direction=(getattr(r, "direction", None) or "unknown").lower())
            for r in security_rules
        ),
    )


def normalize_internet_gateway(raw: Any) -> InternetGateway:
    return InternetGateway(
        **_common_fields(raw, source_type="internet_gateway"),
        is_enabled=getattr(raw, "is_enabled", None),
        vcn_id=getattr(raw, "vcn_id", None),
    )


def normalize_volume(raw: Any, *, source_type: str) -> Volume:
    """list_volumes/list_boot_volumes return the full Volume/BootVolume type (there is no
    separate lighter-weight VolumeSummary in the OCI SDK) -- kms_key_id is returned
    authoritatively, so null means "no customer-managed key", a known fact, not an
    unresolvable unknown. customer_managed_key_present is therefore always a definite
    bool, never None -- P1-4: a prior version treated absent-key as unknown, conflating it
    with a genuinely unavailable field on a summary-shaped response, which this isn't."""

    kms_key_id = getattr(raw, "kms_key_id", None)
    return Volume(
        **_common_fields(raw, source_type=source_type),
        kms_key_id=kms_key_id,
        customer_managed_key_present=kms_key_id is not None,
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


def normalize_autonomous_database_posture(raw_adb: Any) -> dict[str, Any]:
    """Autonomous Database has no auto_backup_enabled-style boolean (unlike Base DB's
    DbBackupConfig) and public_endpoint is a hostname string, not a boolean -- deriving a
    single compressed enabled/disabled or public/private verdict from either would guess.
    Retains raw fields and derives only presence facts (public/private endpoint present,
    access control configured, long-term schedule configured) rather than a status.

    AutonomousDatabaseSummary always declares these attributes; None means Oracle returned
    no value for an existing resource (e.g. no public endpoint), not that the field is
    unreachable -- so the presence facts below resolve to a definite bool, never unknown.
    Raw non-presence fields (mtls_required, backup retention) pass through None as-is."""

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


def normalize_db_system_detail(raw_db_system: Any) -> dict[str, Any]:
    """Raw base_db_system fields the review calls out as lost by generic normalization:
    shape, version, OS patch level, node count, redundancy, subnet, NSGs."""

    return {
        "shape": getattr(raw_db_system, "shape", None),
        "version": getattr(raw_db_system, "version", None),
        "os_version": getattr(raw_db_system, "os_version", None),
        "node_count": getattr(raw_db_system, "node_count", None),
        "disk_redundancy": getattr(raw_db_system, "disk_redundancy", None),
        "subnet_id": getattr(raw_db_system, "subnet_id", None),
        "network_security_group_ids": tuple(getattr(raw_db_system, "nsg_ids", None) or ()),
    }


def normalize_database_detail(raw_database: Any) -> dict[str, Any]:
    """Raw base_database fields the review calls out as lost: backup config detail beyond
    the compressed enabled/disabled status, last/failed backup timestamps, patch version,
    management config."""

    backup_config = getattr(raw_database, "db_backup_config", None)
    management_config = getattr(raw_database, "database_management_config", None)
    return {
        "last_backup_timestamp": normalize_timestamp(getattr(raw_database, "last_backup_timestamp", None)),
        "last_failed_backup_timestamp": normalize_timestamp(
            getattr(raw_database, "last_failed_backup_timestamp", None)
        ),
        "patch_version": getattr(raw_database, "patch_version", None),
        "recovery_window_days": (
            getattr(backup_config, "recovery_window_in_days", None) if backup_config else None
        ),
        "database_management_status": (
            getattr(management_config, "database_management_status", None) if management_config else None
        ),
    }


def normalize_data_guard_detail(raw_dg: Any) -> dict[str, Any]:
    """Raw data_guard fields the review calls out as lost: role, peer role, protection
    mode, transport type -- previously only the bare bidirectional link survived."""

    return {
        "data_guard_role": getattr(raw_dg, "role", None),
        "data_guard_peer_role": getattr(raw_dg, "peer_role", None),
        "data_guard_protection_mode": getattr(raw_dg, "protection_mode", None),
        "data_guard_transport_type": getattr(raw_dg, "transport_type", None),
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
