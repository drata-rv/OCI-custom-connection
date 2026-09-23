"""Builds one aggregate record: normalize -> relationships -> exposure/vpn_posture ->
findings, then metrics and serialization. Resource/finding/warning arrays sort by
id/assertionId for deterministic output.

Does not decide upload eligibility; see :mod:`oci_drata.validation.completeness`.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
from collections.abc import Sequence
from typing import Any

from oci_drata.collection.cloud_guard import CloudGuardCollectionResult
from oci_drata.collection.compute import ComputeCollectionResult
from oci_drata.collection.database_autonomous import AutonomousDatabaseCollectionResult
from oci_drata.collection.database_base import DatabaseBaseCollectionResult
from oci_drata.collection.discovery import DiscoveryResult
from oci_drata.collection.exadata_detection import ExadataDetectionResult
from oci_drata.collection.identity import IdentityCollectionResult
from oci_drata.collection.kms_vault import KmsVaultCollectionResult
from oci_drata.collection.load_balancer import LoadBalancerCollectionResult
from oci_drata.collection.monitoring import MonitoringCollectionResult
from oci_drata.collection.networking import NetworkingCollectionResult
from oci_drata.collection.object_storage import ObjectStorageCollectionResult
from oci_drata.collection.storage import StorageCollectionResult
from oci_drata.collection.vpn import VpnCollectionResult
from oci_drata.collection.waf import WafCollectionResult
from oci_drata.config import AppConfig, DecisionsConfig
from oci_drata.models import (
    METRIC_KEYS,
    RESOURCE_COLLECTION_KEYS,
    CommonResource,
    DatabaseResource,
    Finding,
    Instance,
    Message,
    OperationRecord,
    UnresolvedRelationship,
)
from oci_drata.pagination import OperationResult
from oci_drata.transform import findings as findings_mod
from oci_drata.transform import normalize, relationships
from oci_drata.transform.exposure import (
    ExposureConfig,
    PublicIngressFacts,
    derive_instance_exposure,
    derive_public_ingress_facts,
)
from oci_drata.transform.lifecycle import (
    exclude_lifecycle_cascade,
    exclude_referencing,
    split_by_lifecycle,
)
from oci_drata.transform.vpn_posture import derive_vpn_posture

DERIVATION_VERSION = "1.3.0"
SCHEMA_VERSION = "1.0.0"
COLLECTOR_VERSION = "0.1.0"


def derive_record_id(tenancy_ocid: str, deployment_name: str) -> str:
    """oci-snapshot- + first 24 hex chars of SHA-256(tenancy_ocid + deployment_name).
    build_snapshot() always uses the configured record id directly, never recomputes it here."""

    digest = hashlib.sha256(f"{tenancy_ocid}{deployment_name}".encode()).hexdigest()
    return f"oci-snapshot-{digest[:24]}"


@dataclasses.dataclass(frozen=True)
class AggregateResult:
    record: dict[str, Any]
    unresolved_relationship_count: int
    exadata_detected: bool
    domain_complete: dict[str, bool]
    discovery_complete: bool


def _sorted_dicts(resources: Sequence[CommonResource]) -> list[dict[str, Any]]:
    return [r.to_dict() for r in sorted(resources, key=lambda r: r.id)]


def build_snapshot(
    app_config: AppConfig,
    *,
    discovery: DiscoveryResult,
    compute: ComputeCollectionResult,
    storage: StorageCollectionResult,
    networking: NetworkingCollectionResult,
    database_base: DatabaseBaseCollectionResult,
    autonomous_database: AutonomousDatabaseCollectionResult,
    exadata: ExadataDetectionResult,
    vpn: VpnCollectionResult,
    started_at: datetime.datetime,
    completed_at: datetime.datetime,
) -> AggregateResult:
    all_operations: list[OperationResult] = [
        *discovery.operations,
        *compute.operations,
        *storage.operations,
        *networking.operations,
        *database_base.operations,
        *autonomous_database.operations,
        *exadata.operations,
        *vpn.operations,
    ]
    all_unresolved: list[UnresolvedRelationship] = []

    # -- Compute + storage + networking -----------------------------------
    compartments = [
        normalize.normalize_common(c, source_type="compartment")
        for c in discovery.all_compartments
        if c.id in discovery.approved_compartment_ids
    ]
    images = [
        normalize.normalize_common(img, source_type="image") for img in compute.images.values()
    ]

    kept_instances_raw, excluded_instances_raw = split_by_lifecycle(compute.instances)
    excluded_instance_ids = {i.id for i in excluded_instances_raw}
    vnic_attachments = exclude_referencing(
        compute.vnic_attachments, excluded_ids=excluded_instance_ids, id_field="instance_id"
    )
    boot_volume_attachments = exclude_referencing(
        storage.boot_volume_attachments, excluded_ids=excluded_instance_ids, id_field="instance_id"
    )
    volume_attachments = exclude_referencing(
        storage.volume_attachments, excluded_ids=excluded_instance_ids, id_field="instance_id"
    )

    instances = [normalize.normalize_instance(i) for i in kept_instances_raw]
    instances = relationships.classify_windows(instances, compute.images)
    instances, unresolved = relationships.resolve_instance_network_and_storage(
        instances,
        vnic_attachments=vnic_attachments,
        boot_volume_attachments=boot_volume_attachments,
        volume_attachments=volume_attachments,
    )
    all_unresolved.extend(unresolved)

    vnics = [normalize.normalize_vnic(v) for v in compute.vnics.values()]
    vnics, unresolved = relationships.resolve_vnic_addresses(
        vnics,
        vnic_attachments=vnic_attachments,
        private_ips=compute.private_ips,
        public_ips_by_private_ip_id=compute.public_ips_by_private_ip_id,
    )
    all_unresolved.extend(unresolved)

    kept_boot_volumes_raw, excluded_boot_volumes_raw = split_by_lifecycle(storage.boot_volumes)
    kept_block_volumes_raw, excluded_block_volumes_raw = split_by_lifecycle(storage.block_volumes)

    boot_volumes = [normalize.normalize_volume(v, source_type="boot_volume") for v in kept_boot_volumes_raw]
    boot_volumes = relationships.resolve_volume_attachments(
        boot_volumes, attachments=boot_volume_attachments, attachment_volume_id_field="boot_volume_id"
    )
    block_volumes = [normalize.normalize_volume(v, source_type="block_volume") for v in kept_block_volumes_raw]
    block_volumes = relationships.resolve_volume_attachments(
        block_volumes, attachments=volume_attachments, attachment_volume_id_field="volume_id"
    )

    private_ips = [normalize.normalize_common(p, source_type="private_ip") for p in compute.private_ips]
    public_ips = [
        normalize.normalize_common(p, source_type="public_ip")
        for p in compute.public_ips_by_private_ip_id.values()
    ]
    vcns = [normalize.normalize_common(v, source_type="vcn") for v in networking.vcns]
    subnets = [normalize.normalize_common(s, source_type="subnet") for s in networking.subnets]
    route_tables = [normalize.normalize_route_table(r) for r in networking.route_tables]
    internet_gateways = [normalize.normalize_internet_gateway(g) for g in networking.internet_gateways]
    security_lists = [normalize.normalize_security_list(s) for s in networking.security_lists]
    network_security_groups = [
        normalize.normalize_network_security_group(
            n, security_rules=networking.nsg_security_rules_by_nsg_id.get(n.id, [])
        )
        for n in networking.network_security_groups
    ]
    boot_volume_attachment_resources = [
        normalize.normalize_common(a, source_type="boot_volume_attachment")
        for a in boot_volume_attachments  # already excludes attachments to lifecycle-excluded instances
    ]
    volume_attachment_resources = [
        normalize.normalize_common(a, source_type="volume_attachment")
        for a in volume_attachments  # already excludes attachments to lifecycle-excluded instances
    ]

    exposure_config = ExposureConfig(
        administrative_ports=app_config.decisions.administrative_ports,
        public_source_cidrs=app_config.decisions.public_source_cidrs,
    )
    instances = derive_instance_exposure(
        instances,
        vnics_by_id={v.id: v for v in vnics},
        subnets_by_id={s.id: s for s in networking.subnets},
        route_tables_by_id={r.id: r for r in networking.route_tables},
        security_lists_by_id={s.id: s for s in networking.security_lists},
        nsg_security_rules_by_nsg_id=networking.nsg_security_rules_by_nsg_id,
        internet_gateway_ids={g.id for g in internet_gateways},
        config=exposure_config,
    )

    # -- Base + Autonomous Database ----------------------------------------
    # Cascading lifecycle exclusion: a terminated parent's children are excluded with
    # it (db_system -> db_home -> database -> backup/data_guard), not just resources
    # terminated in their own right -- otherwise a child of an excluded parent would
    # surface as an unresolved relationship (parent not found) instead of correctly
    # reflecting that its whole lineage is gone. See transform/lifecycle.py.
    excluded_lifecycle_ids: dict[str, list[str]] = {}

    def _track_excluded(label: str, excluded_raw: list[Any]) -> None:
        if excluded_raw:
            excluded_lifecycle_ids.setdefault(label, []).extend(r.id for r in excluded_raw)

    kept_db_systems_raw, excluded_db_systems_raw = exclude_lifecycle_cascade(
        database_base.db_systems, parent_excluded_ids=set(), parent_id_field=None
    )
    _track_excluded("db_system", excluded_db_systems_raw)
    excluded_db_system_ids = {s.id for s in excluded_db_systems_raw}

    kept_db_homes_raw, excluded_db_homes_raw = exclude_lifecycle_cascade(
        database_base.db_homes, parent_excluded_ids=excluded_db_system_ids, parent_id_field="db_system_id"
    )
    _track_excluded("db_home", excluded_db_homes_raw)
    excluded_db_home_ids = {h.id for h in excluded_db_homes_raw}

    kept_databases_raw, excluded_databases_raw = exclude_lifecycle_cascade(
        database_base.databases, parent_excluded_ids=excluded_db_home_ids, parent_id_field="db_home_id"
    )
    _track_excluded("database", excluded_databases_raw)
    excluded_database_ids = {d.id for d in excluded_databases_raw}

    kept_base_backups_raw, excluded_base_backups_raw = exclude_lifecycle_cascade(
        database_base.backups, parent_excluded_ids=excluded_database_ids, parent_id_field="database_id"
    )
    _track_excluded("backup", excluded_base_backups_raw)

    kept_base_dg_raw, excluded_base_dg_raw = exclude_lifecycle_cascade(
        database_base.data_guard_associations,
        parent_excluded_ids=excluded_database_ids, parent_id_field="database_id",
    )
    _track_excluded("data_guard_association", excluded_base_dg_raw)

    db_systems = [
        normalize.normalize_database_resource(
            s, database_type="base_db_system", source_type="db_system",
            detail_fields=normalize.normalize_db_system_detail(s),
        )
        for s in kept_db_systems_raw
    ]
    db_homes = [
        normalize.normalize_database_resource(h, database_type="db_home", source_type="db_home")
        for h in kept_db_homes_raw
    ]
    base_databases = [
        normalize.normalize_database_resource(
            d, database_type="base_database", source_type="database",
            backup_status=normalize.normalize_db_backup_status(d),
            detail_fields=normalize.normalize_database_detail(d),
        )
        for d in kept_databases_raw
    ]
    base_backups = [
        normalize.normalize_database_resource(b, database_type="backup", source_type="backup")
        for b in kept_base_backups_raw
    ]
    base_dg = [
        normalize.normalize_database_resource(
            g, database_type="data_guard", source_type="data_guard_association",
            compartment_id="",  # backfilled by resolve_base_database_relationships
            detail_fields=normalize.normalize_data_guard_detail(g),
        )
        for g in kept_base_dg_raw
    ]
    (db_systems, db_homes, base_databases, base_backups, base_dg, unresolved) = (
        relationships.resolve_base_database_relationships(
            raw_db_systems=kept_db_systems_raw, db_systems=db_systems,
            raw_db_homes=kept_db_homes_raw, db_homes=db_homes,
            raw_databases=kept_databases_raw, databases=base_databases,
            raw_backups=kept_base_backups_raw, backups=base_backups,
            raw_data_guard_associations=kept_base_dg_raw,
            data_guard_associations=base_dg,
        )
    )
    all_unresolved.extend(unresolved)

    kept_autonomous_databases_raw, excluded_autonomous_databases_raw = exclude_lifecycle_cascade(
        autonomous_database.autonomous_databases, parent_excluded_ids=set(), parent_id_field=None
    )
    _track_excluded("autonomous_database", excluded_autonomous_databases_raw)
    excluded_adb_ids = {a.id for a in excluded_autonomous_databases_raw}
    kept_adb_ids = {a.id for a in kept_autonomous_databases_raw}

    kept_autonomous_backups_raw, excluded_autonomous_backups_raw = exclude_lifecycle_cascade(
        autonomous_database.autonomous_database_backups,
        parent_excluded_ids=excluded_adb_ids, parent_id_field="autonomous_database_id",
    )
    _track_excluded("autonomous_database_backup", excluded_autonomous_backups_raw)

    kept_autonomous_dg_raw, excluded_autonomous_dg_raw = exclude_lifecycle_cascade(
        autonomous_database.autonomous_database_dataguard_associations,
        parent_excluded_ids=excluded_adb_ids, parent_id_field="autonomous_database_id",
    )
    _track_excluded("autonomous_database_dataguard_association", excluded_autonomous_dg_raw)

    kept_peers_by_adb_id = {
        adb_id: peers
        for adb_id, peers in autonomous_database.autonomous_database_peers_by_adb_id.items()
        if adb_id in kept_adb_ids
    }

    autonomous_databases = [
        normalize.normalize_database_resource(
            a, database_type="autonomous_database", source_type="autonomous_database",
            backup_status="not_applicable",  # no reliable enabled/disabled signal -- see posture fields
            detail_fields=normalize.normalize_autonomous_database_posture(a),
        )
        for a in kept_autonomous_databases_raw
    ]
    autonomous_backups = [
        normalize.normalize_database_resource(b, database_type="backup", source_type="backup")
        for b in kept_autonomous_backups_raw
    ]
    autonomous_dg = [
        normalize.normalize_database_resource(
            g, database_type="data_guard", source_type="data_guard_association", compartment_id="",
            detail_fields=normalize.normalize_data_guard_detail(g),
        )
        for g in kept_autonomous_dg_raw
    ]
    (autonomous_databases, autonomous_backups, autonomous_dg, unresolved) = (
        relationships.resolve_autonomous_database_relationships(
            autonomous_databases=autonomous_databases,
            raw_autonomous_database_backups=kept_autonomous_backups_raw,
            autonomous_database_backups=autonomous_backups,
            raw_autonomous_database_dataguard_associations=kept_autonomous_dg_raw,
            autonomous_database_dataguard_associations=autonomous_dg,
            autonomous_database_peers_by_adb_id=kept_peers_by_adb_id,
        )
    )
    all_unresolved.extend(unresolved)

    backups = base_backups + autonomous_backups
    data_guard_associations = base_dg + autonomous_dg

    # -- VPN -----------------------------------------------------------
    kept_connections_raw, excluded_connections_raw = split_by_lifecycle(vpn.ip_sec_connections)
    _track_excluded("ipsec_connection", excluded_connections_raw)
    excluded_connection_ids = {c.id for c in excluded_connections_raw}

    ipsec_connections = [normalize.normalize_ipsec_connection(c) for c in kept_connections_raw]
    ipsec_tunnels: list[Any] = []
    tunnels_by_connection_id_normalized: dict[str, list[Any]] = {}
    all_excluded_tunnels_raw: list[Any] = []
    for connection_id, raw_tunnels in vpn.tunnels_by_connection_id.items():
        if connection_id in excluded_connection_ids:
            # Whole connection excluded -- its tunnels go with it, not tracked
            # individually (already covered by the ipsec_connection exclusion above).
            continue
        kept_tunnels_raw, excluded_tunnels_raw = split_by_lifecycle(raw_tunnels)
        all_excluded_tunnels_raw.extend(excluded_tunnels_raw)
        fallback_compartment_id = next(
            (c.compartment_id for c in ipsec_connections if c.id == connection_id), ""
        )
        normalized_tunnels = [
            normalize.normalize_ipsec_tunnel(
                t, ipsec_connection_id=connection_id, fallback_compartment_id=fallback_compartment_id
            )
            for t in kept_tunnels_raw
        ]
        tunnels_by_connection_id_normalized[connection_id] = normalized_tunnels
        ipsec_tunnels.extend(normalized_tunnels)
    _track_excluded("ipsec_connection_tunnel", all_excluded_tunnels_raw)

    ipsec_connections = derive_vpn_posture(
        ipsec_connections,
        tunnels_by_connection_id=tunnels_by_connection_id_normalized,
        minimum_tunnel_count=app_config.decisions.minimum_vpn_tunnel_count,
        minimum_up_tunnel_count=app_config.decisions.minimum_up_vpn_tunnel_count,
    )
    cpes = [normalize.normalize_common(c, source_type="cpe") for c in vpn.cpes]

    kept_drgs_raw, excluded_drgs_raw = split_by_lifecycle(vpn.drgs)
    _track_excluded("drg", excluded_drgs_raw)
    excluded_drg_ids = {d.id for d in excluded_drgs_raw}
    drgs = [normalize.normalize_common(d, source_type="drg") for d in kept_drgs_raw]

    kept_drg_attachments_raw, excluded_drg_attachments_raw = exclude_lifecycle_cascade(
        vpn.drg_attachments, parent_excluded_ids=excluded_drg_ids, parent_id_field="drg_id"
    )
    _track_excluded("drg_attachment", excluded_drg_attachments_raw)
    drg_attachments = [
        normalize.normalize_common(a, source_type="drg_attachment") for a in kept_drg_attachments_raw
    ]

    # -- Findings --------------------------------------------------------
    all_findings: list[Finding] = [
        *findings_mod.compute_exposure_findings(
            instances, administrative_ports=app_config.decisions.administrative_ports
        ),
        *findings_mod.volume_customer_managed_key_findings(
            [v for v in (*boot_volumes, *block_volumes) if v.attached_instance_ids],
            required=app_config.decisions.require_customer_managed_volume_keys,
        ),
        *findings_mod.database_customer_managed_key_findings(
            base_databases + autonomous_databases,
            required=app_config.decisions.require_customer_managed_database_keys,
        ),
        *findings_mod.database_public_endpoint_findings(autonomous_databases),
        *findings_mod.vpn_redundancy_findings(ipsec_connections),
    ]

    # -- Warnings ----------------------------------------------------------
    warnings: list[Message] = []
    excluded_lifecycle_ids["instance"] = [i.id for i in excluded_instances_raw]
    excluded_lifecycle_ids["boot_volume"] = [v.id for v in excluded_boot_volumes_raw]
    excluded_lifecycle_ids["block_volume"] = [v.id for v in excluded_block_volumes_raw]
    for label, ids in excluded_lifecycle_ids.items():
        if ids:
            warnings.append(
                Message(
                    code="LIFECYCLE_EXCLUDED",
                    message=(
                        f"{len(ids)} {label}(s) excluded from evidence: "
                        "lifecycle_state is TERMINATED or TERMINATING, or a parent in "
                        "this resource's chain was"
                    ),
                    severity="info",
                    resource_ids=tuple(sorted(ids)),
                )
            )
    if exadata.detected:
        warnings.append(
            Message(
                code="UNSUPPORTED_EXADATA_DETECTED",
                message="Exadata or Exadata-backed resources were detected; database domain "
                "coverage is incomplete. " + "; ".join(exadata.reasons),
                severity="warning",
                resource_ids=tuple(
                    (*exadata.affected_db_system_ids, *exadata.affected_autonomous_database_ids)
                ),
            )
        )
    for region in discovery.unready_regions:
        warnings.append(
            Message(
                code="REGION_NOT_READY",
                message=f"configured region {region!r} is not subscribed/READY",
                severity="error",
            )
        )
    for compartment_id in discovery.inaccessible_compartment_ids:
        warnings.append(
            Message(
                code="COMPARTMENT_INACCESSIBLE",
                message="compartment was not accessible during discovery",
                severity="warning",
                resource_ids=(compartment_id,),
            )
        )

    # -- Metrics -----------------------------------------------------------
    windows_instances = [i for i in instances if i.os_classification == "windows"]
    attached_volumes = [v for v in (*boot_volumes, *block_volumes) if v.attached_instance_ids]
    exadata_evidence_count = (
        len(exadata.affected_db_system_ids)
        + len(exadata.affected_autonomous_database_ids)
        + len(exadata.cloud_vm_clusters)
        + len(exadata.exadata_infrastructures)
        + len(exadata.cloud_exadata_infrastructures)
        + len(exadata.autonomous_exadata_infrastructures)
    )
    metrics = {
        "collectionErrorCount": sum(1 for op in all_operations if op.status == "failed"),
        "unsupportedResourceCount": exadata_evidence_count,
        "windowsVmCount": len(windows_instances),
        "windowsClassificationUnknownCount": sum(
            1 for i in instances if i.os_classification == "unknown"
        ),
        "publiclyAddressedWindowsVmCount": sum(
            1 for i in windows_instances if i.has_public_address is True
        ),
        "internetExposedWindowsVmCount": sum(
            1 for i in windows_instances if i.effective_ingress_exposure == "exposed"
        ),
        "unknownExposureWindowsVmCount": sum(
            1 for i in windows_instances if i.effective_ingress_exposure == "unknown"
        ),
        "attachedVolumeUnknownEncryptionCount": sum(
            1 for v in attached_volumes if v.customer_managed_key_present is None
        ),
        "attachedVolumeWithoutCustomerManagedKeyCount": sum(
            1 for v in attached_volumes if v.customer_managed_key_present is False
        ),
        "baseDatabaseCount": len(base_databases),
        "autonomousDatabaseCount": len(autonomous_databases),
        "databasePublicEndpointCount": sum(
            1 for a in autonomous_databases if a.public_endpoint_present is True
        ),
        "databaseBackupUnknownCount": sum(
            1 for d in (*base_databases, *autonomous_databases) if d.backup_status == "unknown"
        ),
        "exadataDetectedCount": exadata_evidence_count,
        "ipsecConnectionCount": len(ipsec_connections),
        "ipsecTunnelDownCount": sum(
            1 for t in ipsec_tunnels if t.status is not None and t.status != "UP"
        ),
        "ipsecTunnelUnknownCount": sum(1 for t in ipsec_tunnels if t.status is None),
        "nonRedundantIpsecConnectionCount": sum(
            1 for c in ipsec_connections if c.redundancy_status != "redundant"
        ),
    }
    assert set(metrics.keys()) == set(METRIC_KEYS)

    # -- Resources -----------------------------------------------------
    resources = {
        "compartments": _sorted_dicts(compartments),
        "images": _sorted_dicts(images),
        "instances": _sorted_dicts(instances),
        "vnics": _sorted_dicts(vnics),
        "privateIps": _sorted_dicts(private_ips),
        "publicIps": _sorted_dicts(public_ips),
        "bootVolumes": _sorted_dicts(boot_volumes),
        "blockVolumes": _sorted_dicts(block_volumes),
        "bootVolumeAttachments": _sorted_dicts(boot_volume_attachment_resources),
        "volumeAttachments": _sorted_dicts(volume_attachment_resources),
        "vcns": _sorted_dicts(vcns),
        "subnets": _sorted_dicts(subnets),
        "routeTables": _sorted_dicts(route_tables),
        "internetGateways": _sorted_dicts(internet_gateways),
        "securityLists": _sorted_dicts(security_lists),
        "networkSecurityGroups": _sorted_dicts(network_security_groups),
        "dbSystems": _sorted_dicts(db_systems),
        "dbHomes": _sorted_dicts(db_homes),
        "databases": _sorted_dicts(base_databases),
        "autonomousDatabases": _sorted_dicts(autonomous_databases),
        "backups": _sorted_dicts(backups),
        "dataGuardAssociations": _sorted_dicts(data_guard_associations),
        "cpes": _sorted_dicts(cpes),
        "drgs": _sorted_dicts(drgs),
        "drgAttachments": _sorted_dicts(drg_attachments),
        "ipsecConnections": _sorted_dicts(ipsec_connections),
        "ipsecTunnels": _sorted_dicts(ipsec_tunnels),
    }
    assert set(resources.keys()) == set(RESOURCE_COLLECTION_KEYS)

    domain_complete = {
        "compute": compute.complete,
        "storage": storage.complete,
        "networking": networking.complete,
        "databaseBase": database_base.complete,
        "autonomousDatabase": autonomous_database.complete,
        "exadataDetection": exadata.complete,
        "vpn": vpn.complete,
    }

    operation_records = [
        OperationRecord(
            service=op.service, operation=op.operation, region=op.region,
            compartment_id=op.compartment_id, status=op.status, page_count=op.page_count,
            item_count=op.item_count, request_ids=tuple(op.request_ids),
            error_code=op.error_code, error_message=op.error_message,
            retry_delays_seconds=tuple(op.retry_delays_seconds),
        )
        for op in all_operations
    ]
    operation_records.sort(key=lambda o: (o.service, o.operation, o.region or "", o.compartment_id or ""))

    tenancy_dict = {
        "id": app_config.oci.expected_tenancy_ocid,
        "name": getattr(discovery.tenancy, "name", None) or "unknown",
        "homeRegionKey": getattr(discovery.tenancy, "home_region_key", None) or "unknown",
    }

    record = {
        "id": app_config.drata.record_id,
        "displayName": app_config.deployment.snapshot_display_name,
        "schemaVersion": SCHEMA_VERSION,
        "collectorVersion": COLLECTOR_VERSION,
        "collectedAt": normalize.normalize_timestamp(completed_at),
        "snapshotStatus": "complete",  # overwritten by the caller once completeness is decided
        "freshnessThresholdHours": app_config.decisions.freshness_hours,
        "tenancy": tenancy_dict,
        "scope": {
            "expectedRegions": list(app_config.oci.regions.allow),
            "collectedRegions": list(discovery.approved_regions),
            "compartmentIds": list(discovery.approved_compartment_ids),
            "excludedCompartmentIds": list(discovery.excluded_compartment_ids),
        },
        "manifest": {
            "startedAt": normalize.normalize_timestamp(started_at),
            "completedAt": normalize.normalize_timestamp(completed_at),
            "derivationVersion": DERIVATION_VERSION,
            "operations": [o.to_dict() for o in operation_records],
            "unresolvedRelationships": [
                u.to_dict() for u in sorted(all_unresolved, key=lambda u: (u.source_type, u.source_id))
            ],
        },
        "metrics": metrics,
        "resources": resources,
        "findings": [
            f.to_dict() for f in sorted(all_findings, key=lambda f: (f.assertion_id, f.resource_id))
        ],
        "warnings": [w.to_dict() for w in sorted(warnings, key=lambda w: (w.code, w.message))],
    }

    return AggregateResult(
        record=record,
        unresolved_relationship_count=len(all_unresolved),
        exadata_detected=exadata.detected,
        domain_complete=domain_complete,
        discovery_complete=discovery.complete,
    )


# -- Flat-record architecture (see PLAN.md) --------------------------------
#
# One small record per collected resource, POSTed as {"data": [...]} to a single
# flat schema/resourceId -- replaces the nested resources.*/findings[] design
# above. New evidenceTypes are added by extending this section, not by
# restructuring it.
#
# Records carry raw/lightly-transformed OCI facts only -- no precomputed
# compliance verdict (no `status`, no admin-ports-policy-filtered port list).
# The Drata Custom Test evaluates compliance against these raw facts (e.g.
# `publicIngressPorts intersectsAny [22, 3389]`).


@dataclasses.dataclass(frozen=True)
class FlatRecordsResult:
    records: list[dict[str, Any]]
    domain_complete: dict[str, bool]
    discovery_complete: bool
    # Per-evidenceType count of resources dropped by lifecycle exclusion (deleted/
    # terminated). build_snapshot's nested path surfaces this via warnings[]; this path
    # had no equivalent, so a recordCount of 0 was indistinguishable from "every real
    # instance is terminated" versus "nothing was ever collected" -- see PLAN.md/README
    # troubleshooting for the incident this was found from.
    excluded_counts: dict[str, int]
    # instance<->vnic/storage joins that couldn't resolve (relationships.py). Computed
    # but previously discarded here -- unlike build_snapshot, which hard-blocks upload
    # on any unresolved relationship via decide_completeness().
    unresolved_relationship_count: int


def _flatten_instance(
    instance: Instance, ingress: PublicIngressFacts, *, timestamp: str | None
) -> dict[str, Any]:
    return {
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
        "id": user.id,
        "evidenceType": "iam_user",
        "name": user.name,
        "timestamp": timestamp,
        "compartmentId": user.compartment_id,
        "mfaActivated": user.is_mfa_activated,
    }


def _flatten_api_key(api_key: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
        "id": api_key.key_id,
        "evidenceType": "api_key",
        "name": api_key.fingerprint,
        "timestamp": timestamp,
        "userId": api_key.user_id,
        "keyCreatedAt": normalize.normalize_timestamp(api_key.time_created),
    }


def _flatten_bucket(bucket: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
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
    # Cloud Guard's Configuration has no id/compartmentId of its own -- it's a
    # tenancy-wide singleton, not a resource with an OCID. The tenancy OCID is the
    # only stable, unique identifier available for upsert-by-id.
    return {
        "id": tenancy_id or "cloud-guard-configuration",
        "evidenceType": "cloud_guard_configuration",
        "name": "Cloud Guard",
        "timestamp": timestamp,
        "compartmentId": tenancy_id,
        "cloudGuardStatus": configuration.status,
    }


def _flatten_alarm(alarm: Any, *, timestamp: str | None) -> dict[str, Any]:
    return {
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
    """Flat-record counterpart to build_snapshot: instances (raw ingress facts),
    autonomous databases (raw kmsKeyId/publicEndpointHostname), identity
    (iam_user/api_key/iam_policy, raw MFA/key-age/policy-statement facts), and
    object storage buckets (raw kmsKeyId/publicAccessType/versioning) so far.
    Same normalize join build_snapshot uses for resources.instances/
    autonomousDatabases, but stops short of build_snapshot's exposure derivation
    for instances: that applies decisions.administrativePorts as a policy filter,
    which doesn't belong in the collector for this path (see module docstring
    above). Autonomous databases and identity need no equivalent filtering step --
    their raw fields are already presence/fact-shaped, not a verdict, so they're
    reused as-is. Takes DecisionsConfig rather than the full AppConfig -- this
    path has no use for record_id/deployment name (each record carries its own
    id), and only decisions.publicSourceCidrs (what counts as an internet-facing
    source, not which ports matter) is relevant here."""

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

    # Identity resources use OCI's DELETED/DELETING vocabulary, not the
    # TERMINATED/TERMINATING split_by_lifecycle defaults to -- override explicitly
    # rather than silently keeping deleted users/policies (absence of a matching
    # state would otherwise fall through split_by_lifecycle's "keep if unknown" rule).
    _IDENTITY_DELETED_STATES = frozenset({"DELETED", "DELETING"})
    kept_users, excluded_users = split_by_lifecycle(
        identity.users, exclude_states=_IDENTITY_DELETED_STATES
    )
    kept_policies, excluded_policies = split_by_lifecycle(
        identity.policies, exclude_states=_IDENTITY_DELETED_STATES
    )
    kept_api_keys = [
        key
        for user in kept_users
        for key in identity.api_keys_by_user_id.get(user.id, [])
        if getattr(key, "lifecycle_state", None) not in _IDENTITY_DELETED_STATES
    ]

    # Monitoring alarms: OCI's general DELETED/DELETING convention, same caveat as
    # identity above -- not directly confirmed against Monitoring's own lifecycle
    # enum (no LIFECYCLE_STATE_* constants are exposed on AlarmSummary to check
    # against), but consistent with every other non-legacy OCI resource this
    # project has seen so far.
    kept_alarms, excluded_alarms = split_by_lifecycle(
        monitoring.alarms, exclude_states=_IDENTITY_DELETED_STATES
    )

    # LoadBalancer's real lifecycle enum is DELETED/DELETING/ACTIVE/CREATING/FAILED
    # (confirmed via oci.load_balancer.models.LoadBalancer's own LIFECYCLE_STATE_*
    # constants) -- same DELETED/DELETING exclusion convention as identity/alarms.
    kept_load_balancers, excluded_load_balancers = split_by_lifecycle(
        load_balancer.load_balancers, exclude_states=_IDENTITY_DELETED_STATES
    )

    # Same DELETED/DELETING convention as above; not directly confirmed against
    # WebAppFirewallLoadBalancerSummary's own lifecycle enum (no LIFECYCLE_STATE_*
    # constants exposed to check against), same caveat as monitoring alarms.
    kept_wafs, excluded_wafs = split_by_lifecycle(
        waf.web_app_firewalls, exclude_states=_IDENTITY_DELETED_STATES
    )

    # Key's real lifecycle enum (confirmed via oci.key_management.models.Key's own
    # LIFECYCLE_STATE_* constants) includes DELETED/DELETING alongside ENABLED/
    # DISABLED/etc -- DISABLED keys are still real, reportable evidence, only
    # DELETED/DELETING are excluded here.
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
        unresolved_relationship_count=len(unresolved_storage) + len(unresolved_vnic),
    )
