"""Source-fact models for resources the flat-record path emits (instance, vnic) or
joins against on the way to a flat record. Derivation logic lives in oci_drata.transform.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any

Tags = Mapping[str, Any]


def _tags(value: Tags | None) -> dict[str, Any]:
    return dict(value) if value else {}


@dataclasses.dataclass(frozen=True)
class CommonResource:
    id: str
    source_type: str
    region: str
    compartment_id: str
    display_name: str | None
    lifecycle_state: str | None
    time_created: str | None = None
    defined_tags: Tags = dataclasses.field(default_factory=dict)
    freeform_tags: Tags = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sourceType": self.source_type,
            "region": self.region,
            "compartmentId": self.compartment_id,
            "displayName": self.display_name,
            "lifecycleState": self.lifecycle_state,
            "timeCreated": self.time_created,
            "definedTags": _tags(self.defined_tags),
            "freeformTags": _tags(self.freeform_tags),
        }


@dataclasses.dataclass(frozen=True)
class Instance(CommonResource):
    image_id: str | None = None
    os_classification: str = "unknown"  # windows | non_windows | unknown
    has_public_address: bool | None = None
    effective_ingress_exposure: str = "unknown"  # exposed | not_exposed | unknown
    exposed_administrative_ports: tuple[int, ...] = ()
    vnic_ids: tuple[str, ...] = ()
    volume_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "imageId": self.image_id,
                "osClassification": self.os_classification,
                "hasPublicAddress": self.has_public_address,
                "effectiveIngressExposure": self.effective_ingress_exposure,
                "exposedAdministrativePorts": list(self.exposed_administrative_ports),
                "vnicIds": list(self.vnic_ids),
                "volumeIds": list(self.volume_ids),
            }
        )
        return base


@dataclasses.dataclass(frozen=True)
class Vnic(CommonResource):
    instance_id: str | None = None
    subnet_id: str = ""
    nsg_ids: tuple[str, ...] = ()
    private_addresses: tuple[str, ...] = ()
    public_addresses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "instanceId": self.instance_id,
                "subnetId": self.subnet_id,
                "nsgIds": list(self.nsg_ids),
                "privateAddresses": list(self.private_addresses),
                "publicAddresses": list(self.public_addresses),
            }
        )
        return base


@dataclasses.dataclass(frozen=True)
class DatabaseResource(CommonResource):
    database_type: str = "base_database"
    backup_status: str = "unknown"  # enabled | disabled | unknown | not_applicable
    kms_key_id: str | None = None
    related_resource_ids: tuple[str, ...] = ()
    # Autonomous Database posture: separate raw/derived fields, no single guessed status.
    # None on non-ADB rows.
    public_endpoint_hostname: str | None = None
    private_endpoint_configured: bool | None = None
    public_endpoint_present: bool | None = None
    access_control_enabled: bool | None = None
    allowed_source_count: int | None = None
    mtls_required: bool | None = None
    network_security_group_ids: tuple[str, ...] = ()
    backup_retention_days: int | None = None
    backup_retention_locked: bool | None = None
    long_term_backup_schedule_configured: bool | None = None
    # Base DB System detail. None on non-db_system rows.
    shape: str | None = None
    version: str | None = None
    os_version: str | None = None
    node_count: int | None = None
    disk_redundancy: str | None = None
    subnet_id: str | None = None
    # Base Database detail. None on non-database rows.
    last_backup_timestamp: str | None = None
    last_failed_backup_timestamp: str | None = None
    patch_version: str | None = None
    recovery_window_days: int | None = None
    database_management_status: str | None = None
    # Data Guard association detail. None on non-data_guard rows.
    data_guard_role: str | None = None
    data_guard_peer_role: str | None = None
    data_guard_protection_mode: str | None = None
    data_guard_transport_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "databaseType": self.database_type,
                "backupStatus": self.backup_status,
                "kmsKeyId": self.kms_key_id,
                "relatedResourceIds": list(self.related_resource_ids),
                "publicEndpointHostname": self.public_endpoint_hostname,
                "privateEndpointConfigured": self.private_endpoint_configured,
                "publicEndpointPresent": self.public_endpoint_present,
                "accessControlEnabled": self.access_control_enabled,
                "allowedSourceCount": self.allowed_source_count,
                "mtlsRequired": self.mtls_required,
                "networkSecurityGroupIds": list(self.network_security_group_ids),
                "backupRetentionDays": self.backup_retention_days,
                "backupRetentionLocked": self.backup_retention_locked,
                "longTermBackupScheduleConfigured": self.long_term_backup_schedule_configured,
                "shape": self.shape,
                "version": self.version,
                "osVersion": self.os_version,
                "nodeCount": self.node_count,
                "diskRedundancy": self.disk_redundancy,
                "subnetId": self.subnet_id,
                "lastBackupTimestamp": self.last_backup_timestamp,
                "lastFailedBackupTimestamp": self.last_failed_backup_timestamp,
                "patchVersion": self.patch_version,
                "recoveryWindowDays": self.recovery_window_days,
                "databaseManagementStatus": self.database_management_status,
                "dataGuardRole": self.data_guard_role,
                "dataGuardPeerRole": self.data_guard_peer_role,
                "dataGuardProtectionMode": self.data_guard_protection_mode,
                "dataGuardTransportType": self.data_guard_transport_type,
            }
        )
        return base


@dataclasses.dataclass(frozen=True)
class UnresolvedRelationship:
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceType": self.source_type,
            "sourceId": self.source_id,
            "targetType": self.target_type,
            "targetId": self.target_id,
            "reason": self.reason,
        }
