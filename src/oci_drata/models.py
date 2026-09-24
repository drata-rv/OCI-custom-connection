"""Source-fact and derived-fact models mirroring the oci-snapshot-1.0.0.json schema.

to_dict() emits every schema key (additionalProperties: false); derivation logic lives in oci_drata.transform.
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
class Volume(CommonResource):
    kms_key_id: str | None = None
    customer_managed_key_present: bool | None = None
    attached_instance_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "kmsKeyId": self.kms_key_id,
                "customerManagedKeyPresent": self.customer_managed_key_present,
                "attachedInstanceIds": list(self.attached_instance_ids),
            }
        )
        return base


@dataclasses.dataclass(frozen=True)
class PortRange:
    min: int | None = None
    max: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"min": self.min, "max": self.max}


@dataclasses.dataclass(frozen=True)
class RouteRule:
    destination: str | None = None
    destination_type: str | None = None
    network_entity_id: str | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "destination": self.destination,
            "destinationType": self.destination_type,
            "networkEntityId": self.network_entity_id,
            "description": self.description,
        }


@dataclasses.dataclass(frozen=True)
class SecurityRule:
    """Shared shape for security-list and NSG security rules. Direction is assigned by
    the normalizer, since raw Ingress/EgressSecurityRule types carry no direction field."""

    direction: str = "unknown"  # ingress | egress
    protocol: str | None = None
    source: str | None = None
    source_type: str | None = None
    destination: str | None = None
    destination_type: str | None = None
    is_stateless: bool | None = None
    tcp_port_range: PortRange | None = None
    udp_port_range: PortRange | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction,
            "protocol": self.protocol,
            "source": self.source,
            "sourceType": self.source_type,
            "destination": self.destination,
            "destinationType": self.destination_type,
            "isStateless": self.is_stateless,
            "tcpPortRange": self.tcp_port_range.to_dict() if self.tcp_port_range else None,
            "udpPortRange": self.udp_port_range.to_dict() if self.udp_port_range else None,
            "description": self.description,
        }


@dataclasses.dataclass(frozen=True)
class RouteTable(CommonResource):
    route_rules: tuple[RouteRule, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({"routeRules": [r.to_dict() for r in self.route_rules]})
        return base


@dataclasses.dataclass(frozen=True)
class SecurityList(CommonResource):
    ingress_rules: tuple[SecurityRule, ...] = ()
    egress_rules: tuple[SecurityRule, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "ingressRules": [r.to_dict() for r in self.ingress_rules],
                "egressRules": [r.to_dict() for r in self.egress_rules],
            }
        )
        return base


@dataclasses.dataclass(frozen=True)
class NetworkSecurityGroup(CommonResource):
    security_rules: tuple[SecurityRule, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({"securityRules": [r.to_dict() for r in self.security_rules]})
        return base


@dataclasses.dataclass(frozen=True)
class InternetGateway(CommonResource):
    is_enabled: bool | None = None
    vcn_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({"isEnabled": self.is_enabled, "vcnId": self.vcn_id})
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
class IpsecConnection(CommonResource):
    cpe_id: str = ""
    drg_id: str = ""
    tunnel_ids: tuple[str, ...] = ()
    tunnel_count: int = 0
    up_tunnel_count: int = 0
    redundancy_status: str = "unknown"  # redundant | not_redundant | unknown

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "cpeId": self.cpe_id,
                "drgId": self.drg_id,
                "tunnelIds": list(self.tunnel_ids),
                "tunnelCount": self.tunnel_count,
                "upTunnelCount": self.up_tunnel_count,
                "redundancyStatus": self.redundancy_status,
            }
        )
        return base


@dataclasses.dataclass(frozen=True)
class IpsecTunnel(CommonResource):
    ipsec_connection_id: str = ""
    status: str | None = None
    routing: str | None = None
    ike_version: str | None = None
    bgp_state: str | None = None

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "ipsecConnectionId": self.ipsec_connection_id,
                "status": self.status,
                "routing": self.routing,
                "ikeVersion": self.ike_version,
                "bgpState": self.bgp_state,
            }
        )
        return base


@dataclasses.dataclass(frozen=True)
class Finding:
    assertion_id: str
    status: str  # pass | fail | unknown | not_applicable
    resource_type: str
    resource_id: str
    resource_name: str | None
    region: str | None
    compartment_id: str | None
    observed: Any
    expected: Any
    reason: str
    source_ids: tuple[str, ...]
    derivation_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertionId": self.assertion_id,
            "status": self.status,
            "resourceType": self.resource_type,
            "resourceId": self.resource_id,
            "resourceName": self.resource_name,
            "region": self.region,
            "compartmentId": self.compartment_id,
            "observed": self.observed,
            "expected": self.expected,
            "reason": self.reason,
            "sourceIds": list(self.source_ids),
            "derivationVersion": self.derivation_version,
        }


@dataclasses.dataclass(frozen=True)
class Message:
    code: str
    message: str
    severity: str  # info | warning | error
    resource_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "resourceIds": list(self.resource_ids),
        }


@dataclasses.dataclass(frozen=True)
class OperationRecord:
    service: str
    operation: str
    region: str | None
    status: str  # success | failed | unsupported | skipped
    page_count: int
    item_count: int
    request_ids: tuple[str, ...]
    compartment_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    retry_delays_seconds: tuple[float, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "operation": self.operation,
            "region": self.region,
            "compartmentId": self.compartment_id,
            "status": self.status,
            "pageCount": self.page_count,
            "itemCount": self.item_count,
            "requestIds": list(self.request_ids),
            "errorCode": self.error_code,
            "errorMessage": self.error_message,
            "retryDelaysSeconds": list(self.retry_delays_seconds),
        }


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


RESOURCE_COLLECTION_KEYS: tuple[str, ...] = (
    "compartments",
    "images",
    "instances",
    "vnics",
    "privateIps",
    "publicIps",
    "bootVolumes",
    "blockVolumes",
    "bootVolumeAttachments",
    "volumeAttachments",
    "vcns",
    "subnets",
    "routeTables",
    "internetGateways",
    "securityLists",
    "networkSecurityGroups",
    "dbSystems",
    "dbHomes",
    "databases",
    "autonomousDatabases",
    "backups",
    "dataGuardAssociations",
    "cpes",
    "drgs",
    "drgAttachments",
    "ipsecConnections",
    "ipsecTunnels",
)

METRIC_KEYS: tuple[str, ...] = (
    "collectionErrorCount",
    "unsupportedResourceCount",
    "windowsVmCount",
    "windowsClassificationUnknownCount",
    "publiclyAddressedWindowsVmCount",
    "internetExposedWindowsVmCount",
    "unknownExposureWindowsVmCount",
    "attachedVolumeUnknownEncryptionCount",
    "attachedVolumeWithoutCustomerManagedKeyCount",
    "baseDatabaseCount",
    "autonomousDatabaseCount",
    "databasePublicEndpointCount",
    "databaseBackupUnknownCount",
    "exadataDetectedCount",
    "ipsecConnectionCount",
    "ipsecTunnelDownCount",
    "ipsecTunnelUnknownCount",
    "nonRedundantIpsecConnectionCount",
)
