"""Allowlisted source-fact and derived-fact models.

Every dataclass here mirrors one definition in
``schemas/oci-snapshot-1.0.0.json`` field-for-field. ``to_dict()`` always
emits every schema-declared property (using ``None``/``"unknown"``/``[]``
defaults rather than omitting a key) so serialization is deterministic and
never accidentally introduces a property the schema's
``additionalProperties: false`` would reject.

These are *source facts* (allowlisted copies of OCI response fields, with
region/compartment/sourceType/parent-ID stamped on) and a small set of
*derived* shapes (:class:`Finding`, :class:`Message`). Derivation logic
itself lives in :mod:`oci_drata.transform`, not here -- this module only
defines the allowed shape of the data.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Mapping

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
class DatabaseResource(CommonResource):
    database_type: str = "base_database"
    public_endpoint: bool | None = None
    backup_status: str = "unknown"  # enabled | disabled | unknown | not_applicable
    kms_key_id: str | None = None
    related_resource_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update(
            {
                "databaseType": self.database_type,
                "publicEndpoint": self.public_endpoint,
                "backupStatus": self.backup_status,
                "kmsKeyId": self.kms_key_id,
                "relatedResourceIds": list(self.related_resource_ids),
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
