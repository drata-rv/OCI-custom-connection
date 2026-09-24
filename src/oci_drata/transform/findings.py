"""Derived-fact assertions: one Finding per resource per security predicate.
Emits per-resource facts only; pass/fail rollup happens in the consuming Custom Test.
"""

from __future__ import annotations

from oci_drata.models import DatabaseResource, Finding, Instance, IpsecConnection, Volume

DERIVATION_VERSION = "1.3.0"


def compute_exposure_findings(
    instances: list[Instance], *, administrative_ports: tuple[int, ...]
) -> list[Finding]:
    """Checks reachability of the configured administrative ports only
    (decisions.administrativePorts), not all ports. Reason always lists the full
    configured port set, even on pass/unknown, so what was checked stays visible."""

    findings = []
    for instance in instances:
        status = {"exposed": "fail", "not_exposed": "pass", "unknown": "unknown"}[
            instance.effective_ingress_exposure
        ]
        findings.append(
            Finding(
                assertion_id="OCI-COMPUTE-ADMIN-PORT-EXPOSURE",
                status=status,
                resource_type="compute_instance",
                resource_id=instance.id,
                resource_name=instance.display_name,
                region=instance.region,
                compartment_id=instance.compartment_id,
                observed=instance.effective_ingress_exposure,
                expected="not_exposed",
                reason=(
                    f"evaluatedAdministrativePorts={list(administrative_ports)!r} "
                    f"exposedAdministrativePorts={list(instance.exposed_administrative_ports)!r} "
                    f"hasPublicAddress={instance.has_public_address!r}"
                ),
                source_ids=(instance.id, *instance.vnic_ids),
                derivation_version=DERIVATION_VERSION,
            )
        )
    return findings


def volume_customer_managed_key_findings(
    volumes: list[Volume], *, required: bool
) -> list[Finding]:
    if not required:
        return []
    findings = []
    for volume in volumes:
        if volume.customer_managed_key_present is None:
            status = "unknown"
        else:
            status = "pass" if volume.customer_managed_key_present else "fail"
        findings.append(
            Finding(
                assertion_id="OCI-STORAGE-CUSTOMER-MANAGED-KEY",
                status=status,
                resource_type=volume.source_type,
                resource_id=volume.id,
                resource_name=volume.display_name,
                region=volume.region,
                compartment_id=volume.compartment_id,
                observed=volume.customer_managed_key_present,
                expected=True,
                reason=f"kmsKeyId={volume.kms_key_id!r}",
                source_ids=(volume.id,),
                derivation_version=DERIVATION_VERSION,
            )
        )
    return findings


def database_customer_managed_key_findings(
    resources: list[DatabaseResource], *, required: bool
) -> list[Finding]:
    if not required:
        return []
    findings = []
    for resource in resources:
        has_key = resource.kms_key_id is not None
        findings.append(
            Finding(
                assertion_id="OCI-DATABASE-CUSTOMER-MANAGED-KEY",
                status="pass" if has_key else "fail",
                resource_type=resource.database_type,
                resource_id=resource.id,
                resource_name=resource.display_name,
                region=resource.region,
                compartment_id=resource.compartment_id,
                observed=has_key,
                expected=True,
                reason=f"kmsKeyId={resource.kms_key_id!r}",
                source_ids=(resource.id,),
                derivation_version=DERIVATION_VERSION,
            )
        )
    return findings


def database_public_endpoint_findings(autonomous_databases: list[DatabaseResource]) -> list[Finding]:
    """Checks presence of a public endpoint hostname only, not effective reachability --
    an ADB can carry one while an ACL or private endpoint still restricts access.
    accessControlEnabled/privateEndpointConfigured ride along in the reason for
    review, not folded into the verdict."""

    findings = []
    for adb in autonomous_databases:
        if adb.public_endpoint_present is None:
            status = "unknown"
        else:
            status = "fail" if adb.public_endpoint_present else "pass"
        findings.append(
            Finding(
                assertion_id="OCI-ADB-PUBLIC-ENDPOINT-PRESENT",
                status=status,
                resource_type=adb.database_type,
                resource_id=adb.id,
                resource_name=adb.display_name,
                region=adb.region,
                compartment_id=adb.compartment_id,
                observed=adb.public_endpoint_present,
                expected=False,
                reason=(
                    f"publicEndpointPresent={adb.public_endpoint_present!r} "
                    f"accessControlEnabled={adb.access_control_enabled!r} "
                    f"privateEndpointConfigured={adb.private_endpoint_configured!r} "
                    f"(checks endpoint presence only -- effective reachability through "
                    f"ACL/private-endpoint/NSGs is not resolved by this derivation)"
                ),
                source_ids=(adb.id,),
                derivation_version=DERIVATION_VERSION,
            )
        )
    return findings


def vpn_redundancy_findings(connections: list[IpsecConnection]) -> list[Finding]:
    findings = []
    for connection in connections:
        status = {"redundant": "pass", "not_redundant": "fail", "unknown": "unknown"}[
            connection.redundancy_status
        ]
        findings.append(
            Finding(
                assertion_id="OCI-VPN-TUNNEL-REDUNDANCY",
                status=status,
                resource_type="ipsec_connection",
                resource_id=connection.id,
                resource_name=connection.display_name,
                region=connection.region,
                compartment_id=connection.compartment_id,
                observed=f"{connection.up_tunnel_count}/{connection.tunnel_count} tunnels up",
                expected="redundant",
                reason=connection.redundancy_status,
                source_ids=(connection.id, *connection.tunnel_ids),
                derivation_version=DERIVATION_VERSION,
            )
        )
    return findings
