"""Network exposure derivation for compute instances (spec 5.4).

``effectiveIngressExposure`` answers one specific compliance question --
"is this instance reachable on a configured administrative port from a
public source" -- not "is any port on this instance open to the internet".
That's why it's computed together with ``exposedAdministrativePorts``
rather than as an independent general-exposure flag: spec's own metrics
(``internetExposedWindowsVmCount``, ``publiclyAddressedWindowsVmCount``)
are specifically about administrative-port reachability, and every
finding built downstream cites a concrete port.

Per spec: "effectiveIngressExposure=exposed only when collector can prove
public addressing, route path, and permissive effective ingress. Missing
route/rule/membership evidence yields unknown, not not_exposed." -- proving
the negative (no public address at all) is the one case allowed to short
circuit straight to not_exposed regardless of route/rule completeness,
since a resource with no public IP cannot be internet-reachable no matter
what its routing or security rules say.

Known MVP simplification, documented rather than hidden: a source CIDR is
matched by exact string equality against the configured
``decisions.publicSourceCidrs`` list (default ``0.0.0.0/0``, ``::/0``), not
by CIDR-superset containment. A rule permitting ``0.0.0.0/1`` would not be
flagged even though it covers half the public internet. Extending this to
real CIDR containment math is a natural follow-up, not implemented here to
avoid an unverified, untested subnetting routine in a security-relevant
code path.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Iterable

from oci_drata.models import Instance, Vnic

_TCP_PROTOCOLS = frozenset({"6", "all"})


@dataclasses.dataclass(frozen=True)
class ExposureConfig:
    administrative_ports: tuple[int, ...]
    public_source_cidrs: tuple[str, ...]


def _has_igw_route(route_rules: Iterable[Any], internet_gateway_ids: set[str]) -> bool:
    for rule in route_rules:
        network_entity_id = getattr(rule, "network_entity_id", None)
        destination = getattr(rule, "destination", None)
        if network_entity_id in internet_gateway_ids and destination in ("0.0.0.0/0", "::/0"):
            return True
    return False


def _rule_covers_port(tcp_options: Any, port: int) -> bool:
    if tcp_options is None:
        return True  # no tcp_options on a TCP/all rule means every port
    port_range = getattr(tcp_options, "destination_port_range", None)
    if port_range is None:
        return True
    return port_range.min <= port <= port_range.max


def _permissive_admin_ports(
    rules: Iterable[Any],
    *,
    administrative_ports: tuple[int, ...],
    public_source_cidrs: tuple[str, ...],
    is_ingress: Callable[[Any], bool] | None = None,
) -> set[int]:
    exposed: set[int] = set()
    for rule in rules:
        if is_ingress is not None and not is_ingress(rule):
            continue
        protocol = getattr(rule, "protocol", None)
        if protocol not in _TCP_PROTOCOLS:
            continue
        source = getattr(rule, "source", None)
        source_type = getattr(rule, "source_type", None)
        if source_type not in (None, "CIDR_BLOCK") or source not in public_source_cidrs:
            continue
        tcp_options = getattr(rule, "tcp_options", None)
        for port in administrative_ports:
            if _rule_covers_port(tcp_options, port):
                exposed.add(port)
    return exposed


def derive_instance_exposure(
    instances: list[Instance],
    *,
    vnics_by_id: dict[str, Vnic],
    subnets_by_id: dict[str, Any],
    route_tables_by_id: dict[str, Any],
    security_lists_by_id: dict[str, Any],
    nsg_security_rules_by_nsg_id: dict[str, list[Any]],
    internet_gateway_ids: set[str],
    config: ExposureConfig,
) -> list[Instance]:
    resolved: list[Instance] = []
    for instance in instances:
        resolved.append(_derive_one(instance, vnics_by_id, subnets_by_id, route_tables_by_id,
                                     security_lists_by_id, nsg_security_rules_by_nsg_id,
                                     internet_gateway_ids, config))
    return resolved


def _derive_one(
    instance: Instance,
    vnics_by_id: dict[str, Vnic],
    subnets_by_id: dict[str, Any],
    route_tables_by_id: dict[str, Any],
    security_lists_by_id: dict[str, Any],
    nsg_security_rules_by_nsg_id: dict[str, list[Any]],
    internet_gateway_ids: set[str],
    config: ExposureConfig,
) -> Instance:
    if not instance.vnic_ids:
        # No resolved VNIC at all -- can't prove or disprove addressing.
        return dataclasses.replace(
            instance, has_public_address=None, effective_ingress_exposure="unknown"
        )

    instance_vnics = [vnics_by_id[v] for v in instance.vnic_ids if v in vnics_by_id]
    if len(instance_vnics) != len(instance.vnic_ids):
        # A VNIC attachment referenced a VNIC we failed to resolve --
        # addressing cannot be proven complete either way.
        return dataclasses.replace(
            instance, has_public_address=None, effective_ingress_exposure="unknown"
        )

    has_public_address = any(v.public_addresses for v in instance_vnics)
    if not has_public_address:
        # Definitive: no public IP anywhere on this instance's VNICs means
        # it cannot be internet-reachable, regardless of route/rule
        # completeness -- the one case allowed to short-circuit past
        # "unknown".
        return dataclasses.replace(
            instance,
            has_public_address=False,
            effective_ingress_exposure="not_exposed",
            exposed_administrative_ports=(),
        )

    public_vnics = [v for v in instance_vnics if v.public_addresses]
    route_evidence_complete = True
    ingress_evidence_complete = True
    has_igw_route = False
    exposed_ports: set[int] = set()

    for vnic in public_vnics:
        subnet = subnets_by_id.get(vnic.subnet_id)
        if subnet is None:
            route_evidence_complete = False
            ingress_evidence_complete = False
            continue

        route_table_id = getattr(subnet, "route_table_id", None)
        route_table = route_tables_by_id.get(route_table_id) if route_table_id else None
        if route_table is None:
            route_evidence_complete = False
        else:
            if _has_igw_route(getattr(route_table, "route_rules", None) or (), internet_gateway_ids):
                has_igw_route = True

        for security_list_id in getattr(subnet, "security_list_ids", None) or ():
            security_list = security_lists_by_id.get(security_list_id)
            if security_list is None:
                ingress_evidence_complete = False
                continue
            exposed_ports |= _permissive_admin_ports(
                getattr(security_list, "ingress_security_rules", None) or (),
                administrative_ports=config.administrative_ports,
                public_source_cidrs=config.public_source_cidrs,
            )

        for nsg_id in vnic.nsg_ids:
            if nsg_id not in nsg_security_rules_by_nsg_id:
                ingress_evidence_complete = False
                continue
            exposed_ports |= _permissive_admin_ports(
                nsg_security_rules_by_nsg_id[nsg_id],
                administrative_ports=config.administrative_ports,
                public_source_cidrs=config.public_source_cidrs,
                is_ingress=lambda rule: getattr(rule, "direction", None) == "INGRESS",
            )

    if not route_evidence_complete or not ingress_evidence_complete:
        return dataclasses.replace(
            instance,
            has_public_address=True,
            effective_ingress_exposure="unknown",
            exposed_administrative_ports=tuple(sorted(exposed_ports)),
        )

    if has_igw_route and exposed_ports:
        exposure = "exposed"
    else:
        exposure = "not_exposed"

    return dataclasses.replace(
        instance,
        has_public_address=True,
        effective_ingress_exposure=exposure,
        exposed_administrative_ports=tuple(sorted(exposed_ports)),
    )
