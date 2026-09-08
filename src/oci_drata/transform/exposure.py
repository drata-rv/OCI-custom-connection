"""Network exposure derivation for compute instances (spec 5.4).

effectiveIngressExposure reflects administrative-port reachability only, not general port exposure.
Missing route/rule/membership evidence yields unknown; only no public address short-circuits to not_exposed.
Source is evaluated by real CIDR containment/overlap (ipaddress), not string equality: a rule's source
counts as public when it is globally routable (excludes RFC1918/loopback/link-local/CGNAT/reserved, per
ipaddress.is_global) AND overlaps a configured publicSourceCidrs reference network. A source that fails to
parse, or an NSG-typed source (membership not resolved -- no NSG-to-NSG chain resolution in this MVP),
marks evidence incomplete for that VNIC rather than silently excluding the rule.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from collections.abc import Callable, Iterable
from typing import Any

from oci_drata.models import Instance, Vnic

_TCP_PROTOCOLS = frozenset({"6", "all"})
_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_network(cidr: str) -> _IpNetwork | None:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return None


def _is_effectively_public(source_network: _IpNetwork, public_reference_networks: tuple[_IpNetwork, ...]) -> bool:
    if not source_network.is_global:
        return False
    return any(
        source_network.version == reference.version and source_network.overlaps(reference)
        for reference in public_reference_networks
    )


@dataclasses.dataclass(frozen=True)
class ExposureConfig:
    administrative_ports: tuple[int, ...]
    public_source_cidrs: tuple[str, ...]
    public_reference_networks: tuple[_IpNetwork, ...] = dataclasses.field(init=False, repr=False)

    def __post_init__(self) -> None:
        parsed = tuple(n for n in (_parse_network(c) for c in self.public_source_cidrs) if n is not None)
        object.__setattr__(self, "public_reference_networks", parsed)


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
    public_reference_networks: tuple[_IpNetwork, ...],
    is_ingress: Callable[[Any], bool] | None = None,
) -> tuple[set[int], bool]:
    """Returns (exposed administrative ports, evidence_complete). evidence_complete is False when a rule's
    source can't be resolved to a definite public/private verdict (unparseable CIDR, or NSG-typed source
    whose membership this MVP doesn't resolve) -- such a rule can't be proven safe, so it must not be
    silently dropped from consideration."""

    exposed: set[int] = set()
    evidence_complete = True
    for rule in rules:
        if is_ingress is not None and not is_ingress(rule):
            continue
        protocol = getattr(rule, "protocol", None)
        if protocol not in _TCP_PROTOCOLS:
            continue
        source = getattr(rule, "source", None)
        source_type = getattr(rule, "source_type", None)

        if source_type == "SERVICE_CIDR_BLOCK":
            continue  # Oracle-managed service network, never internet-sourced.
        if source_type == "NETWORK_SECURITY_GROUP":
            evidence_complete = False
            continue
        if source_type not in (None, "CIDR_BLOCK"):
            evidence_complete = False
            continue

        source_network = _parse_network(source) if source else None
        if source_network is None:
            evidence_complete = False
            continue
        if not _is_effectively_public(source_network, public_reference_networks):
            continue

        tcp_options = getattr(rule, "tcp_options", None)
        for port in administrative_ports:
            if _rule_covers_port(tcp_options, port):
                exposed.add(port)
    return exposed, evidence_complete


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
        # No VNIC ids: addressing unprovable -> unknown.
        return dataclasses.replace(
            instance, has_public_address=None, effective_ingress_exposure="unknown"
        )

    instance_vnics = [vnics_by_id[v] for v in instance.vnic_ids if v in vnics_by_id]
    if len(instance_vnics) != len(instance.vnic_ids):
        # Unresolved VNIC reference: addressing not provably complete.
        return dataclasses.replace(
            instance, has_public_address=None, effective_ingress_exposure="unknown"
        )

    has_public_address = any(v.public_addresses for v in instance_vnics)
    if not has_public_address:
        # No public IP: not internet-reachable regardless of route/rule completeness. Only short-circuit case.
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
            sl_ports, sl_complete = _permissive_admin_ports(
                getattr(security_list, "ingress_security_rules", None) or (),
                administrative_ports=config.administrative_ports,
                public_reference_networks=config.public_reference_networks,
            )
            exposed_ports |= sl_ports
            ingress_evidence_complete = ingress_evidence_complete and sl_complete

        for nsg_id in vnic.nsg_ids:
            if nsg_id not in nsg_security_rules_by_nsg_id:
                ingress_evidence_complete = False
                continue
            nsg_ports, nsg_complete = _permissive_admin_ports(
                nsg_security_rules_by_nsg_id[nsg_id],
                administrative_ports=config.administrative_ports,
                public_reference_networks=config.public_reference_networks,
                is_ingress=lambda rule: getattr(rule, "direction", None) == "INGRESS",
            )
            exposed_ports |= nsg_ports
            ingress_evidence_complete = ingress_evidence_complete and nsg_complete

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
