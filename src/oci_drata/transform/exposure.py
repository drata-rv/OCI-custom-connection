"""Public-ingress-reachability derivation for compute instances, for the flat-record path.

Reports raw reachability facts (public address, named ingress ports, whether a rule is too broad to
enumerate) with no administrative-ports policy applied -- that policy belongs in the Drata Custom Test.
Missing route/rule/membership evidence yields a null/incomplete fact; only no public address
short-circuits to a definite not-exposed. A source counts as public via real CIDR overlap
(ipaddress.is_global) against publicSourceCidrs, never string equality; a source that fails to parse, or
an NSG-typed source (membership unresolved), marks evidence incomplete rather than excluding the rule.
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


_DEFAULT_ROUTE_FAMILY = {"0.0.0.0/0": 4, "::/0": 6}
_ALL_PORTS = (1, 65535)


def _address_families(addresses: Iterable[str]) -> frozenset[int]:
    return frozenset(6 if ":" in address else 4 for address in addresses)


def _has_igw_route(
    route_rules: Iterable[Any], internet_gateway_ids: set[str], families: frozenset[int]
) -> bool:
    """A default route to an internet gateway in the same IP family as a public address."""

    for rule in route_rules:
        network_entity_id = getattr(rule, "network_entity_id", None)
        family = _DEFAULT_ROUTE_FAMILY.get(getattr(rule, "destination", None) or "")
        if network_entity_id in internet_gateway_ids and family in families:
            return True
    return False


def _public_ingress_from_rules(
    rules: Iterable[Any],
    *,
    public_reference_networks: tuple[_IpNetwork, ...],
    families: frozenset[int],
    is_ingress: Callable[[Any], bool] | None = None,
) -> tuple[set[int], set[tuple[int, int]], bool]:
    """Reports every port a public-source rule names, with no administrative-ports allowlist applied
    (that policy belongs in the Drata Custom Test, not here). A single-port rule is a named port; an
    unrestricted or multi-port rule is kept as its (min, max) range instead of dropped or truncated.
    Only rules whose source is in an IP family the VNIC holds a public address in apply.
    Returns (named ports, ranges, evidence_complete)."""

    named_ports: set[int] = set()
    ranges: set[tuple[int, int]] = set()
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
        if source_network.version not in families:
            continue
        if not _is_effectively_public(source_network, public_reference_networks):
            continue

        tcp_options = getattr(rule, "tcp_options", None)
        port_range = getattr(tcp_options, "destination_port_range", None) if tcp_options else None
        if port_range is None:
            ranges.add(_ALL_PORTS)  # no port restriction on this rule: every port is open
        elif port_range.min is not None and port_range.min == port_range.max:
            named_ports.add(port_range.min)
        else:
            low = port_range.min if port_range.min is not None else _ALL_PORTS[0]
            high = port_range.max if port_range.max is not None else _ALL_PORTS[1]
            ranges.add((low, high))
    return named_ports, ranges, evidence_complete


@dataclasses.dataclass(frozen=True)
class PublicIngressFacts:
    has_public_address: bool | None
    public_ingress_ports: tuple[int, ...]
    has_ranged_public_ingress: bool | None
    public_ingress_port_ranges: tuple[str, ...] = ()


def derive_public_ingress_facts(
    instances: list[Instance],
    *,
    vnics_by_id: dict[str, Vnic],
    subnets_by_id: dict[str, Any],
    route_tables_by_id: dict[str, Any],
    security_lists_by_id: dict[str, Any],
    nsg_security_rules_by_nsg_id: dict[str, list[Any]],
    internet_gateway_ids: set[str],
    public_source_cidrs: tuple[str, ...],
) -> dict[str, PublicIngressFacts]:
    """Reports public-internet reachability with no administrative-ports policy applied. Returns a
    dict keyed by instance id, since these facts don't belong on the Instance model itself."""

    public_reference_networks = tuple(
        n for n in (_parse_network(c) for c in public_source_cidrs) if n is not None
    )
    return {
        instance.id: _derive_public_ingress_one(
            instance, vnics_by_id, subnets_by_id, route_tables_by_id,
            security_lists_by_id, nsg_security_rules_by_nsg_id,
            internet_gateway_ids, public_reference_networks,
        )
        for instance in instances
    }


def _derive_public_ingress_one(
    instance: Instance,
    vnics_by_id: dict[str, Vnic],
    subnets_by_id: dict[str, Any],
    route_tables_by_id: dict[str, Any],
    security_lists_by_id: dict[str, Any],
    nsg_security_rules_by_nsg_id: dict[str, list[Any]],
    internet_gateway_ids: set[str],
    public_reference_networks: tuple[_IpNetwork, ...],
) -> PublicIngressFacts:
    if not instance.vnic_ids:
        return PublicIngressFacts(
            has_public_address=None, public_ingress_ports=(), has_ranged_public_ingress=None
        )

    instance_vnics = [vnics_by_id[v] for v in instance.vnic_ids if v in vnics_by_id]
    if len(instance_vnics) != len(instance.vnic_ids):
        return PublicIngressFacts(
            has_public_address=None, public_ingress_ports=(), has_ranged_public_ingress=None
        )

    has_public_address = any(v.public_addresses for v in instance_vnics)
    if not has_public_address:
        return PublicIngressFacts(
            has_public_address=False, public_ingress_ports=(), has_ranged_public_ingress=False
        )

    public_vnics = [v for v in instance_vnics if v.public_addresses]
    route_evidence_complete = True
    ingress_evidence_complete = True
    has_igw_route = False
    named_ports: set[int] = set()
    ranges: set[tuple[int, int]] = set()

    for vnic in public_vnics:
        families = _address_families(vnic.public_addresses)
        subnet = subnets_by_id.get(vnic.subnet_id)
        if subnet is None:
            route_evidence_complete = False
            ingress_evidence_complete = False
            continue

        route_table_id = getattr(subnet, "route_table_id", None)
        route_table = route_tables_by_id.get(route_table_id) if route_table_id else None
        if route_table is None:
            route_evidence_complete = False
        elif _has_igw_route(
            getattr(route_table, "route_rules", None) or (), internet_gateway_ids, families
        ):
            has_igw_route = True

        for security_list_id in getattr(subnet, "security_list_ids", None) or ():
            security_list = security_lists_by_id.get(security_list_id)
            if security_list is None:
                ingress_evidence_complete = False
                continue
            ports, port_ranges, complete = _public_ingress_from_rules(
                getattr(security_list, "ingress_security_rules", None) or (),
                public_reference_networks=public_reference_networks,
                families=families,
            )
            named_ports |= ports
            ranges |= port_ranges
            ingress_evidence_complete = ingress_evidence_complete and complete

        for nsg_id in vnic.nsg_ids:
            if nsg_id not in nsg_security_rules_by_nsg_id:
                ingress_evidence_complete = False
                continue
            ports, port_ranges, complete = _public_ingress_from_rules(
                nsg_security_rules_by_nsg_id[nsg_id],
                public_reference_networks=public_reference_networks,
                families=families,
                is_ingress=lambda rule: getattr(rule, "direction", None) == "INGRESS",
            )
            named_ports |= ports
            ranges |= port_ranges
            ingress_evidence_complete = ingress_evidence_complete and complete

    range_labels = tuple(f"{low}-{high}" for low, high in sorted(ranges))

    if not route_evidence_complete or not ingress_evidence_complete:
        return PublicIngressFacts(
            has_public_address=True,
            public_ingress_ports=tuple(sorted(named_ports)),
            has_ranged_public_ingress=None,
            public_ingress_port_ranges=range_labels,
        )

    if not has_igw_route:
        return PublicIngressFacts(
            has_public_address=True, public_ingress_ports=(), has_ranged_public_ingress=False
        )

    return PublicIngressFacts(
        has_public_address=True,
        public_ingress_ports=tuple(sorted(named_ports)),
        has_ranged_public_ingress=bool(ranges),
        public_ingress_port_ranges=range_labels,
    )


