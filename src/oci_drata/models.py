"""Source-fact models for the resources the public-ingress derivation joins over (instance,
vnic). Derivation logic lives in oci_drata.transform."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Instance:
    id: str
    region: str
    compartment_id: str
    display_name: str | None
    image_id: str | None = None
    os_classification: str = "unknown"  # windows | non_windows | unknown
    vnic_ids: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Vnic:
    id: str
    subnet_id: str
    nsg_ids: tuple[str, ...] = ()
    public_addresses: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class UnresolvedRelationship:
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    reason: str
