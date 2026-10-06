"""Normalizes raw OCI SDK objects into the source-fact models exposure derivation joins over.
Cross-resource joins (Windows classification, VNIC attachment, public addresses) run
afterward in relationships; exposure derivation after that."""

from __future__ import annotations

import datetime
from typing import Any

from oci_drata.models import Instance, Vnic


def normalize_timestamp(value: datetime.datetime | str | None) -> str | None:
    """Normalizes to UTC RFC3339, second precision, Z-suffixed. Re-normalizes
    string input rather than trusting it verbatim."""

    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError(f"naive datetime cannot be normalized to UTC RFC3339: {value!r}")
    return value.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _region(raw: Any) -> str:
    region = getattr(raw, "region", None)
    if not region:
        raise ValueError(f"raw object {raw!r} was not region-stamped before normalization")
    return region


def normalize_instance(raw: Any) -> Instance:
    """Copies only what the flat record and exposure derivation read. osClassification and
    vnic_ids are filled in later by transform.relationships."""

    return Instance(
        id=raw.id,
        region=_region(raw),
        compartment_id=raw.compartment_id,
        display_name=getattr(raw, "display_name", None),
        image_id=getattr(raw, "image_id", None),
    )


def normalize_vnic(raw: Any) -> Vnic:
    """subnet_id required, raises if absent. public_addresses filled in later by
    transform.relationships (a VNIC carries only its primary address)."""

    subnet_id = getattr(raw, "subnet_id", None)
    if not subnet_id:
        raise ValueError(f"VNIC {raw.id} has no subnet_id; exposure derivation requires one")
    return Vnic(id=raw.id, subnet_id=subnet_id, nsg_ids=tuple(getattr(raw, "nsg_ids", None) or ()))


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
