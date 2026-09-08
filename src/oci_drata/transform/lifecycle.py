"""Excludes resources whose lifecycle_state means they no longer meaningfully exist
(TERMINATED/TERMINATING) from evidence. Never silently -- callers must report the
excluded count via a Message in resources.warnings, not just drop the count.

Scoped to resource types with no downstream unresolved-relationship tracking that
excluding an item could falsely trip (a terminated instance's own vnic/volume
attachments must be excluded alongside it, or resolve_instance_network_and_storage
would report them as pointing at a "missing" instance). Compute instances and volumes
are covered; db systems/databases/autonomous databases/VPN resources are not -- their
parent/child relationship resolution would need the same correlated exclusion, not
done here.
"""

from __future__ import annotations

from typing import Any, TypeVar

TERMINAL_LIFECYCLE_STATES = frozenset({"TERMINATED", "TERMINATING"})

T = TypeVar("T")


def split_by_lifecycle(
    items: list[T], *, exclude_states: frozenset[str] = TERMINAL_LIFECYCLE_STATES
) -> tuple[list[T], list[T]]:
    """Returns (kept, excluded). An item with no lifecycle_state field/value is kept --
    absence isn't proof of termination."""

    kept: list[T] = []
    excluded: list[T] = []
    for item in items:
        state = getattr(item, "lifecycle_state", None)
        if state in exclude_states:
            excluded.append(item)
        else:
            kept.append(item)
    return kept, excluded


def exclude_referencing(
    attachments: list[Any], *, excluded_ids: set[str], id_field: str
) -> list[Any]:
    """Drops any attachment/reference object whose id_field names an excluded resource,
    so a terminated instance's own vnic/volume attachments don't surface as unresolved
    relationships pointing at a "missing" instance."""

    return [a for a in attachments if getattr(a, id_field, None) not in excluded_ids]
