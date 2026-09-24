"""Excludes TERMINATED/TERMINATING resources from evidence; always report the excluded
count via a Message in resources.warnings, never drop it silently. Exclusion cascades to
correlated children (exclude_lifecycle_cascade) so an excluded parent's children go too.
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


def exclude_lifecycle_cascade(
    items: list[T], *, parent_excluded_ids: set[str], parent_id_field: str | None
) -> tuple[list[T], list[T]]:
    """split_by_lifecycle() plus cascading exclusion: an item is also excluded if
    parent_id_field references an excluded parent id, even when its own lifecycle_state
    isn't terminal. parent_id_field=None skips the cascade (same as split_by_lifecycle)."""

    kept, excluded = split_by_lifecycle(items)
    if parent_id_field is None or not parent_excluded_ids:
        return kept, excluded

    still_kept: list[T] = []
    excluded_by_parent: list[T] = []
    for item in kept:
        if getattr(item, parent_id_field, None) in parent_excluded_ids:
            excluded_by_parent.append(item)
        else:
            still_kept.append(item)
    return still_kept, [*excluded, *excluded_by_parent]
