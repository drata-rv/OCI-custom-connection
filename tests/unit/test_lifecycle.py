from __future__ import annotations

from types import SimpleNamespace

from oci_drata.transform.lifecycle import (
    exclude_lifecycle_cascade,
    exclude_referencing,
    split_by_lifecycle,
)


def _resource(id_: str, lifecycle_state: str | None) -> SimpleNamespace:
    return SimpleNamespace(id=id_, lifecycle_state=lifecycle_state)


def test_split_by_lifecycle_excludes_terminated_and_terminating() -> None:
    items = [
        _resource("running", "RUNNING"),
        _resource("stopped", "STOPPED"),  # still a real resource -- kept, not excluded
        _resource("terminated", "TERMINATED"),
        _resource("terminating", "TERMINATING"),
    ]
    kept, excluded = split_by_lifecycle(items)
    assert [i.id for i in kept] == ["running", "stopped"]
    assert [i.id for i in excluded] == ["terminated", "terminating"]


def test_split_by_lifecycle_missing_state_is_kept_not_excluded() -> None:
    """Absence of lifecycle_state isn't proof of termination -- e.g. a resource type this
    filter isn't applied to, or a raw object missing the field for another reason."""

    kept, excluded = split_by_lifecycle([_resource("x", None)])
    assert [i.id for i in kept] == ["x"]
    assert excluded == []


def test_exclude_referencing_drops_attachments_to_excluded_ids() -> None:
    attachments = [
        SimpleNamespace(instance_id="i1"),
        SimpleNamespace(instance_id="i2"),
        SimpleNamespace(instance_id="i3"),
    ]
    kept = exclude_referencing(attachments, excluded_ids={"i2"}, id_field="instance_id")
    assert [a.instance_id for a in kept] == ["i1", "i3"]


def _child(id_: str, parent_id: str, lifecycle_state: str = "AVAILABLE") -> SimpleNamespace:
    return SimpleNamespace(id=id_, lifecycle_state=lifecycle_state, db_system_id=parent_id)


def test_exclude_lifecycle_cascade_excludes_child_of_excluded_parent() -> None:
    """A db_home whose db_system_id references an already-terminated db_system must be
    excluded too, even though the db_home's own lifecycle_state is AVAILABLE -- otherwise
    it surfaces as a database resource whose parent db_system silently doesn't exist,
    an unresolved relationship, instead of correctly reflecting the whole lineage is gone."""

    children = [_child("home1", parent_id="sys1"), _child("home2", parent_id="sys2")]
    kept, excluded = exclude_lifecycle_cascade(
        children, parent_excluded_ids={"sys1"}, parent_id_field="db_system_id"
    )
    assert [c.id for c in kept] == ["home2"]
    assert [c.id for c in excluded] == ["home1"]


def test_exclude_lifecycle_cascade_still_excludes_by_own_lifecycle() -> None:
    children = [_child("home1", parent_id="sys-ok", lifecycle_state="TERMINATED")]
    kept, excluded = exclude_lifecycle_cascade(
        children, parent_excluded_ids=set(), parent_id_field="db_system_id"
    )
    assert kept == []
    assert [c.id for c in excluded] == ["home1"]


def test_exclude_lifecycle_cascade_no_parent_field_behaves_like_split_by_lifecycle() -> None:
    items = [SimpleNamespace(id="a", lifecycle_state="TERMINATED"), SimpleNamespace(id="b", lifecycle_state="AVAILABLE")]
    kept, excluded = exclude_lifecycle_cascade(items, parent_excluded_ids=set(), parent_id_field=None)
    assert [i.id for i in kept] == ["b"]
    assert [i.id for i in excluded] == ["a"]


def test_exclude_lifecycle_cascade_multi_level() -> None:
    """Mirrors the real db_system -> db_home -> database chain: excluding at the top
    must propagate all the way down without each level needing bespoke logic."""

    db_systems = [SimpleNamespace(id="sys1", lifecycle_state="TERMINATED")]
    kept_sys, excluded_sys = exclude_lifecycle_cascade(
        db_systems, parent_excluded_ids=set(), parent_id_field=None
    )
    excluded_sys_ids = {s.id for s in excluded_sys}

    db_homes = [_child("home1", parent_id="sys1")]
    kept_homes, excluded_homes = exclude_lifecycle_cascade(
        db_homes, parent_excluded_ids=excluded_sys_ids, parent_id_field="db_system_id"
    )
    excluded_home_ids = {h.id for h in excluded_homes}
    assert excluded_home_ids == {"home1"}

    databases = [SimpleNamespace(id="db1", lifecycle_state="AVAILABLE", db_home_id="home1")]
    kept_dbs, excluded_dbs = exclude_lifecycle_cascade(
        databases, parent_excluded_ids=excluded_home_ids, parent_id_field="db_home_id"
    )
    assert kept_dbs == []
    assert [d.id for d in excluded_dbs] == ["db1"]
