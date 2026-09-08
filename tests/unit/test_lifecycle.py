from __future__ import annotations

from types import SimpleNamespace

from oci_drata.transform.lifecycle import exclude_referencing, split_by_lifecycle


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
