from __future__ import annotations

from types import SimpleNamespace

import pytest

from oci_drata.security import GuardedOciClient, OciOperationNotAllowedError


class _FakeOciClient:
    """Stands in for a raw OCI SDK client -- callable list_*/get_* methods, a mutation
    method a dynamic/aliased call might resolve to, and a plain non-operation attribute."""

    def list_instances(self, **kwargs):
        return ["instance-1"]

    def get_vnic(self, **kwargs):
        return SimpleNamespace(id="v1")

    def list_something_not_in_the_allowlist(self, **kwargs):
        return []

    def create_instance(self, **kwargs):
        return "should never run"

    def terminate_db_system(self, **kwargs):
        return "should never run"

    def get_windows_instance_initial_credentials(self, **kwargs):
        return "should never run"

    base_client = "not an operation, passes through untouched"


@pytest.fixture
def guarded() -> GuardedOciClient:
    return GuardedOciClient(_FakeOciClient())


def test_allowed_list_operation_passes_through(guarded: GuardedOciClient) -> None:
    assert guarded.list_instances() == ["instance-1"]


def test_allowed_get_operation_passes_through(guarded: GuardedOciClient) -> None:
    assert guarded.get_vnic().id == "v1"


def test_list_operation_not_in_allowlist_is_blocked(guarded: GuardedOciClient) -> None:
    with pytest.raises(OciOperationNotAllowedError, match="list_something_not_in_the_allowlist"):
        guarded.list_something_not_in_the_allowlist()


def test_mutation_operation_is_blocked_even_though_not_list_or_get_shaped(
    guarded: GuardedOciClient,
) -> None:
    """The exact gap a dynamically-resolved or aliased call could otherwise slip
    through: create_/terminate_*-shaped names aren't list_*/get_*, so they must be
    checked independently of that prefix filter, not only alongside it."""

    with pytest.raises(OciOperationNotAllowedError, match="create_instance"):
        guarded.create_instance()
    with pytest.raises(OciOperationNotAllowedError, match="terminate_db_system"):
        guarded.terminate_db_system()


def test_forbidden_exact_name_operation_is_blocked(guarded: GuardedOciClient) -> None:
    with pytest.raises(OciOperationNotAllowedError, match="get_windows_instance_initial_credentials"):
        guarded.get_windows_instance_initial_credentials()


def test_dynamically_resolved_call_is_still_guarded(guarded: GuardedOciClient) -> None:
    """The actual threat model: a name built at runtime (alias, config-driven dispatch)
    rather than a literal `client.create_instance(...)` call site the AST scan would
    have caught statically."""

    operation_name = "".join(["create", "_", "instance"])
    with pytest.raises(OciOperationNotAllowedError):
        getattr(guarded, operation_name)()


def test_non_operation_attribute_passes_through_untouched(guarded: GuardedOciClient) -> None:
    assert guarded.base_client == "not an operation, passes through untouched"


def test_setattr_is_refused() -> None:
    guarded = GuardedOciClient(_FakeOciClient())
    with pytest.raises(OciOperationNotAllowedError):
        guarded.some_field = "value"
