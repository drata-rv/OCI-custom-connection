"""Static enforcement of the read-only, least-privilege posture: every OCI
client method referenced anywhere under src/oci_drata/collection must be in
security.ALLOWED_OCI_OPERATIONS and must not match a forbidden name/prefix.
A collector cannot silently grow a mutating or secret-retrieving call --
this test fails the build the moment one is added, without needing live
OCI credentials.
"""

from __future__ import annotations

import ast
import glob
from pathlib import Path

import pytest

from oci_drata.security import (
    ALLOWED_OCI_OPERATIONS,
    FORBIDDEN_OPERATIONS,
    is_allowed_operation,
    is_forbidden_operation,
)

COLLECTION_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "oci_drata" / "collection"


def _oci_shaped_attribute_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    return {a for a in attrs if a.startswith(("list_", "get_"))}


def _collection_files() -> list[Path]:
    return [Path(p) for p in sorted(glob.glob(str(COLLECTION_DIR / "*.py")))]


@pytest.mark.parametrize("path", _collection_files(), ids=lambda p: p.name)
def test_every_referenced_operation_is_allowlisted(path: Path) -> None:
    referenced = _oci_shaped_attribute_names(path)
    not_allowed = {name for name in referenced if not is_allowed_operation(name)}
    assert not not_allowed, f"{path.name} references non-allowlisted operations: {not_allowed}"


@pytest.mark.parametrize("path", _collection_files(), ids=lambda p: p.name)
def test_no_forbidden_operation_referenced(path: Path) -> None:
    referenced = _oci_shaped_attribute_names(path)
    forbidden = {name for name in referenced if is_forbidden_operation(name)}
    assert not forbidden, f"{path.name} references forbidden operations: {forbidden}"


@pytest.mark.parametrize("path", _collection_files(), ids=lambda p: p.name)
def test_no_secret_or_credential_operation_referenced(path: Path) -> None:
    text = path.read_text()
    for needle in ("shared_secret", "device_config", "initial_credentials", "wallet"):
        assert needle not in text, f"{path.name} references forbidden term {needle!r}"


def test_forbidden_operations_are_not_accidentally_allowlisted() -> None:
    assert ALLOWED_OCI_OPERATIONS.isdisjoint(FORBIDDEN_OPERATIONS)
