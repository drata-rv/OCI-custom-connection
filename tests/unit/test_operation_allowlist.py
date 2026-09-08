"""Fails if any OCI operation referenced under src/oci_drata/collection is
missing from ALLOWED_OCI_OPERATIONS or matches a forbidden name/prefix."""

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
