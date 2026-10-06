"""The read-only, least-privilege guarantee, enforced statically: every OCI operation named
anywhere under src/oci_drata/collection must be allowlisted, none may be forbidden or
secret-bearing, and the allowlist may not grant anything no collector calls."""

from __future__ import annotations

import ast
from pathlib import Path

from oci_drata.security import (
    ALLOWED_OCI_OPERATIONS,
    FORBIDDEN_OPERATIONS,
    is_allowed_operation,
    is_forbidden_operation,
)

COLLECTION_DIR = Path(__file__).resolve().parents[2] / "src" / "oci_drata" / "collection"
COLLECTION_FILES = sorted(COLLECTION_DIR.glob("*.py"))


def _operation_names(path: Path) -> set[str]:
    """Operations named as an attribute (client.list_x) or as the string label passed to paginate()."""

    tree = ast.parse(path.read_text())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    return {name for name in names if name.startswith(("list_", "get_"))}


def test_allowlist_matches_exactly_the_operations_collectors_reference_and_none_forbidden() -> None:
    assert COLLECTION_FILES
    problems = []
    referenced: set[str] = set()
    for path in COLLECTION_FILES:
        for name in sorted(_operation_names(path)):
            referenced.add(name)
            if not is_allowed_operation(name):
                problems.append(f"{path.name}: {name} is not allowlisted")
            if is_forbidden_operation(name):
                problems.append(f"{path.name}: {name} is forbidden")
    problems += [f"{name} is allowlisted but no collector calls it" for name in sorted(ALLOWED_OCI_OPERATIONS - referenced)]
    assert not problems, problems


def test_no_secret_or_credential_terms_in_collectors() -> None:
    for path in COLLECTION_FILES:
        text = path.read_text()
        for needle in ("shared_secret", "device_config", "initial_credentials", "wallet"):
            assert needle not in text, f"{path.name} references forbidden term {needle!r}"


def test_forbidden_operations_are_not_accidentally_allowlisted() -> None:
    assert ALLOWED_OCI_OPERATIONS.isdisjoint(FORBIDDEN_OPERATIONS)
