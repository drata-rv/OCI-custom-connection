"""Flattens src/oci_drata/schemas/oci-snapshot-1.0.0.json into the shape Drata's Custom
Connection "JSON Schema" importer accepts: type/properties/items/additionalProperties
(bool) only -- no $ref, no definitions, no minLength/maxLength/pattern/enum/format/
required/title, and every integer rendered as "number".

This does NOT replace src/oci_drata/schemas/oci-snapshot-1.0.0.json -- that file stays
the full Draft-07 schema used by validation/schema.py. This is a Drata-import-only
derivative.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "oci_drata" / "schemas" / "oci-snapshot-1.0.0.json"
OUT = REPO_ROOT / "schemas" / "oci-snapshot-drata-import.json"

ALLOWED_KEYS = {"type", "properties", "items", "additionalProperties"}
TYPE_MAP = {"integer": "number"}


def resolve(node, definitions, seen):
    if isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        assert ref.startswith("#/definitions/"), f"unsupported $ref shape: {ref}"
        name = ref[len("#/definitions/") :]
        if name in seen:
            raise ValueError(f"cycle detected resolving {name}")
        target = definitions[name]
        return resolve(target, definitions, seen | {name})

    if not isinstance(node, dict):
        return node

    out = {}

    node_type = node.get("type")
    if isinstance(node_type, list):
        # Collapse a nullable type array (["string", "null"]) to its non-null member --
        # Drata's importer wants a single scalar type, not a union.
        non_null = [t for t in node_type if t != "null"]
        node_type = non_null[0] if non_null else "string"
    if node_type is not None:
        out["type"] = TYPE_MAP.get(node_type, node_type)

    if "properties" in node:
        out["properties"] = {
            key: resolve(value, definitions, seen) for key, value in node["properties"].items()
        }
    if "items" in node:
        out["items"] = resolve(node["items"], definitions, seen)
    if "additionalProperties" in node:
        ap = node["additionalProperties"]
        if isinstance(ap, bool):
            out["additionalProperties"] = ap
        # else: a schema object (OCI's free-form tags map) -- Drata's importer has no
        # documented support for additionalProperties-as-schema, so it's dropped and
        # the field imports as an unvalidated bare object.

    # Everything not in ALLOWED_KEYS (required, minLength/maxLength/pattern/enum/
    # format/description/$id/$schema/...) is deliberately dropped.

    return out


def main():
    with open(SRC) as f:
        schema = json.load(f)

    definitions = schema.get("definitions", {})
    flat = resolve(schema, definitions, seen=frozenset())

    with open(OUT, "w") as f:
        json.dump(flat, f, indent=2)
        f.write("\n")

    # Sanity: valid JSON, round-trips, no $ref/definitions/title/required/etc left.
    text = json.dumps(flat)
    for forbidden in (
        "$ref", "definitions", "minLength", "maxLength", "pattern",
        "\"enum\"", "\"format\"", "\"title\"", "\"required\"", "\"integer\"",
    ):
        if forbidden in text:
            print(f"FAIL: {forbidden!r} still present in output", file=sys.stderr)
            sys.exit(1)

    print(f"wrote {OUT}")
    print(f"size: {len(text)} bytes, {text.count(chr(10)) + 1} lines (pretty-printed)")
    print(f"top-level properties: {list(flat['properties'].keys())}")


if __name__ == "__main__":
    main()
