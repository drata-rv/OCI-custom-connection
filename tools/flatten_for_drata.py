"""Flattens src/oci_drata/schemas/oci-snapshot-1.0.0.json into the shape Drata's Custom
Connection "JSON Schema" importer actually accepts.

Confirmed dialect (two independent sources):
  1. Drata's own documented example: type/properties/items/additionalProperties (bool)
     only -- no $ref, no definitions, no minLength/maxLength/pattern/enum/format, no
     type arrays for nullable fields.
  2. Empirically: Drata's own "Sample JSON Data" auto-generator, run against
     tests/fixtures/sample-record.json on a live customer call, never emitted "required"
     or "title", and rendered every integer value as "number" (no "integer" type).
Both independently omit "required" and "title" and use "number" for all numerics --
so this converter drops "required"/"title" and maps integer -> number rather than
guess they're supported.

This does NOT replace src/oci_drata/schemas/oci-snapshot-1.0.0.json -- that file stays
the full Draft-07 schema used by validation/schema.py (jsonschema library, full spec
support). This is a Drata-import-only derivative.
"""

import json
import sys

SRC = "/Users/rodv/Desktop/OCI/src/oci_drata/schemas/oci-snapshot-1.0.0.json"
OUT = "/Users/rodv/Desktop/OCI/schemas/oci-snapshot-drata-import.json"

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
            # Every one of Drata's documented examples, and its own sample-data
            # generator, use additionalProperties only as a plain boolean. Nested
            # boolean is the same construct one level deeper -- low risk.
            out["additionalProperties"] = ap
        # else: ap is a schema object -- the OCI "tags" free-form key/value map shape
        # (definedTags/freeformTags). Drata has zero documented support for
        # additionalProperties-as-schema (a dynamic-key map); every example and the
        # sample-data generator use boolean only. Rather than guess, drop the
        # constraint and leave a bare object so the field still imports -- Drata just
        # won't validate its nested keys.

    # "required" (unsupported -- Drata's own generator never emits it, no documented
    # example shows it) and anything else (minLength/maxLength/pattern/enum/format/
    # description/$id/$schema/...) is deliberately dropped.

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
