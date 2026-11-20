"""A small JSON Schema (draft 2020-12 subset) validator for the shipped schemas/*.json.

It supports what those schemas use: $ref to #/$defs, type, const, enum, properties,
required, additionalProperties, items, minItems, minLength, minimum, pattern, oneOf,
allOf and if/then. An unsupported keyword fails loudly, so a schema can't silently
outgrow it. When the jsonschema package is installed, documents are checked with it too.
"""
import json
import re
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
SCHEMA_FILES = {
    "vcd-shadow-cleaner.scan/1": "scan-1.schema.json",
    "vcd-shadow-cleaner.plan/1": "plan-1.schema.json",
    "vcd-shadow-cleaner.discovery/1": "discovery-1.schema.json",
    "vcd-shadow-cleaner.profiles/1": "profiles-1.schema.json",
}
_IGNORED = {"$schema", "title", "description", "$defs", "$id"}
_SUPPORTED = {"$ref", "type", "const", "enum", "properties", "required", "additionalProperties",
              "items", "minItems", "minLength", "minimum", "pattern", "oneOf", "allOf", "if", "then"}


def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / SCHEMA_FILES[name]).read_text())


def _type_ok(value, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "null":
        return value is None
    raise AssertionError(f"unsupported type {t!r}")


def _errors(value, schema: dict, root: dict, path: str):
    unknown = set(schema) - _SUPPORTED - _IGNORED
    assert not unknown, f"schema keyword(s) {sorted(unknown)} at {path} not supported by schema_check"
    out = []
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/$defs/"), ref
        out += _errors(value, root["$defs"][ref[len("#/$defs/"):]], root, path)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, t) for t in types):
            return out + [f"{path}: {value!r:.80} is not of type {types}"]
    if "const" in schema and value != schema["const"]:
        out.append(f"{path}: {value!r:.80} != const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{path}: {value!r:.80} not in {schema['enum']}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            out.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and "minimum" in schema:
        if value < schema["minimum"]:
            out.append(f"{path}: {value} < {schema['minimum']}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in value:
                out.append(f"{path}: missing required {k!r}")
        for k, v in value.items():
            if k in props:
                out += _errors(v, props[k], root, f"{path}.{k}")
            else:
                ap = schema.get("additionalProperties", True)
                if ap is False:
                    out.append(f"{path}: unexpected property {k!r}")
                elif isinstance(ap, dict):
                    out += _errors(v, ap, root, f"{path}.{k}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            out.append(f"{path}: fewer than {schema['minItems']} items")
        if "items" in schema:
            for i, v in enumerate(value):
                out += _errors(v, schema["items"], root, f"{path}[{i}]")
    if "oneOf" in schema:
        n = sum(1 for s in schema["oneOf"] if not _errors(value, s, root, path))
        if n != 1:
            out.append(f"{path}: matches {n} of oneOf, expected 1")
    for s in schema.get("allOf", []):
        out += _errors(value, s, root, path)
    if "if" in schema and not _errors(value, schema["if"], root, path):
        out += _errors(value, schema.get("then", {}), root, path)
    return out


def validate(doc: dict, name: str = None) -> None:
    """Assert doc is valid against the schema its 'schema' field names (or name)."""
    name = name or doc.get("schema")
    assert name in SCHEMA_FILES, f"unknown schema {name!r}"
    schema = load_schema(name)
    errs = _errors(doc, schema, schema, "$")
    assert not errs, "schema violations:\n  " + "\n  ".join(errs)
    try:
        import jsonschema
    except ImportError:
        return
    jsonschema.Draft202012Validator(schema).validate(doc)
