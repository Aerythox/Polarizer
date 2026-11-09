"""Reads the operations Polarizer needs from an OpenAPI 3 spec."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
PATH_PARAM = re.compile(r"\{([^}/]+)\}")
MAX_REF_DEPTH = 20


class SpecError(Exception):
    pass


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    requires_auth: bool
    # Top-level fields of the JSON request body and of the first 2xx response.
    request_fields: dict[str, dict] = field(default_factory=dict)
    response_fields: dict[str, dict] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def path_params(self) -> list[str]:
        return PATH_PARAM.findall(self.path)


def load_operations(path: str | Path) -> list[Operation]:
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SpecError(f"Could not read the spec at {path}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        raise SpecError(f"{path} does not look like an OpenAPI spec: it has no paths.")

    default_security = doc.get("security", [])
    operations = []
    for route, item in doc["paths"].items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            operations.append(
                Operation(
                    method=method.upper(),
                    path=route,
                    requires_auth=_requires_auth(op.get("security", default_security)),
                    request_fields=_fields(doc, _json_schema(doc, op.get("requestBody"))),
                    response_fields=_fields(doc, _success_schema(doc, op.get("responses") or {})),
                )
            )
    return operations


def _requires_auth(security: Any) -> bool:
    # [] means public, and [{}] means authentication is optional.
    return isinstance(security, list) and any(bool(requirement) for requirement in security)


def _json_schema(doc: dict, holder: Any) -> Any:
    holder = resolve(doc, holder)
    if not isinstance(holder, dict):
        return None
    schema = ((holder.get("content") or {}).get("application/json") or {}).get("schema")
    return resolve(doc, schema)


def _success_schema(doc: dict, responses: dict) -> Any:
    for code in sorted(responses, key=str):
        if str(code).startswith("2"):
            return _json_schema(doc, responses[code])
    return None


def _fields(doc: dict, schema: Any) -> dict[str, dict]:
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return {}
    properties = schema.get("properties") or {}
    return {name: resolve(doc, prop) or {} for name, prop in properties.items()}


def resolve(doc: dict, node: Any, depth: int = 0) -> Any:
    """Follows local $ref pointers such as #/components/schemas/User."""
    if not (isinstance(node, dict) and "$ref" in node):
        return node
    if depth > MAX_REF_DEPTH:
        raise SpecError("A $ref chain in the spec is too deep or circular.")

    ref = node["$ref"]
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise SpecError(f"Only local $ref values are supported, not {ref!r}.")
    target: Any = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            raise SpecError(f"The spec has an unresolved $ref: {ref}")
        target = target[part]
    return resolve(doc, target, depth + 1)
