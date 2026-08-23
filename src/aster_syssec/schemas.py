from __future__ import annotations

import hashlib
import json
import os
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from referencing import Registry as ReferenceRegistry
from referencing import Resource


@dataclass(frozen=True)
class SchemaDocument:
    name: str
    id: str
    sha256: str
    value: dict[str, Any]


def load_schema(name: str) -> SchemaDocument:
    if Path(name).name != name or not name.endswith(".schema.json"):
        raise ValueError(f"invalid schema name: {name!r}")
    path = schema_directory() / name
    if not path.is_file():
        raise ValueError(f"unknown evidence schema: {name}")
    payload = path.read_bytes()
    try:
        value = json.loads(payload)
        Draft202012Validator.check_schema(value)
    except (json.JSONDecodeError, SchemaError) as error:
        raise ValueError(f"invalid evidence schema {name}: {error}") from error
    schema_id = value.get("$id")
    if not isinstance(schema_id, str) or not schema_id:
        raise ValueError(f"evidence schema {name} has no $id")
    return SchemaDocument(
        name=name,
        id=schema_id,
        sha256=hashlib.sha256(payload).hexdigest(),
        value=value,
    )


def validate_instance(value: Any, name: str) -> SchemaDocument:
    document = load_schema(name)
    validator = Draft202012Validator(
        document.value,
        format_checker=FormatChecker(),
        registry=_reference_registry(),
    )
    try:
        instance = json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"{name} instance is not JSON-serializable: {error}"
        ) from error
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda item: tuple(str(part) for part in item.path),
    )
    if errors:
        error = errors[0]
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        raise ValueError(f"{name} instance {location or '/'}: {error.message}")
    return document


def schema_set_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted(schema_directory().glob("*.schema.json")):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def schema_name_for_id(schema_id: str) -> str:
    for path in sorted(schema_directory().glob("*.schema.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("$id") == schema_id:
            return path.name
    raise ValueError(f"unknown evidence schema id: {schema_id}")


def _reference_registry() -> ReferenceRegistry:
    registry = ReferenceRegistry()
    for path in sorted(schema_directory().glob("*.schema.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        schema_id = value.get("$id")
        if isinstance(schema_id, str) and schema_id:
            registry = registry.with_resource(schema_id, Resource.from_contents(value))
    return registry


def schema_directory() -> Path:
    override = os.environ.get("SYSSEC_SCHEMA_ROOT")
    if override:
        path = Path(override).expanduser().resolve()
        if path.is_dir():
            return path

    module = Path(__file__).resolve()
    candidates = [
        module.parents[2] / "schemas",
        Path(sysconfig.get_path("data")) / "share/aster-syssec/schemas",
        Path(sys.argv[0]).resolve().parent.parent / "share/aster-syssec/schemas",
    ]
    candidates.extend(
        parent / "share/aster-syssec/schemas" for parent in module.parents
    )
    for candidate in candidates:
        if (candidate / "run-manifest.schema.json").is_file():
            return candidate
    raise ValueError("cannot locate aster-syssec evidence schemas")
