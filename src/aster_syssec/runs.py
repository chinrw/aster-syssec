from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import __version__
from .config import Registry
from .provenance import reviewer_identity
from .schemas import load_schema, schema_name_for_id, validate_instance
from .source import (
    atomic_write_json,
    atomic_write_text,
    inspect_source,
    require_disjoint_paths,
)


@dataclass
class RunContext:
    root: Path
    manifest_path: Path
    manifest: dict[str, Any]
    _artifacts: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    _artifact_schemas: dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def start(
        cls,
        *,
        work_root: Path,
        command: str,
        source_root: Path,
        registry: Registry,
        parameters: dict[str, Any],
    ) -> RunContext:
        require_disjoint_paths(source_root, work_root)
        snapshot = inspect_source(source_root)
        now = datetime.now(UTC)
        revision = (snapshot.revision or "working-tree")[:12]
        run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{command}-{uuid4().hex[:8]}"
        root = Path(work_root).resolve() / "runs" / revision / run_id
        root.mkdir(parents=True, exist_ok=False)
        manifest = {
            "schema_version": 2,
            "run_id": run_id,
            "command": command,
            "started_at": now.isoformat(),
            "finished_at": None,
            "status": "running",
            "source": snapshot.to_dict(),
            "reviewer": reviewer_identity(),
            "configuration_hash": registry.config_hash,
            "tool_versions": {
                "aster-syssec": __version__,
                "python": platform.python_version(),
                "platform": sys.platform,
                "git": _command_version("git", "--version"),
                "uv": _command_version("uv", "--version"),
                "asterinas_rust_toolchain": _rust_toolchain(source_root),
            },
            "parameters": parameters,
            "outputs": [],
            "error": None,
        }
        validate_instance(manifest, "run-manifest.schema.json")
        manifest_path = root / "run-manifest.json"
        atomic_write_json(manifest_path, manifest)
        return cls(root=root, manifest_path=manifest_path, manifest=manifest)

    def write_json(
        self, relative: str, value: Any, *, schema: str | None = None
    ) -> Path:
        self._require_running()
        document = validate_instance(value, schema) if schema is not None else None
        path = self._output_path(relative)
        atomic_write_json(path, value)
        self._register(
            path,
            media_type="application/json",
            schema_name=document.name if document else None,
            schema_id=document.id if document else None,
            schema_sha256=document.sha256 if document else None,
        )
        return path

    def write_text(
        self,
        relative: str,
        value: str,
        *,
        media_type: str = "text/plain; charset=utf-8",
    ) -> Path:
        self._require_running()
        path = self._output_path(relative)
        atomic_write_text(path, value)
        self._register(path, media_type=media_type)
        return path

    def register_artifact(self, path: Path, *, media_type: str | None = None) -> Path:
        self._require_running()
        resolved = Path(path).resolve()
        self._relative_output(resolved)
        self._register(resolved, media_type=media_type or _media_type(resolved))
        return resolved

    def register_json_artifact(self, path: Path, *, schema: str) -> Path:
        self._require_running()
        resolved = Path(path).resolve()
        self._relative_output(resolved)
        try:
            value = json.loads(resolved.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ValueError(
                f"external JSON artifact is invalid: {resolved}"
            ) from error
        document = validate_instance(value, schema)
        self._register(
            resolved,
            media_type="application/json",
            schema_name=document.name,
            schema_id=document.id,
            schema_sha256=document.sha256,
        )
        return resolved

    def artifact_record(self, relative: str) -> dict[str, Any]:
        self._require_running()
        normalized = self._relative_output(self._output_path(relative))
        try:
            return dict(self._artifacts[normalized])
        except KeyError as error:
            raise ValueError(f"run artifact is not registered: {normalized}") from error

    def complete(self, outputs: Iterable[Path] = ()) -> None:
        self._require_running()
        self._verify_source()
        self._register_outputs(outputs)
        records = self._verified_artifacts()
        self.manifest["finished_at"] = datetime.now(UTC).isoformat()
        self.manifest["status"] = "completed"
        self.manifest["outputs"] = records
        validate_instance(self.manifest, "run-manifest.schema.json")
        atomic_write_json(self.manifest_path, self.manifest)

    def fail(self, error: BaseException, outputs: Iterable[Path] = ()) -> None:
        self._require_running()
        self._register_outputs(outputs)
        self.manifest["finished_at"] = datetime.now(UTC).isoformat()
        self.manifest["status"] = "failed"
        self.manifest["outputs"] = [
            dict(record, integrity="unverified") for record in self._artifacts.values()
        ]
        self.manifest["error"] = f"{type(error).__name__}: {error}"
        validate_instance(self.manifest, "run-manifest.schema.json")
        atomic_write_json(self.manifest_path, self.manifest)

    def _register_outputs(self, outputs: Iterable[Path]) -> None:
        for path in outputs:
            resolved = Path(path).resolve()
            relative = self._relative_output(resolved)
            if relative not in self._artifacts:
                self._register(resolved, media_type=_media_type(resolved))

    def _register(
        self,
        path: Path,
        *,
        media_type: str,
        schema_name: str | None = None,
        schema_id: str | None = None,
        schema_sha256: str | None = None,
    ) -> None:
        relative = self._relative_output(path)
        if relative in self._artifacts:
            raise ValueError(f"run artifact is already registered: {relative}")
        sha256, size = _measure(path)
        record: dict[str, Any] = {
            "path": relative,
            "sha256": sha256,
            "size": size,
            "media_type": media_type,
        }
        if schema_name is not None:
            record["schema"] = schema_id
            record["schema_sha256"] = schema_sha256
            self._artifact_schemas[relative] = schema_name
        self._artifacts[relative] = record

    def _verified_artifacts(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for relative, registered in self._artifacts.items():
            path = self.root / relative
            sha256, size = _measure(path)
            if sha256 != registered["sha256"] or size != registered["size"]:
                raise ValueError(f"run artifact changed after registration: {relative}")
            schema = self._artifact_schemas.get(relative)
            if schema is not None:
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"registered JSON artifact is no longer valid: {relative}"
                    ) from error
                validate_instance(value, schema)
            records.append(dict(registered, integrity="verified"))
        return records

    def _output_path(self, relative: str) -> Path:
        raw = Path(relative)
        if raw.is_absolute() or ".." in raw.parts or not raw.parts:
            raise ValueError(f"run output must be relative: {relative}")
        return self.root / raw

    def _relative_output(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError as error:
            raise ValueError(f"run artifact is outside the run root: {path}") from error

    def _require_running(self) -> None:
        status = self.manifest["status"]
        if status != "running":
            raise ValueError(f"run is already {status}")

    def _verify_source(self) -> None:
        expected = self.manifest["source"]
        observed = inspect_source(Path(expected["path"]))
        if (
            observed.revision != expected["revision"]
            or observed.dirty_hash != expected["dirty_hash"]
        ):
            raise ValueError("Asterinas source changed during run")


def _command_version(command: str, flag: str) -> str | None:
    executable = shutil.which(command)
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, flag],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", "replace").strip()


def _rust_toolchain(source_root: Path) -> str | None:
    path = Path(source_root) / "rust-toolchain.toml"
    if not path.is_file():
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))["toolchain"]["channel"]
    except (KeyError, tomllib.TOMLDecodeError):
        return None


def _measure(path: Path) -> tuple[str, int]:
    if path.is_symlink():
        raise ValueError(f"run artifact must not be a symlink: {path}")
    if path.is_file():
        payload = path.read_bytes()
        return hashlib.sha256(payload).hexdigest(), len(payload)
    if not path.is_dir():
        raise ValueError(f"run artifact does not exist: {path}")
    digest = hashlib.sha256()
    size = 0
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path).as_posix()
        if item.is_symlink():
            payload = os.readlink(item).encode("utf-8", "surrogateescape")
            kind = b"symlink"
        elif item.is_file():
            payload = item.read_bytes()
            kind = b"file"
        else:
            continue
        digest.update(kind)
        digest.update(b"\0")
        digest.update(relative.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        size += len(payload)
    return digest.hexdigest(), size


def _media_type(path: Path) -> str:
    if path.is_dir():
        return "inode/directory"
    return {
        ".json": "application/json",
        ".md": "text/markdown; charset=utf-8",
        ".sh": "text/x-shellscript; charset=utf-8",
        ".tar": "application/x-tar",
    }.get(path.suffix, "application/octet-stream")


def verify_run_manifest(manifest_path: Path) -> dict[str, Any]:
    manifest_path = Path(manifest_path).resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid run manifest: {error}") from error
    validate_instance(manifest, "run-manifest.schema.json")
    run_root = manifest_path.parent
    for record in manifest["outputs"]:
        raw = Path(record["path"])
        if raw.is_absolute() or ".." in raw.parts:
            raise ValueError(f"invalid artifact path in run manifest: {raw}")
        path = (run_root / raw).resolve()
        try:
            path.relative_to(run_root)
        except ValueError as error:
            raise ValueError(f"artifact escapes run root: {raw}") from error
        sha256, size = _measure(path)
        if sha256 != record["sha256"] or size != record["size"]:
            raise ValueError(f"artifact hash or size mismatch: {raw}")
        schema_id = record.get("schema")
        if schema_id is None:
            continue
        schema_name = schema_name_for_id(schema_id)
        document = load_schema(schema_name)
        if document.sha256 != record.get("schema_sha256"):
            raise ValueError(f"artifact schema hash mismatch: {raw}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid JSON artifact: {raw}") from error
        validate_instance(value, schema_name)
    return manifest
