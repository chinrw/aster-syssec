from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .runs import verify_run_manifest
from .schemas import validate_instance
from .source import atomic_write_json

DEFAULT_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_FILES = 5_000


def pack_evidence(
    work_root: Path,
    output: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    work_root = Path(work_root).resolve()
    output_path = Path(os.path.abspath(Path(output).expanduser()))
    _require_no_symlink_components(output_path)
    output = output_path.resolve()
    if not work_root.is_dir():
        raise ValueError(f"evidence work root does not exist: {work_root}")
    if max_bytes < 1 or max_files < 1:
        raise ValueError("evidence pack limits must be positive")
    if (
        work_root == output
        or output.is_relative_to(work_root)
        or work_root.is_relative_to(output)
    ):
        raise ValueError("evidence work root and pack output must not overlap")
    if output.exists():
        raise ValueError(f"evidence pack output already exists: {output}")

    manifest_paths = sorted((work_root / "runs").rglob("run-manifest.json"))
    if not manifest_paths:
        raise ValueError(f"no run manifests found below: {work_root}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}.", dir=output.parent
    ) as temporary:
        stage = Path(temporary) / "pack"
        stage.mkdir()
        file_records: dict[str, dict[str, Any]] = {}
        manifest_records: list[dict[str, Any]] = []

        for manifest_path in manifest_paths:
            if manifest_path.is_symlink():
                raise ValueError(f"run manifest must not be a symlink: {manifest_path}")
            manifest = verify_run_manifest(manifest_path)
            if manifest["status"] == "running":
                raise ValueError(f"run manifest is still running: {manifest_path}")
            manifest_relative = manifest_path.relative_to(work_root)
            _copy_file(
                manifest_path,
                stage / manifest_relative,
                relative=manifest_relative,
                kind="manifest",
                run_id=str(manifest["run_id"]),
                records=file_records,
            )
            manifest_records.append(
                {
                    "path": manifest_relative.as_posix(),
                    "run_id": manifest["run_id"],
                    "status": manifest["status"],
                    "sha256": file_records[manifest_relative.as_posix()]["sha256"],
                }
            )
            for artifact in manifest["outputs"]:
                artifact_relative = manifest_relative.parent / artifact["path"]
                _copy_artifact(
                    manifest_path.parent / artifact["path"],
                    stage / artifact_relative,
                    relative=artifact_relative,
                    run_id=str(manifest["run_id"]),
                    records=file_records,
                )
            copied_manifest = stage / manifest_relative
            if json.loads(copied_manifest.read_text(encoding="utf-8")) != manifest:
                raise ValueError(f"run manifest changed while packing: {manifest_path}")
            verify_run_manifest(copied_manifest)

        files = [file_records[path] for path in sorted(file_records)]
        content_sha256 = _content_sha256(files)
        index = {
            "schema_version": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "content_sha256": content_sha256,
            "manifests": manifest_records,
            "files": files,
            "limits": {"max_bytes": max_bytes, "max_files": max_files},
        }
        validate_instance(index, "evidence-pack.schema.json")
        index_path = atomic_write_json(stage / "evidence-pack.json", index)
        packed_files = len(files) + 1
        packed_bytes = (
            sum(int(item["size"]) for item in files) + index_path.stat().st_size
        )
        if packed_files > max_files:
            raise ValueError(
                f"evidence pack exceeds file budget: {packed_files} > {max_files}"
            )
        if packed_bytes > max_bytes:
            raise ValueError(
                f"evidence pack exceeds byte budget: {packed_bytes} > {max_bytes}"
            )
        stage.replace(output)

    return {
        "output": str(output),
        "manifests": len(manifest_records),
        "files": packed_files,
        "bytes": packed_bytes,
        "content_sha256": content_sha256,
    }


def _require_no_symlink_components(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError(f"evidence pack output must not be a symlink: {candidate}")


def _copy_artifact(
    source: Path,
    destination: Path,
    *,
    relative: Path,
    run_id: str,
    records: dict[str, dict[str, Any]],
) -> None:
    if source.is_symlink():
        raise ValueError(f"evidence artifact must not be a symlink: {source}")
    if source.is_file():
        _copy_file(
            source,
            destination,
            relative=relative,
            kind="artifact",
            run_id=run_id,
            records=records,
        )
        return
    if not source.is_dir():
        raise ValueError(f"evidence artifact does not exist: {source}")
    destination.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.rglob("*")):
        item_relative = item.relative_to(source)
        if item.is_symlink():
            raise ValueError(f"evidence artifact must not contain symlinks: {item}")
        if item.is_dir():
            (destination / item_relative).mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            _copy_file(
                item,
                destination / item_relative,
                relative=relative / item_relative,
                kind="artifact",
                run_id=run_id,
                records=records,
            )


def _copy_file(
    source: Path,
    destination: Path,
    *,
    relative: Path,
    kind: str,
    run_id: str,
    records: dict[str, dict[str, Any]],
) -> None:
    key = relative.as_posix()
    if key in records:
        raise ValueError(f"duplicate evidence pack path: {key}")
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"evidence pack source must be a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    payload = destination.read_bytes()
    records[key] = {
        "path": key,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "kind": kind,
        "run_id": run_id,
    }


def _content_sha256(files: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for item in files:
        digest.update(str(item["path"]).encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(str(item["sha256"])))
        digest.update(b"\0")
        digest.update(str(item["size"]).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()
