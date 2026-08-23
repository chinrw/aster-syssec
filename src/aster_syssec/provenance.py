from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import __version__
from .schemas import schema_set_sha256
from .source import inspect_source


def reviewer_identity() -> dict[str, Any]:
    package_root = Path(__file__).resolve().parent
    project_root = _project_root(package_root)
    source = (
        inspect_source(project_root).to_dict() if project_root is not None else None
    )
    installed_lock = _installed_data_file("flake.lock")
    build_revision = os.environ.get("SYSSEC_BUILD_REVISION")
    git_source = source if source and source["git_dir_kind"] != "absent" else None
    return {
        "version": __version__,
        "git_commit": git_source["revision"]
        if git_source
        else _normalize_build_revision(build_revision),
        "dirty_hash": git_source["dirty_hash"] if git_source else None,
        "content_sha256": _content_hash(package_root),
        "rules_sha256": _file_hash(package_root / "scanner.py"),
        "schemas_sha256": schema_set_sha256(),
        "flake_lock_sha256": (
            _file_hash(project_root / "flake.lock")
            if project_root is not None and (project_root / "flake.lock").is_file()
            else _file_hash(installed_lock)
            if installed_lock is not None
            else None
        ),
        "source": source,
    }


def file_sha256(path: Path) -> str:
    return _file_hash(Path(path))


def _project_root(package_root: Path) -> Path | None:
    candidates: list[Path] = []
    configured = os.environ.get("SYSSEC_SOURCE_ROOT")
    if configured:
        candidates.append(Path(configured).expanduser().resolve())
    candidates.append(package_root.parents[1])
    for candidate in candidates:
        if (candidate / "pyproject.toml").is_file() and (
            candidate / "src/aster_syssec"
        ).is_dir():
            return candidate
    return None


def _installed_data_file(name: str) -> Path | None:
    from .schemas import schema_directory

    candidate = schema_directory().parent / name
    return candidate if candidate.is_file() else None


def _normalize_build_revision(value: str | None) -> str | None:
    if not value or value == "unknown":
        return None
    return value.removesuffix("-dirty")


def _content_hash(package_root: Path) -> str:
    files = sorted(
        path
        for path in package_root.rglob("*")
        if path.is_file() and path.suffix in {".py", ".toml"}
    )
    return _hash_files(package_root, files)


def _hash_files(root: Path, paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
