from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SourceSnapshot:
    path: str
    revision: str | None
    branch: str | None
    dirty_hash: str
    dirty_entries: tuple[str, ...]
    git_dir_kind: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _git(
    root: Path, *args: str, check: bool = False
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=check,
        capture_output=True,
        timeout=30,
    )


def inspect_source(root: Path) -> SourceSnapshot:
    root = root.resolve()
    top_level = _git(root, "rev-parse", "--show-toplevel")
    repository_root = (
        Path(top_level.stdout.decode("utf-8", "replace").strip()).resolve()
        if top_level.returncode == 0
        else None
    )
    is_repository_root = repository_root == root
    if is_repository_root:
        revision_result = _git(root, "rev-parse", "HEAD")
        revision = (
            revision_result.stdout.decode("utf-8", "replace").strip()
            if revision_result.returncode == 0
            else None
        )
        branch_result = _git(root, "branch", "--show-current")
        branch = (
            branch_result.stdout.decode("utf-8", "replace").strip() or None
            if branch_result.returncode == 0
            else None
        )
        status_result = _git(
            root, "status", "--porcelain=v1", "-z", "--untracked-files=all"
        )
        status_bytes = (
            status_result.stdout
            if status_result.returncode == 0
            else b"git-status-failed"
        )
        entries = tuple(
            entry.decode("utf-8", "surrogateescape")
            for entry in status_bytes.split(b"\0")
            if entry
        )
    else:
        revision = None
        branch = None
        status_bytes = b"not-a-git-repository"
        entries = ()

    digest = hashlib.sha256()
    digest.update(status_bytes)
    if revision is not None:
        diff = _git(root, "diff", "--binary", "HEAD")
        if diff.returncode == 0:
            digest.update(diff.stdout)
        for entry in entries:
            if not entry.startswith("?? "):
                continue
            relative = entry[3:]
            candidate = root / relative
            if candidate.is_file():
                digest.update(relative.encode("utf-8", "surrogateescape"))
                digest.update(hashlib.sha256(candidate.read_bytes()).digest())
    else:
        _hash_source_tree(root, digest)

    git_marker = root / ".git"
    if git_marker.is_dir():
        git_kind = "directory"
    elif git_marker.is_file():
        git_kind = "file"
    else:
        git_kind = "absent"
    return SourceSnapshot(
        path=str(root),
        revision=revision,
        branch=branch,
        dirty_hash=digest.hexdigest(),
        dirty_entries=entries,
        git_dir_kind=git_kind,
    )


def ensure_asterinas_checkout(root: Path) -> None:
    required = (
        "kernel/core/src/syscall/mod.rs",
        "kernel/core/src/syscall/arch/x86.rs",
        "kernel/core/src/syscall/arch/generic.rs",
        "rust-toolchain.toml",
    )
    missing = [relative for relative in required if not (root / relative).is_file()]
    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"not a supported Asterinas checkout; missing: {joined}")


def require_disjoint_paths(source_root: Path, work_root: Path) -> None:
    source = Path(source_root).resolve()
    work = Path(work_root).resolve()
    if source == work or work.is_relative_to(source) or source.is_relative_to(work):
        raise ValueError("Asterinas checkout and SYSSEC_WORK_ROOT must not overlap")


def atomic_write_json(path: Path, value: Any) -> Path:
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return atomic_write_text(path, payload)


def atomic_write_text(path: Path, payload: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return path


def relative_paths(root: Path, paths: Iterable[Path]) -> tuple[str, ...]:
    resolved_root = root.resolve()
    result: list[str] = []
    for path in paths:
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(resolved_root)
        except ValueError as error:
            raise ValueError(f"path is outside Asterinas checkout: {path}") from error
        result.append(relative.as_posix())
    return tuple(result)


def _hash_source_tree(root: Path, digest: Any) -> None:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            payload = os.readlink(path).encode("utf-8", "surrogateescape")
            kind = b"symlink"
        elif path.is_file():
            payload = path.read_bytes()
            kind = b"file"
        else:
            continue
        digest.update(kind)
        digest.update(b"\0")
        digest.update(relative.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
