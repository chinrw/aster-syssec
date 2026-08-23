from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable

from .config import Registry, require_tracks
from .models import Catalog


def select_review_paths(
    source_root: Path,
    registry: Registry,
    catalog: Catalog,
    *,
    track_ids: Iterable[str] = (),
    requested_paths: Iterable[str] = (),
    changed_from: str | None = None,
) -> tuple[Path, ...]:
    source_root = source_root.resolve()
    selected: set[Path] = set()
    track_ids = tuple(track_ids)
    requested_paths = tuple(requested_paths)

    for raw in requested_paths:
        candidate = (source_root / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
        _ensure_inside(source_root, candidate)
        _add_rust_paths(candidate, selected)

    if track_ids:
        tracks = require_tracks(registry, track_ids)
        syscall_names = {name for track in tracks for name in track.syscalls}
        for item in catalog.syscalls:
            if item.name in syscall_names and item.handler_path:
                path = source_root / item.handler_path
                if path.is_file():
                    selected.add(path.resolve())
        for track in tracks:
            for raw in track.source_roots:
                candidate = source_root / raw
                if candidate.exists():
                    _add_rust_paths(candidate, selected)

    if changed_from:
        for relative in _git_changed_paths(source_root, changed_from):
            candidate = source_root / relative
            if candidate.is_file() and candidate.suffix == ".rs":
                selected.add(candidate.resolve())

    if not selected and not (requested_paths or track_ids or changed_from):
        _add_rust_paths(source_root / "kernel/core/src/syscall", selected)

    return tuple(sorted(selected))


def _add_rust_paths(path: Path, selected: set[Path]) -> None:
    if path.is_file() and path.suffix == ".rs":
        selected.add(path.resolve())
    elif path.is_dir():
        selected.update(item.resolve() for item in path.rglob("*.rs") if item.is_file())


def _ensure_inside(root: Path, path: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"review path is outside Asterinas checkout: {path}") from error


def _git_changed_paths(root: Path, base: str) -> tuple[str, ...]:
    commands = (
        ("diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"),
        ("diff", "--name-only", "--diff-filter=ACMR"),
        ("diff", "--cached", "--name-only", "--diff-filter=ACMR"),
    )
    paths: set[str] = set()
    for index, args in enumerate(commands):
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if result.returncode != 0:
            if index == 0:
                message = result.stderr.decode("utf-8", "replace").strip()
                raise ValueError(f"cannot resolve changed-from {base!r}: {message}")
            continue
        paths.update(
            line
            for line in result.stdout.decode("utf-8", "surrogateescape").splitlines()
            if line
        )
    return tuple(sorted(paths))
