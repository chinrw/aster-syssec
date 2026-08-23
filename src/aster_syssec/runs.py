from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from . import __version__
from .config import Registry
from .source import atomic_write_json, inspect_source


@dataclass
class RunContext:
    root: Path
    manifest_path: Path
    manifest: dict[str, Any]

    @classmethod
    def start(
        cls,
        *,
        work_root: Path,
        command: str,
        source_root: Path,
        registry: Registry,
        parameters: dict[str, Any],
    ) -> "RunContext":
        snapshot = inspect_source(source_root)
        now = datetime.now(timezone.utc)
        revision = (snapshot.revision or "working-tree")[:12]
        run_id = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{command}-{uuid4().hex[:8]}"
        root = Path(work_root).resolve() / "runs" / revision / run_id
        root.mkdir(parents=True, exist_ok=False)
        manifest = {
            "schema_version": 1,
            "run_id": run_id,
            "command": command,
            "started_at": now.isoformat(),
            "finished_at": None,
            "status": "running",
            "source": snapshot.to_dict(),
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
        manifest_path = root / "run-manifest.json"
        atomic_write_json(manifest_path, manifest)
        return cls(root=root, manifest_path=manifest_path, manifest=manifest)

    def write_json(self, relative: str, value: Any) -> Path:
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError(f"run output must be relative: {relative}")
        return atomic_write_json(self.root / relative, value)

    def write_text(self, relative: str, value: str) -> Path:
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError(f"run output must be relative: {relative}")
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def complete(self, outputs: Iterable[Path]) -> None:
        self.manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        self.manifest["status"] = "completed"
        self.manifest["outputs"] = [path.relative_to(self.root).as_posix() for path in outputs]
        atomic_write_json(self.manifest_path, self.manifest)

    def fail(self, error: BaseException, outputs: Iterable[Path] = ()) -> None:
        self.manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        self.manifest["status"] = "failed"
        self.manifest["outputs"] = [path.relative_to(self.root).as_posix() for path in outputs]
        self.manifest["error"] = f"{type(error).__name__}: {error}"
        atomic_write_json(self.manifest_path, self.manifest)


def _command_version(command: str, flag: str) -> str | None:
    executable = shutil.which(command)
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, flag],
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
