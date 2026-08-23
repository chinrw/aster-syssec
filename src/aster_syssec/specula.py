from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Track
from .source import inspect_source


def prepare_handoff(
    *,
    source_root: Path,
    profile_root: Path,
    specula_repo: Path,
    track: Track,
    stage: str,
    run_root: Path,
    run_id: str | None = None,
    export_linked: bool = False,
) -> tuple[dict[str, Any], str | None, tuple[Path, ...]]:
    if stage not in {"dry-run", "analysis"}:
        raise ValueError("the first-version adapter only permits dry-run or analysis")
    source_root = source_root.resolve()
    profile_root = profile_root.resolve()
    specula_repo = specula_repo.resolve()
    config_path = profile_root / "specula-asterinas-hybrid.json"
    guidance_path = profile_root / track.guidance
    if not config_path.is_file():
        raise ValueError(f"Specula agent config does not exist: {config_path}")
    if not guidance_path.is_file():
        raise ValueError(f"track guidance does not exist: {guidance_path}")
    if not (specula_repo / "pyproject.toml").is_file():
        raise ValueError(f"Specula checkout is missing pyproject.toml: {specula_repo}")
    _validate_agent_config(config_path)

    snapshot = inspect_source(source_root)
    tracked_dirt = tuple(entry for entry in snapshot.dirty_entries if not entry.startswith("?? "))
    artifact = source_root
    export_paths: list[Path] = []
    blockers: list[str] = []
    export_metadata: dict[str, Any] | None = None
    if snapshot.git_dir_kind == "file":
        if export_linked:
            if tracked_dirt:
                blockers.append(
                    "linked-worktree export was not created because tracked changes would be omitted: "
                    + ", ".join(tracked_dirt)
                )
            elif snapshot.revision is None:
                blockers.append("linked-worktree export requires a Git revision")
            else:
                artifact, export_metadata, created = _export_head(source_root, run_root, snapshot.revision)
                export_paths.extend(created)
        else:
            blockers.append(
                "Asterinas is a linked worktree; Specula --keep-original requires a tracked-file-only "
                "exact-HEAD export. Re-run with --export-linked."
            )
    elif snapshot.revision is None:
        blockers.append("the authoritative Asterinas source has no Git revision")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    specula_run_id = run_id or f"asterinas-syssec-{track.id}-{stage}-{timestamp}"
    argv = [
        "uv", "run", "--project", str(specula_repo), "specula", "run",
        "--keep-original",
        f"--agent-config={config_path}",
        f"--artifact={artifact}",
        f"--guidance={guidance_path}",
        "--enable-reviews",
        "--confirm-debate",
        "--max-parallel=1",
        "--max-turns=0",
        "--policy-retries=2",
        "--transient-resumes=20",
        f"--run-id={specula_run_id}",
    ]
    if stage == "dry-run":
        argv.append("--dry-run")
    else:
        argv.extend(
            [
                "--skip-specgen",
                "--skip-harness",
                "--skip-validate",
                "--skip-confirmation",
                "--skip-classification",
                "--skip-repair-loop",
            ]
        )
    argv.append(track.target)
    direct_command = shlex.join(argv)
    nix_argv = [
        "nix", "shell", "nixpkgs#jdk21", "nixpkgs#maven", "--command", *argv
    ]
    shell_command = shlex.join(nix_argv) if not blockers else None
    handoff = {
        "schema_version": 1,
        "ready": not blockers,
        "blockers": blockers,
        "stage": stage,
        "track": track.id,
        "specula_readiness": track.specula_readiness,
        "requires_human_gate_after_stage": True,
        "source": snapshot.to_dict(),
        "artifact": str(artifact),
        "source_export": export_metadata,
        "execution_identity": {
            "source_revision": snapshot.revision,
            "source_dirty_hash": snapshot.dirty_hash,
            "agent_config": str(config_path),
            "agent_config_sha256": _sha256(config_path),
            "guidance": str(guidance_path),
            "guidance_sha256": _sha256(guidance_path),
            "target": track.target,
            "run_id": specula_run_id,
        },
        "direct_command": direct_command if not blockers else None,
        "nix_command": shell_command,
        "next_gate": (
            "Review modeling-brief.md, analysis-report.md, and review-analysis.md. "
            "Do not start spec generation until one shared state machine and a Linux-visible contract are approved."
        ),
    }
    return handoff, shell_command, tuple(export_paths)


def _validate_agent_config(path: Path) -> None:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if parsed.get("version") != 1:
        raise ValueError("Specula agent config version must be 1")
    profiles = parsed.get("profiles")
    default = parsed.get("default_profile")
    if not isinstance(profiles, dict) or default not in profiles:
        raise ValueError("Specula agent config has an unresolved default_profile")
    allowed_phases = {
        "analyze", "specgen", "harness", "validate", "confirm", "repair", "classify", "review"
    }
    unknown = set(parsed.get("phases", {})) - allowed_phases
    if unknown:
        raise ValueError(f"Specula agent config has unknown phase keys: {sorted(unknown)}")
    unresolved = set(parsed.get("phases", {}).values()) - set(profiles)
    if unresolved:
        raise ValueError(f"Specula agent config references missing profiles: {sorted(unresolved)}")


def _export_head(source_root: Path, run_root: Path, revision: str) -> tuple[Path, dict[str, Any], tuple[Path, ...]]:
    export_root = run_root / "specula/source-export"
    archive = run_root / "specula/source-export.tar"
    export_root.mkdir(parents=True, exist_ok=False)
    archive.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "-C", str(source_root), "archive", "--format=tar", "--output", str(archive), revision],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.decode("utf-8", "replace").strip())
    with tarfile.open(archive, mode="r:") as tar:
        _safe_extract(tar, export_root)
    metadata = {
        "kind": "git-archive",
        "revision": revision,
        "archive": str(archive),
        "archive_sha256": _sha256(archive),
        "excluded_dirty_entries": list(inspect_source(source_root).dirty_entries),
    }
    return export_root, metadata, (archive, export_root)


def _safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in tar.getmembers():
        target = (destination / member.name).resolve()
        try:
            target.relative_to(destination)
        except ValueError as error:
            raise ValueError(f"unsafe path in git archive: {member.name}") from error
        if member.issym():
            if Path(member.linkname).is_absolute():
                raise ValueError(f"unsafe absolute symlink in git archive: {member.name}")
            link_target = (target.parent / member.linkname).resolve()
            try:
                link_target.relative_to(destination)
            except ValueError as error:
                raise ValueError(f"unsafe symlink in git archive: {member.name}") from error
        elif not (member.isfile() or member.isdir()):
            raise ValueError(f"unsupported member in git archive: {member.name}")
    tar.extractall(destination)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
