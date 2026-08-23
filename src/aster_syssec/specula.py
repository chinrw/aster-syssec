from __future__ import annotations

import hashlib
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import Track
from .handoff import HandoffPlan, preflight_contract, validate_specula_agent_config
from .provenance import file_sha256
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
) -> HandoffPlan:
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
    validate_specula_agent_config(config_path)

    snapshot = inspect_source(source_root)
    tracked_dirt = tuple(
        entry for entry in snapshot.dirty_entries if not entry.startswith("?? ")
    )
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
                artifact, export_metadata, created = _export_head(
                    source_root, run_root, snapshot.revision
                )
                export_paths.extend(created)
        else:
            blockers.append(
                "Asterinas is a linked worktree; Specula --keep-original requires a tracked-file-only "
                "exact-HEAD export. Re-run with --export-linked."
            )
    elif snapshot.revision is None:
        blockers.append("the authoritative Asterinas source has no Git revision")

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    source_identity = (snapshot.revision or snapshot.dirty_hash)[:12]
    run_token = hashlib.sha256(str(run_root.resolve()).encode("utf-8")).hexdigest()[:10]
    specula_run_id = run_id or (
        f"asterinas-syssec-{track.id}-{stage}-{source_identity}-{timestamp}-{run_token}"
    )
    argv = [
        "uv",
        "run",
        "--project",
        str(specula_repo),
        "specula",
        "run",
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
    nix_argv = ["nix", "shell", "nixpkgs#jdk21", "nixpkgs#maven", "--command", *argv]
    shell_command = shlex.join(nix_argv) if not blockers else None
    handoff = {
        "schema_version": 1,
        "kind": "specula",
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
            "agent_config_sha256": file_sha256(config_path),
            "guidance": str(guidance_path),
            "guidance_sha256": file_sha256(guidance_path),
            "target": track.target,
            "run_id": specula_run_id,
        },
        "direct_command": direct_command if not blockers else None,
        "nix_command": shell_command,
        "preflight": preflight_contract(
            checkouts={
                "asterinas-source": source_root,
                "specula": specula_repo,
                **({"asterinas-artifact": artifact} if not blockers else {}),
            },
            files=[config_path, guidance_path],
        ),
        "next_gate": (
            "Review modeling-brief.md, analysis-report.md, and review-analysis.md. "
            "Do not start spec generation until one shared state machine and a Linux-visible contract are approved."
        ),
    }
    return HandoffPlan(
        kind="specula",
        evidence=handoff,
        execution_command=shell_command,
        artifacts=tuple(export_paths),
        schema="specula-handoff.schema.json",
    )


def _export_head(
    source_root: Path, run_root: Path, revision: str
) -> tuple[Path, dict[str, Any], tuple[Path, ...]]:
    export_root = run_root / "specula/source-export"
    bundle = run_root / "specula/source.bundle"
    bundle.parent.mkdir(parents=True, exist_ok=True)
    _run_git(
        ["-C", str(source_root), "bundle", "create", str(bundle), "HEAD"],
        timeout=120,
    )
    _run_git(
        ["clone", "--no-local", "--no-checkout", str(bundle), str(export_root)],
        timeout=300,
    )
    _run_git(["-C", str(export_root), "checkout", "--detach", revision], timeout=120)
    observed = (
        _run_git(
            ["-C", str(export_root), "rev-parse", "HEAD"],
            timeout=30,
        )
        .stdout.decode("utf-8", "replace")
        .strip()
    )
    if observed != revision:
        raise ValueError(
            f"source export HEAD mismatch: expected {revision}, observed {observed}"
        )
    status = _run_git(
        ["-C", str(export_root), "status", "--porcelain=v1"],
        timeout=30,
    ).stdout
    if status:
        raise ValueError("source export working tree is not clean")
    if not (export_root / ".git").is_dir():
        raise ValueError("source export does not have an independent Git directory")
    alternates = export_root / ".git/objects/info/alternates"
    if alternates.exists():
        raise ValueError("source export unexpectedly uses shared Git object alternates")
    metadata = {
        "kind": "git-bundle-clone",
        "revision": revision,
        "bundle": str(bundle),
        "bundle_sha256": file_sha256(bundle),
        "history_available": True,
        "history_scope": "ancestors-of-exact-head",
        "independent_git_dir": True,
        "uses_object_alternates": False,
        "excluded_dirty_entries": list(inspect_source(source_root).dirty_entries),
    }
    return export_root, metadata, (bundle, export_root)


def _run_git(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.decode("utf-8", "replace").strip())
    return result
