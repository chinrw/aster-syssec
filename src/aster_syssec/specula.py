from __future__ import annotations

import hashlib
import shlex
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import Track
from .handoff import HandoffPlan, preflight_contract, specula_agent_selection
from .provenance import file_sha256, locked_nixpkgs_reference
from .source import inspect_source
from .specula_gates import STAGE_GATES, STAGE_REQUIRED_APPROVALS, copy_gate_inputs

STAGE_PHASES = {
    "dry-run": "analyze",
    "analysis": "analyze",
    "specgen": "specgen",
    "harness": "harness",
    "validate": "validate",
}


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
    gate_approval: Path | None = None,
) -> HandoffPlan:
    if stage not in STAGE_PHASES:
        raise ValueError(f"unsupported Specula stage: {stage}")
    source_root = source_root.resolve()
    profile_root = profile_root.resolve()
    specula_repo = specula_repo.resolve()
    run_root = run_root.resolve()
    config_path = profile_root / "specula-asterinas-hybrid.json"
    guidance_path = profile_root / track.guidance
    if not config_path.is_file():
        raise ValueError(f"Specula agent config does not exist: {config_path}")
    if not guidance_path.is_file():
        raise ValueError(f"track guidance does not exist: {guidance_path}")
    if not (specula_repo / "pyproject.toml").is_file():
        raise ValueError(f"Specula checkout is missing pyproject.toml: {specula_repo}")

    phase = STAGE_PHASES[stage]
    selection = specula_agent_selection(config_path, phase)
    snapshot = inspect_source(source_root)
    tracked_dirt = tuple(
        entry for entry in snapshot.dirty_entries if not entry.startswith("?? ")
    )
    blockers: list[str] = []
    if snapshot.git_dir_kind == "file" and not export_linked:
        blockers.append(
            "Asterinas is a linked worktree; an exact-HEAD independent export requires --export-linked."
        )
    if snapshot.revision is None:
        blockers.append("the authoritative Asterinas source has no Git revision")
    if tracked_dirt:
        blockers.append(
            "exact-HEAD Specula export excludes tracked working-tree changes: "
            + ", ".join(tracked_dirt)
        )

    required_approval = STAGE_REQUIRED_APPROVALS.get(stage)
    if required_approval is None and gate_approval is not None:
        raise ValueError(f"Specula {stage} does not consume a gate approval")
    if required_approval is not None and gate_approval is None:
        blockers.append(
            f"Specula {stage} requires an approved {required_approval} gate"
        )

    workspace = run_root / "specula/workspace"
    workspace.mkdir(parents=True, exist_ok=False)
    shutil.copy2(guidance_path, workspace / ".prompt-extra.md")

    artifact = source_root
    export_paths: list[Path] = []
    export_metadata: dict[str, Any] | None = None
    if not blockers:
        assert snapshot.revision is not None
        artifact, export_metadata, created = _export_head(
            source_root, run_root, snapshot.revision
        )
        export_paths.extend(created)

    approval_summary: dict[str, Any] | None = None
    phase_inputs: list[dict[str, Any]] = []
    if not blockers and gate_approval is not None:
        assert required_approval is not None
        approval_summary, phase_inputs = copy_gate_inputs(
            approval_path=gate_approval,
            expected_gate=required_approval,
            expected_track=track.id,
            source=snapshot,
            destination=workspace / ".specula-output",
        )
        approval_copy = run_root / "specula/approved-inputs/gate-approval.json"
        approval_copy.parent.mkdir(parents=True, exist_ok=False)
        shutil.copy2(gate_approval, approval_copy)
        export_paths.append(approval_copy)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    source_identity = (snapshot.revision or snapshot.dirty_hash)[:12]
    run_token = hashlib.sha256(str(run_root).encode("utf-8")).hexdigest()[:10]
    specula_run_id = run_id or (
        f"asterinas-syssec-{track.id}-{stage}-{source_identity}-{timestamp}-{run_token}"
    )
    phase_target = track.target if phase == "analyze" else track.target.split("|", 1)[0]
    nixpkgs_reference = locked_nixpkgs_reference()
    argv = [
        "uv",
        "run",
        "--project",
        str(specula_repo),
        "specula",
        phase,
        "--max-parallel=1",
        "--max-turns=0",
        "--policy-retries=2",
        "--transient-resumes=20",
        f"--agent={selection['agent']}",
        f"--model={selection['model']}",
        f"--effort={selection['effort']}",
        f"--artifact={artifact}",
    ]
    if stage == "dry-run":
        argv.append("--dry-run")
    argv.append(phase_target)
    nix_argv = [
        "nix",
        "shell",
        f"{nixpkgs_reference}#jdk21",
        f"{nixpkgs_reference}#maven",
        "--command",
        *argv,
    ]
    direct_command = shlex.join(argv) if not blockers else None
    nix_command = shlex.join(nix_argv) if not blockers else None
    shell_command = (
        f"cd {shlex.quote(str(workspace))}\n{nix_command}"
        if nix_command is not None
        else None
    )
    handoff = {
        "schema_version": 2,
        "kind": "specula",
        "ready": not blockers,
        "blockers": blockers,
        "stage": stage,
        "phase": phase,
        "safety_class": "model",
        "track": track.id,
        "specula_readiness": track.specula_readiness,
        "requires_human_gate_after_stage": stage != "dry-run",
        "source": snapshot.to_dict(),
        "artifact": str(artifact),
        "artifact_initial": inspect_source(artifact).to_dict(),
        "source_export": export_metadata,
        "workspace": str(workspace),
        "phase_inputs": phase_inputs,
        "gate_approval": approval_summary,
        "execution_identity": {
            "source_revision": snapshot.revision,
            "source_dirty_hash": snapshot.dirty_hash,
            "agent_config": str(config_path),
            "agent_config_sha256": file_sha256(config_path),
            "guidance": str(guidance_path),
            "guidance_sha256": file_sha256(guidance_path),
            "target": track.target,
            "phase_target": phase_target,
            "run_id": specula_run_id,
        },
        "phase_command": (
            {
                "argv": argv,
                "nix_argv": nix_argv,
                "cwd": str(workspace),
                "nixpkgs_reference": nixpkgs_reference,
                "agent_selection": selection,
            }
            if not blockers
            else None
        ),
        "direct_command": direct_command,
        "nix_command": nix_command,
        "preflight": preflight_contract(
            checkouts={
                "asterinas-source": source_root,
                "specula": specula_repo,
            },
            files=[config_path, guidance_path],
        ),
        "next_gate": None if stage == "dry-run" else STAGE_GATES[stage],
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
    # The phase may instrument the checkout, so only the immutable bundle is evidence.
    return export_root, metadata, (bundle,)


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
