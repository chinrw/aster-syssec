from __future__ import annotations

import shlex
import subprocess
from collections.abc import Iterable
from pathlib import Path

from .handoff import HandoffPlan, preflight_contract
from .provenance import file_sha256
from .source import inspect_source


def prepare_aster_code_review(
    *,
    source_root: Path,
    run_root: Path,
    agent_profile: str,
    per_persona_context: str,
    base: str | None = None,
    paths: Iterable[str] = (),
) -> HandoffPlan:
    source_root = source_root.resolve()
    paths = tuple(paths)
    if (base is None) == (not paths):
        raise ValueError(
            "agent review requires exactly one of --base or one or more --path values"
        )
    if per_persona_context not in {"auto", "yes", "no"}:
        raise ValueError("per-persona-context must be auto, yes, or no")
    skill_root = source_root / ".agents/skills/aster-code-review"
    launcher = skill_root / "aster_code_review.sh"
    skill = skill_root / "SKILL.md"
    profile_root = skill_root / "agent_profiles" / agent_profile
    if not launcher.is_file() or not skill.is_file():
        raise ValueError(
            "the Asterinas checkout does not contain the aster-code-review skill"
        )
    if not profile_root.is_dir():
        choices = sorted(
            path.name
            for path in (skill_root / "agent_profiles").iterdir()
            if path.is_dir()
        )
        raise ValueError(
            f"unknown Asterinas review profile {agent_profile!r}; choose one of: {choices}"
        )

    output = run_root / "agent-review/review.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    snapshot = inspect_source(source_root)
    base_revision: str | None = None
    target_files: list[Path] = []
    if base is not None:
        resolved = subprocess.run(
            ["git", "-C", str(source_root), "merge-base", base, "HEAD"],
            check=False,
            capture_output=True,
            timeout=30,
        )
        if resolved.returncode != 0:
            detail = resolved.stderr.decode("utf-8", "replace").strip()
            raise ValueError(f"cannot resolve agent-review base {base!r}: {detail}")
        mode = "diff"
        base_revision = resolved.stdout.decode("utf-8", "replace").strip()
        target_args = [base_revision]
    else:
        mode = "files"
        target_args = [_validate_target(source_root, raw) for raw in paths]
        target_files = [_target_path(source_root, raw) for raw in target_args]
    argv = [
        str(launcher),
        mode,
        *target_args,
        str(output),
        f"--per-persona-context={per_persona_context}",
    ]
    command = "\n".join(
        (
            f"cd {shlex.quote(str(source_root))}",
            f"export ACR_AGENT_PROFILE={shlex.quote(agent_profile)}",
            f"exec {shlex.join(argv)}",
        )
    )
    profile_files = sorted(path for path in profile_root.rglob("*") if path.is_file())
    handoff = {
        "schema_version": 1,
        "kind": "aster-code-review",
        "ready": True,
        "mode": mode,
        "base": base,
        "base_revision": base_revision,
        "head_revision": snapshot.revision,
        "paths": list(target_args) if mode == "files" else [],
        "output": str(output),
        "source": snapshot.to_dict(),
        "skill": str(skill),
        "skill_sha256": file_sha256(skill),
        "launcher": str(launcher),
        "launcher_sha256": file_sha256(launcher),
        "agent_profile": agent_profile,
        "profile_files": {
            path.relative_to(profile_root).as_posix(): file_sha256(path)
            for path in profile_files
        },
        "per_persona_context": per_persona_context,
        "executes_agents": True,
        "executed_by_syssec": False,
        "execution_command": command,
        "preflight": preflight_contract(
            checkouts={"asterinas": source_root},
            files=[skill, launcher, *profile_files, *target_files],
        ),
    }
    return HandoffPlan(
        kind="aster-code-review",
        evidence=handoff,
        execution_command=command,
        artifacts=(),
        schema="agent-review-handoff.schema.json",
    )


def _validate_target(root: Path, raw: str) -> str:
    path_part = raw
    if ":" in raw:
        possible_path, possible_range = raw.rsplit(":", 1)
        if possible_range and all(
            char.isdigit() or char in "-," for char in possible_range
        ):
            path_part = possible_path
    path = (root / path_part).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError(
            f"agent-review path is outside Asterinas checkout: {raw}"
        ) from error
    if not path.is_file():
        raise ValueError(f"agent-review target is not a file: {raw}")
    if path_part != relative.as_posix():
        raise ValueError(f"agent-review target must be checkout-relative: {raw}")
    return raw


def _target_path(root: Path, raw: str) -> Path:
    path_part = raw
    if ":" in raw:
        possible_path, possible_range = raw.rsplit(":", 1)
        if possible_range and all(
            char.isdigit() or char in "-," for char in possible_range
        ):
            path_part = possible_path
    return (root / path_part).resolve()
