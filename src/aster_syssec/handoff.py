from __future__ import annotations

import json
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .provenance import file_sha256, reviewer_identity
from .source import inspect_source

SPECULA_PHASES = frozenset(
    {
        "analyze",
        "specgen",
        "harness",
        "validate",
        "confirm",
        "repair",
        "classify",
        "review",
    }
)


@dataclass(frozen=True)
class HandoffPlan:
    kind: str
    evidence: dict[str, Any]
    execution_command: str | None
    artifacts: tuple[Path, ...]
    schema: str

    def command_with_preflight(self, handoff_path: Path) -> str | None:
        if self.execution_command is None:
            return None
        preflight = _preflight_command(Path(handoff_path).resolve())
        return f"{preflight}\n{self.execution_command}"


def _preflight_command(handoff_path: Path) -> str:
    reviewer = reviewer_identity()
    source = reviewer.get("source")
    if isinstance(source, dict) and isinstance(source.get("path"), str):
        source_path = Path(source["path"]) / "src"
        argv = [
            sys.executable,
            "-m",
            "aster_syssec",
            "verify-handoff",
            "--handoff",
            str(handoff_path),
        ]
        return f"PYTHONPATH={shlex.quote(str(source_path))} {shlex.join(argv)}"

    entrypoint = Path(sys.argv[0]).resolve()
    if not entrypoint.is_file():
        raise ValueError("cannot pin the installed aster-syssec preflight executable")
    return shlex.join(
        [str(entrypoint), "verify-handoff", "--handoff", str(handoff_path)]
    )


def validate_specula_agent_config(path: Path) -> None:
    parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    allowed_keys = {"version", "default_profile", "profiles", "phases"}
    unknown_keys = set(parsed) - allowed_keys
    if unknown_keys:
        raise ValueError(
            f"Specula agent config has unknown keys: {sorted(unknown_keys)}"
        )
    if parsed.get("version") != 1:
        raise ValueError("Specula agent config version must be 1")
    profiles = parsed.get("profiles")
    default = parsed.get("default_profile")
    if not isinstance(profiles, dict) or default not in profiles:
        raise ValueError("Specula agent config has an unresolved default_profile")
    phases = parsed.get("phases")
    if not isinstance(phases, dict):
        raise TypeError("Specula agent config phases must be an object")
    unknown = set(phases) - SPECULA_PHASES
    if unknown:
        raise ValueError(
            f"Specula agent config has unknown phase keys: {sorted(unknown)}"
        )
    unresolved = set(phases.values()) - set(profiles)
    if unresolved:
        raise ValueError(
            f"Specula agent config references missing profiles: {sorted(unresolved)}"
        )


def preflight_contract(
    *,
    checkouts: dict[str, Path],
    files: list[Path],
) -> dict[str, Any]:
    reviewer = reviewer_identity()
    return {
        "reviewer": {
            key: reviewer[key]
            for key in (
                "version",
                "git_commit",
                "dirty_hash",
                "content_sha256",
                "rules_sha256",
                "schemas_sha256",
                "flake_lock_sha256",
            )
        },
        "checkouts": {
            name: inspect_source(path).to_dict()
            for name, path in sorted(checkouts.items())
        },
        "files": {
            str(path.resolve()): file_sha256(path)
            for path in sorted({Path(item).resolve() for item in files})
        },
    }


def verify_handoff(path: Path) -> dict[str, Any]:
    path = Path(path).resolve()
    try:
        handoff = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read handoff evidence {path}: {error}") from error
    kind = handoff.get("kind")
    if kind not in {"aster-code-review", "specula"}:
        raise ValueError(f"unsupported handoff kind: {kind!r}")
    preflight = handoff.get("preflight")
    if not isinstance(preflight, dict):
        raise TypeError("handoff has no preflight contract")

    expected_reviewer = preflight.get("reviewer")
    observed_reviewer = reviewer_identity()
    if not isinstance(expected_reviewer, dict):
        raise TypeError("handoff preflight reviewer identity must be an object")
    if any(
        observed_reviewer.get(key) != value for key, value in expected_reviewer.items()
    ):
        raise ValueError(
            "aster-syssec implementation changed after handoff preparation"
        )

    checkouts = preflight.get("checkouts")
    if not isinstance(checkouts, dict):
        raise TypeError("handoff preflight checkouts must be an object")
    for name, expected in checkouts.items():
        if not isinstance(expected, dict) or not isinstance(expected.get("path"), str):
            raise TypeError(f"invalid checkout identity in handoff: {name}")
        observed = inspect_source(Path(expected["path"]))
        if observed.revision != expected.get("revision"):
            raise ValueError(f"{name} HEAD changed after handoff preparation")
        if observed.dirty_hash != expected.get("dirty_hash"):
            raise ValueError(f"{name} working tree changed after handoff preparation")

    files = preflight.get("files")
    if not isinstance(files, dict):
        raise TypeError("handoff preflight files must be an object")
    for raw_path, expected_sha256 in files.items():
        input_path = Path(raw_path)
        if not input_path.is_file():
            raise ValueError(f"handoff input disappeared: {input_path}")
        if file_sha256(input_path) != expected_sha256:
            raise ValueError(f"handoff input changed after preparation: {input_path}")
    return {"kind": kind, "verified": True, "handoff": str(path)}
