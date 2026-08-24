from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from ..engine_results import EngineExecution, evidence_id
from ..targets import VerificationTarget
from .base import EngineContext
from .process import ProcessResult, run_process

_TEST_RESULT = re.compile(
    r"test result: (?:ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed;.*?"
    r"(\d+) filtered out"
)


def doctor_loom() -> dict[str, str | None]:
    cargo = shutil.which("cargo")
    version = (
        _command_version([cargo, "--version"], Path.cwd(), os.environ.copy())
        if cargo
        else None
    )
    return {
        "engine": "loom",
        "adapter": "implemented",
        "status": "available" if version else "unavailable",
        "executable": cargo,
        "version": version,
    }


def execute_loom(target: VerificationTarget, context: EngineContext) -> EngineExecution:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ValueError("Loom target requires cargo on PATH")
    package = str(target.configuration["package"])
    test = str(target.configuration["test"])
    target_triple = str(target.configuration["target_triple"])
    max_branches = int(target.configuration["max_branches"])
    max_preemptions = int(target.configuration["max_preemptions"])
    max_permutations = target.configuration.get("max_permutations")
    prefix = f"engines/loom/{target.id}"
    build_root = context.run.root / "build/loom"
    temporary_root = context.run.root / "tmp"
    for path in (build_root, temporary_root):
        path.mkdir(parents=True, exist_ok=True)
    isolated = {
        "CARGO_TARGET_DIR": str(build_root),
        "CARGO_NET_OFFLINE": "true",
        "LOOM_MAX_BRANCHES": str(max_branches),
        "LOOM_MAX_PREEMPTIONS": str(max_preemptions),
        "TMPDIR": str(temporary_root),
    }
    if max_permutations is not None:
        isolated["LOOM_MAX_PERMUTATIONS"] = str(max_permutations)
    environment = os.environ.copy()
    for name in isolated:
        environment.pop(name, None)
    environment.update(isolated)
    argv = [
        cargo,
        "test",
        "--locked",
        "-p",
        package,
        "--target",
        target_triple,
        test,
        "--",
        "--nocapture",
    ]
    source = context.run.manifest["source"]
    command = {"argv": argv, "cwd": str(context.source_root)}
    environment_evidence = {
        "variables": isolated,
        "writable_roots": [str(build_root), str(temporary_root)],
    }
    plan_seed = {
        "target": target.id,
        "target_config_sha256": target.config_sha256,
        "source_revision": source["revision"],
        "source_dirty_hash": source["dirty_hash"],
        "command": argv,
    }
    plan_id = evidence_id("PLAN", plan_seed)
    plan = {
        "schema_version": 1,
        "plan_id": plan_id,
        "created_at": datetime.now(UTC).isoformat(),
        "target": target.id,
        "target_config_sha256": target.config_sha256,
        "engine": target.engine,
        "track": target.track,
        "properties": list(target.properties),
        "source_symbols": list(target.source_symbols),
        "source": {
            "path": source["path"],
            "revision": source["revision"],
            "dirty_hash": source["dirty_hash"],
        },
        "command": command,
        "environment": environment_evidence,
        "limits": {
            "timeout_seconds": target.limits.timeout_seconds,
            "memory_bytes": target.limits.memory_bytes,
            "unwind": None,
        },
        "expected": target.policy.expected,
    }
    context.run.write_json(
        f"{prefix}/plan.json", plan, schema="engine-plan.schema.json"
    )
    context.run.write_json(
        f"{prefix}/command.json", command, schema="engine-command.schema.json"
    )
    context.run.write_json(
        f"{prefix}/environment.json",
        environment_evidence,
        schema="engine-environment.schema.json",
    )

    started = datetime.now(UTC)
    try:
        process = run_process(
            argv,
            cwd=context.source_root,
            environment=environment,
            timeout_seconds=target.limits.timeout_seconds,
            memory_bytes=target.limits.memory_bytes,
        )
    except OSError as error:
        process = ProcessResult(
            stdout="",
            stderr=str(error),
            returncode=None,
            timed_out=False,
            duration_ms=0,
        )
    finished = datetime.now(UTC)
    stdout_path = context.run.write_text(f"{prefix}/stdout.log", process.stdout)
    stderr_path = context.run.write_text(f"{prefix}/stderr.log", process.stderr)
    counts = _test_counts(process.stdout + process.stderr)
    outcome, diagnostics = _classify(process, test, counts)
    loom_version = _locked_package_version(context.source_root / "Cargo.lock", "loom")
    result_seed = {"plan_id": plan_id, "outcome": outcome, "exit": process.returncode}
    result = {
        "schema_version": 1,
        "result_id": evidence_id("RESULT", result_seed),
        "plan_id": plan_id,
        "target": target.id,
        "engine": "loom",
        "track": target.track,
        "properties": list(target.properties),
        "source_symbols": list(target.source_symbols),
        "outcome": outcome,
        "expected": target.policy.expected,
        "expectation_met": outcome == target.policy.expected,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": process.duration_ms,
        "process": {
            "exit_code": process.exit_code,
            "signal": process.signal,
            "timed_out": process.timed_out,
        },
        "tool": {
            "cargo_version": _command_version(
                [cargo, "--version"], context.source_root, environment
            ),
            "loom_version": loom_version,
            "rust_toolchain": context.run.manifest["tool_versions"].get(
                "asterinas_rust_toolchain"
            ),
        },
        "artifacts": {
            "stdout": stdout_path.relative_to(context.run.root).as_posix(),
            "stderr": stderr_path.relative_to(context.run.root).as_posix(),
        },
        "diagnostics": diagnostics,
        "engine_details": {
            "test": test,
            "target_triple": target_triple,
            "max_branches": max_branches,
            "max_preemptions": max_preemptions,
            "max_permutations": max_permutations,
            "tests": {
                "passed": counts[0],
                "failed": counts[1],
                "filtered_out": counts[2],
            },
        },
    }
    context.run.write_json(
        f"{prefix}/result.json", result, schema="loom-result.schema.json"
    )
    return EngineExecution(result=result, schema="loom-result.schema.json")


def _classify(
    process: ProcessResult,
    test: str,
    counts: tuple[int | None, int | None, int | None],
) -> tuple[str, list[str]]:
    combined = process.stdout + "\n" + process.stderr
    lowered = combined.lower()
    if process.timed_out:
        return "timeout", ["Loom exceeded the configured timeout"]
    if process.signal is not None:
        return "crash", [f"Loom process terminated by signal {process.signal}"]
    if process.exit_code == 0 and "test result: ok" in lowered:
        if counts[0] is None or counts[0] == 0 or test not in combined:
            return "incomplete", ["Loom did not execute the configured model"]
        return "pass", []
    if "test result: failed" in lowered or "panicked at" in lowered:
        return "counterexample", ["Loom found a failing execution"]
    if process.exit_code not in {0, None} and any(
        marker in lowered for marker in ("could not compile", "error[")
    ):
        return "compile-error", ["Loom target did not compile"]
    return "tool-error", ["Loom exited without a recognized complete result"]


def _test_counts(output: str) -> tuple[int | None, int | None, int | None]:
    match = _TEST_RESULT.search(output)
    if match is None:
        return None, None, None
    passed, failed, filtered_out = match.groups()
    return int(passed), int(failed), int(filtered_out)


def _locked_package_version(lock_path: Path, package: str) -> str | None:
    try:
        parsed = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    versions = {
        str(item["version"])
        for item in parsed.get("package", [])
        if isinstance(item, dict) and item.get("name") == package
    }
    return next(iter(versions)) if len(versions) == 1 else None


def _command_version(
    argv: list[str], cwd: Path, environment: dict[str, str]
) -> str | None:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return (result.stdout or result.stderr).strip() or None
