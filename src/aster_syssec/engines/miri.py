from __future__ import annotations

import os
import re
import shutil
import subprocess
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


def doctor_miri() -> dict[str, str | None]:
    cargo = shutil.which("cargo")
    version = (
        _command_version([cargo, "miri", "--version"], Path.cwd(), os.environ.copy())
        if cargo
        else None
    )
    return {
        "engine": "miri",
        "adapter": "implemented",
        "status": "available" if version else "unavailable",
        "executable": cargo,
        "version": version,
    }


def execute_miri(target: VerificationTarget, context: EngineContext) -> EngineExecution:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ValueError("Miri target requires cargo on PATH")
    package = str(target.configuration["package"])
    test = str(target.configuration["test"])
    target_triple = str(target.configuration["target_triple"])
    prefix = f"engines/miri/{target.id}"
    build_root = context.run.root / "build/miri"
    temporary_root = context.run.root / "tmp"
    cache_root = context.work_root / "cache/miri"
    for path in (build_root, temporary_root, cache_root):
        path.mkdir(parents=True, exist_ok=True)
    isolated = {
        "CARGO_TARGET_DIR": str(build_root),
        "TMPDIR": str(temporary_root),
        "XDG_CACHE_HOME": str(cache_root),
    }
    environment = os.environ.copy()
    for name in isolated:
        environment.pop(name, None)
    environment.update(isolated)
    argv = [
        cargo,
        "miri",
        "test",
        "-p",
        package,
        "--target",
        target_triple,
        test,
    ]
    source = context.run.manifest["source"]
    command = {"argv": argv, "cwd": str(context.source_root)}
    environment_evidence = {
        "variables": isolated,
        "writable_roots": [
            str(build_root),
            str(temporary_root),
            str(cache_root),
        ],
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
    tool_version = _command_version(
        [cargo, "miri", "--version"], context.source_root, environment
    )
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
    outcome, diagnostics, violation = _classify(process, test)
    counts = _test_counts(process.stdout + process.stderr)
    result_seed = {"plan_id": plan_id, "outcome": outcome, "exit": process.returncode}
    result = {
        "schema_version": 1,
        "result_id": evidence_id("RESULT", result_seed),
        "plan_id": plan_id,
        "target": target.id,
        "engine": "miri",
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
            "miri_version": tool_version,
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
            "target_triple": target_triple,
            "tests": {
                "passed": counts[0],
                "failed": counts[1],
                "filtered_out": counts[2],
            },
            "violation": violation,
        },
    }
    context.run.write_json(
        f"{prefix}/result.json", result, schema="miri-result.schema.json"
    )
    return EngineExecution(result=result, schema="miri-result.schema.json")


def _classify(process: ProcessResult, test: str) -> tuple[str, list[str], str | None]:
    combined = process.stdout + "\n" + process.stderr
    lowered = combined.lower()
    if process.timed_out:
        return "timeout", ["Miri exceeded the configured timeout"], None
    if process.signal is not None:
        return "crash", [f"Miri process terminated by signal {process.signal}"], None
    if "unsupported operation" in lowered or "not supported by miri" in lowered:
        return "unsupported", ["Miri reported an unsupported operation"], "unsupported"
    if "undefined behavior" in lowered or "encountered undefined behavior" in lowered:
        return (
            "counterexample",
            ["Miri reported undefined behavior"],
            "undefined-behavior",
        )
    counts = _test_counts(combined)
    if process.exit_code == 0 and "test result: ok" in lowered:
        if counts[0] is None or counts[0] == 0 or test not in combined:
            return "incomplete", ["Miri did not execute the configured test"], None
        return "pass", [], None
    if "test result: failed" in lowered:
        return "counterexample", ["The configured Miri test failed"], "test-failure"
    if process.exit_code not in {0, None} and any(
        marker in lowered
        for marker in ("could not compile", "compilation failed", "error[")
    ):
        return "compile-error", ["Miri target did not compile"], None
    return "tool-error", ["Miri exited without a recognized complete result"], None


def _test_counts(output: str) -> tuple[int | None, int | None, int | None]:
    match = _TEST_RESULT.search(output)
    if match is None:
        return None, None, None
    passed, failed, filtered_out = match.groups()
    return int(passed), int(failed), int(filtered_out)


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
