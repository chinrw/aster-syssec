from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from ..engine_results import EngineExecution, evidence_id
from ..targets import VerificationTarget
from .base import EngineContext, resolve_cache_root
from .process import ProcessResult, run_process

_COMPLETE = re.compile(
    r"Complete\s+-\s+(\d+)\s+successfully verified harnesses,\s+"
    r"(\d+)\s+failures,\s+(\d+)\s+total\."
)
_CBMC_VERSION = re.compile(r"^CBMC(?: version)?\s+([^\r\n]+)", re.MULTILINE)
_FAILED_CHECK = re.compile(
    r"^Check\s+\d+:\s+([^\r\n]+)\r?\n\s+- Status:\s+FAILURE",
    re.MULTILINE,
)
_PLAYBACK = re.compile(
    r"Concrete playback unit test[^\r\n]*:\r?\n```(?:rust)?\r?\n(.*?)\r?\n```",
    re.DOTALL,
)


def doctor_kani() -> dict[str, str | None]:
    cargo = shutil.which("cargo")
    version = (
        _command_version([cargo, "kani", "--version"], Path.cwd(), os.environ.copy())
        if cargo
        else None
    )
    return {
        "engine": "kani",
        "adapter": "implemented",
        "status": "available" if version else "unavailable",
        "executable": cargo,
        "version": version,
    }


def execute_kani(target: VerificationTarget, context: EngineContext) -> EngineExecution:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ValueError("Kani target requires cargo on PATH")
    package = str(target.configuration["package"])
    harness = str(target.configuration["harness"])
    prefix = f"engines/kani/{target.id}"
    build_root = context.run.root / "build/kani"
    temporary_root = context.run.root / "tmp"
    cache_root = resolve_cache_root(context)
    kani_home = cache_root / "kani"
    rustup_home = cache_root / "kani-rustup"
    for path in (build_root, temporary_root, kani_home, rustup_home):
        path.mkdir(parents=True, exist_ok=True)
    isolated = {
        "CARGO_TARGET_DIR": str(build_root),
        "KANI_HOME": str(kani_home),
        "RUSTUP_HOME": str(rustup_home),
        "TMPDIR": str(temporary_root),
    }
    environment = os.environ.copy()
    for name in isolated:
        environment.pop(name, None)
    environment.update(isolated)
    argv = [
        cargo,
        "kani",
        "-p",
        package,
        "--harness",
        harness,
        "-Z",
        "concrete-playback",
        "--concrete-playback",
        "print",
    ]
    if target.limits.unwind is not None:
        argv.extend(["--default-unwind", str(target.limits.unwind)])
    source = context.run.manifest["source"]
    command = {"argv": argv, "cwd": str(context.source_root)}
    environment_evidence = {
        "variables": isolated,
        "writable_roots": [
            str(build_root),
            str(temporary_root),
            str(kani_home),
            str(rustup_home),
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
            "unwind": target.limits.unwind,
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
        [cargo, "kani", "--version"], context.source_root, environment
    )
    bundle = _kani_bundle(cache_root, tool_version)
    cbmc = shutil.which("cbmc", path=environment.get("PATH"))
    cbmc_version = (
        _command_version([cbmc, "--version"], context.source_root, environment)
        if cbmc
        else None
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
    outcome, diagnostics, unwind_sufficient = _classify(process)
    counterexample_path: Path | None = None
    playback_path: Path | None = None
    if outcome == "counterexample":
        counterexample_path = context.run.write_text(
            f"{prefix}/counterexample.txt", process.stdout + process.stderr
        )
        playback = _concrete_playback(process.stdout + process.stderr)
        if playback is not None:
            playback_path = context.run.write_text(
                f"{prefix}/concrete-playback.rs",
                playback,
                media_type="text/x-rust; charset=utf-8",
            )
    combined = process.stdout + process.stderr
    counts = _check_counts(combined)
    if cbmc_version is None:
        cbmc_version = _captured_cbmc_version(combined)
    result_seed = {"plan_id": plan_id, "outcome": outcome, "exit": process.returncode}
    result = {
        "schema_version": 1,
        "result_id": evidence_id("RESULT", result_seed),
        "plan_id": plan_id,
        "target": target.id,
        "engine": "kani",
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
            "kani_version": tool_version,
            "cbmc_version": cbmc_version,
            "rust_toolchain": bundle["rust_toolchain"],
            "rustc_version": bundle["rustc_version"],
        },
        "artifacts": {
            "stdout": stdout_path.relative_to(context.run.root).as_posix(),
            "stderr": stderr_path.relative_to(context.run.root).as_posix(),
            "counterexample": (
                counterexample_path.relative_to(context.run.root).as_posix()
                if counterexample_path
                else None
            ),
            "concrete_playback": (
                playback_path.relative_to(context.run.root).as_posix()
                if playback_path
                else None
            ),
        },
        "diagnostics": diagnostics,
        "engine_details": {
            "checks": {
                "successful": counts[0],
                "failures": counts[1],
                "total": counts[2],
                "failed_checks": _failed_checks(combined),
            },
            "completeness": {
                "unwind": target.limits.unwind,
                "unwind_sufficient": unwind_sufficient,
                "assumptions": [],
            },
            "counterexample": {
                "present": outcome == "counterexample",
                "artifact": (
                    counterexample_path.relative_to(context.run.root).as_posix()
                    if counterexample_path
                    else None
                ),
                "concrete_playback_artifact": (
                    playback_path.relative_to(context.run.root).as_posix()
                    if playback_path
                    else None
                ),
            },
        },
    }
    context.run.write_json(
        f"{prefix}/result.json", result, schema="kani-result.schema.json"
    )
    return EngineExecution(result=result, schema="kani-result.schema.json")


def _classify(process: ProcessResult) -> tuple[str, list[str], bool | None]:
    combined = (process.stdout + "\n" + process.stderr).lower()
    if process.timed_out:
        return "timeout", ["Kani exceeded the configured timeout"], None
    if process.signal is not None:
        return "crash", [f"Kani process terminated by signal {process.signal}"], None
    if "unwinding assertion" in combined or "unwind bound" in combined:
        return "incomplete", ["Kani reported an insufficient unwind bound"], False
    if process.exit_code == 0 and "verification:- successful" in combined:
        return "pass", [], True
    if "verification:- failed" in combined:
        return "counterexample", ["Kani reported one or more failed checks"], True
    if process.exit_code not in {0, None} and any(
        marker in combined
        for marker in ("could not compile", "compilation failed", "error[")
    ):
        return "compile-error", ["Kani target did not compile"], None
    return "tool-error", ["Kani exited without a recognized complete result"], None


def _check_counts(output: str) -> tuple[int | None, int | None, int | None]:
    match = _COMPLETE.search(output)
    if match is None:
        return None, None, None
    successful, failures, total = match.groups()
    return int(successful), int(failures), int(total)


def _captured_cbmc_version(output: str) -> str | None:
    match = _CBMC_VERSION.search(output)
    return match.group(1).strip() if match else None


def _failed_checks(output: str) -> list[str]:
    return [match.strip() for match in _FAILED_CHECK.findall(output)]


def _concrete_playback(output: str) -> str | None:
    match = _PLAYBACK.search(output)
    return match.group(1).rstrip() + "\n" if match else None


def _kani_bundle(cache_root: Path, tool_version: str | None) -> dict[str, str | None]:
    match = re.search(r"\b(\d+\.\d+\.\d+)\b", tool_version or "")
    if match is None:
        return {"rust_toolchain": None, "rustc_version": None}
    bundle = cache_root / "kani" / f"kani-{match.group(1)}"
    return {
        "rust_toolchain": _read_optional(bundle / "rust-toolchain-version"),
        "rustc_version": _read_optional(bundle / "rustc-version"),
    }


def _read_optional(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


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
