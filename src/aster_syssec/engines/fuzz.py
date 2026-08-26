from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from ..engine_results import EngineExecution, evidence_id
from ..targets import VerificationTarget
from .base import EngineContext, resolve_cache_root
from .process import ProcessResult, run_process

_DONE = re.compile(r"Done\s+(\d+)\s+runs", re.IGNORECASE)


def doctor_fuzz() -> dict[str, str | None]:
    cargo = shutil.which("cargo")
    version = (
        _command_version([cargo, "fuzz", "--version"], Path.cwd(), os.environ.copy())
        if cargo
        else None
    )
    return {
        "engine": "fuzz",
        "adapter": "implemented",
        "status": "available" if version else "unavailable",
        "executable": cargo,
        "version": version,
    }


def execute_fuzz(target: VerificationTarget, context: EngineContext) -> EngineExecution:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ValueError("host fuzz target requires cargo on PATH")
    fuzz_target = str(target.configuration["fuzz_target"])
    runs = int(target.configuration["runs"])
    max_input_size = int(target.configuration["max_input_size"])
    sanitizer = str(target.configuration["sanitizer"])
    source_manifest = context.source_root / str(target.configuration["manifest_path"])
    source_fuzz_root = source_manifest.parent
    prefix = f"engines/fuzz/{target.id}"
    fuzz_root = context.run.root / "inputs/fuzz" / target.id
    _copy_fuzz_project(source_fuzz_root, fuzz_root, context.source_root)
    fuzz_lock = fuzz_root / "Cargo.lock"
    if not fuzz_lock.is_file():
        raise ValueError("cargo-fuzz target requires a checked-in Cargo.lock")
    lock_before = sha256(fuzz_lock.read_bytes()).hexdigest()
    build_root = context.run.root / "build/fuzz" / target.id
    temporary_root = context.run.root / "tmp"
    corpus_root = context.run.root / "corpus/fuzz" / target.id
    artifact_root = context.run.root / "crashes/fuzz" / target.id
    cache_root = resolve_cache_root(context)
    cargo_home = cache_root / "cargo"
    persistent_corpus = cache_root / "corpus/host" / target.id
    for path in (
        build_root,
        temporary_root,
        corpus_root,
        artifact_root,
        cargo_home,
        persistent_corpus,
    ):
        path.mkdir(parents=True, exist_ok=True)
    seed_count = _copy_corpus(persistent_corpus, corpus_root)
    isolated = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(build_root),
        "CARGO_NET_OFFLINE": "true",
        "TMPDIR": str(temporary_root),
    }
    environment = os.environ.copy()
    for name in isolated:
        environment.pop(name, None)
    environment.update(isolated)
    argv = [
        cargo,
        "fuzz",
        "run",
        "--fuzz-dir",
        str(fuzz_root),
        "--target-dir",
        str(build_root),
        "--sanitizer",
        sanitizer,
        fuzz_target,
        str(corpus_root),
        "--",
        f"-runs={runs}",
        f"-max_len={max_input_size}",
        f"-artifact_prefix={artifact_root}{os.sep}",
    ]
    source = context.run.manifest["source"]
    command = {"argv": argv, "cwd": str(context.source_root)}
    environment_evidence = {
        "variables": isolated,
        "writable_roots": [
            str(build_root),
            str(temporary_root),
            str(corpus_root),
            str(artifact_root),
            str(persistent_corpus),
            str(fuzz_root),
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
        [cargo, "fuzz", "--version"], context.source_root, environment
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
    crash_inputs = sorted(
        path.name for path in artifact_root.iterdir() if path.is_file()
    )
    completed_runs = _completed_runs(process.stdout + process.stderr)
    outcome, diagnostics = _classify(process, completed_runs, crash_inputs)
    if sha256(fuzz_lock.read_bytes()).hexdigest() != lock_before:
        outcome = "tool-error"
        diagnostics.append("cargo-fuzz changed the checked-in lockfile copy")
    crash_artifact: str | None = None
    if crash_inputs:
        context.run.register_artifact(artifact_root)
        crash_artifact = artifact_root.relative_to(context.run.root).as_posix()
    _copy_corpus(corpus_root, persistent_corpus)
    corpus_count = sum(1 for path in corpus_root.iterdir() if path.is_file())
    result_seed = {
        "plan_id": plan_id,
        "outcome": outcome,
        "exit": process.returncode,
        "crash_inputs": crash_inputs,
    }
    result = {
        "schema_version": 1,
        "result_id": evidence_id("RESULT", result_seed),
        "plan_id": plan_id,
        "target": target.id,
        "engine": "fuzz",
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
            "cargo_fuzz_version": tool_version,
            "rust_toolchain": context.run.manifest["tool_versions"].get(
                "asterinas_rust_toolchain"
            ),
        },
        "artifacts": {
            "stdout": stdout_path.relative_to(context.run.root).as_posix(),
            "stderr": stderr_path.relative_to(context.run.root).as_posix(),
            "corpus": None,
            "crashes": crash_artifact,
            "fuzz_project": None,
        },
        "diagnostics": diagnostics,
        "engine_details": {
            "fuzz_target": fuzz_target,
            "configured_runs": runs,
            "completed_runs": completed_runs,
            "max_input_size": max_input_size,
            "sanitizer": sanitizer,
            "seed_count": seed_count,
            "corpus_count": corpus_count,
            "crash_inputs": crash_inputs,
        },
    }
    context.run.write_json(
        f"{prefix}/result.json", result, schema="fuzz-result.schema.json"
    )
    return EngineExecution(result=result, schema="fuzz-result.schema.json")


def _copy_corpus(source: Path, destination: Path) -> int:
    copied = 0
    for path in sorted(source.iterdir()):
        if path.is_symlink() or not path.is_file():
            continue
        shutil.copy2(path, destination / path.name)
        copied += 1
    return copied


def _copy_fuzz_project(source: Path, destination: Path, source_root: Path) -> None:
    if any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("cargo-fuzz project must not contain symlinks")
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("artifacts", "corpus", "target"),
    )
    manifest_path = destination / "Cargo.toml"
    parsed = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    dependencies = parsed.get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise TypeError("cargo-fuzz dependencies must be a TOML table")
    manifest = manifest_path.read_text(encoding="utf-8")
    lines = manifest.splitlines()
    for name, specification in dependencies.items():
        if not isinstance(specification, dict) or "path" not in specification:
            continue
        relative = str(specification["path"])
        resolved = (source / relative).resolve()
        try:
            resolved.relative_to(source_root.resolve())
        except ValueError as error:
            raise ValueError(
                f"cargo-fuzz path dependency escapes the Asterinas checkout: {name}"
            ) from error
        marker = f'path = "{relative}"'
        replacement = f'path = "{resolved}"'
        matches = [
            index
            for index, line in enumerate(lines)
            if line.lstrip().startswith(f"{name} =") and marker in line
        ]
        if len(matches) != 1:
            raise ValueError(
                f"cannot pin cargo-fuzz path dependency in shadow project: {name}"
            )
        index = matches[0]
        lines[index] = lines[index].replace(marker, replacement, 1)
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _completed_runs(output: str) -> int | None:
    match = _DONE.search(output)
    return int(match.group(1)) if match else None


def _classify(
    process: ProcessResult,
    completed_runs: int | None,
    crash_inputs: list[str],
) -> tuple[str, list[str]]:
    combined = (process.stdout + "\n" + process.stderr).lower()
    if process.timed_out:
        return "timeout", ["cargo-fuzz exceeded the configured timeout"]
    if process.signal is not None:
        return "crash", [f"cargo-fuzz terminated by signal {process.signal}"]
    if crash_inputs or "error: libfuzzer" in combined:
        return "counterexample", ["libFuzzer produced a crash input"]
    if "not supported" in combined or "unsupported" in combined:
        return "unsupported", ["cargo-fuzz reported an unsupported configuration"]
    if process.exit_code == 0 and completed_runs is not None:
        return "pass", []
    if process.exit_code not in {0, None} and any(
        marker in combined for marker in ("could not compile", "error[")
    ):
        return "compile-error", ["cargo-fuzz target did not compile"]
    if process.exit_code == 0:
        return "incomplete", ["libFuzzer did not report a completed bounded campaign"]
    return "tool-error", ["cargo-fuzz exited without a recognized result"]


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
