from __future__ import annotations

import os
import shutil
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..engine_results import EngineExecution, evidence_id
from ..targets import VerificationTarget
from .base import EngineContext
from .process import ProcessResult, run_process

_MAGIC = int.from_bytes(b"SYSLAY01", "little")
_RECORD_WORDS = 7


def doctor_layout() -> dict[str, str | None]:
    cargo = shutil.which("cargo")
    objcopy = shutil.which("llvm-objcopy")
    cargo_version = (
        _command_version([cargo, "--version"], Path.cwd(), os.environ.copy())
        if cargo
        else None
    )
    objcopy_version = (
        _command_version([objcopy, "--version"], Path.cwd(), os.environ.copy())
        if objcopy
        else None
    )
    objcopy_first_line = _first_line(objcopy_version)
    available = cargo_version is not None and objcopy_first_line is not None
    version = (
        f"{cargo_version}; {objcopy_first_line}"
        if cargo_version is not None and objcopy_first_line is not None
        else None
    )
    return {
        "engine": "layout",
        "adapter": "implemented",
        "status": "available" if available else "unavailable",
        "executable": objcopy,
        "version": version,
    }


def execute_layout(
    target: VerificationTarget, context: EngineContext
) -> EngineExecution:
    cargo = shutil.which("cargo")
    objcopy = shutil.which("llvm-objcopy")
    if cargo is None or objcopy is None:
        raise ValueError("layout target requires cargo and llvm-objcopy on PATH")
    package = str(target.configuration["package"])
    manifest_path = context.source_root / "Cargo.toml"
    target_triple = str(target.configuration["target_triple"])
    feature = str(target.configuration["feature"])
    record = str(target.configuration["record"])
    section = str(target.configuration["section"])
    endianness = str(target.configuration["endianness"])
    expected_layout = _normalized_expected(target.configuration["expected_layout"])
    prefix = f"engines/layout/{target.id}"
    build_root = context.run.root / "build/layout" / target.id
    temporary_root = context.run.root / "tmp"
    for path in (build_root, temporary_root):
        path.mkdir(parents=True, exist_ok=True)
    isolated = {
        "CARGO_TARGET_DIR": str(build_root),
        "TMPDIR": str(temporary_root),
    }
    environment = os.environ.copy()
    for name in isolated:
        environment.pop(name, None)
    environment.update(isolated)
    argv = [
        cargo,
        "rustc",
        "--manifest-path",
        str(manifest_path),
        "--locked",
        "--offline",
        "-p",
        package,
        "--features",
        feature,
        "--target",
        target_triple,
        "--lib",
        "--",
        "--emit=obj",
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
    compile_process = _run(
        argv,
        context=context,
        environment=environment,
        target=target,
    )
    compile_stdout = context.run.write_text(
        f"{prefix}/compile.stdout.log", compile_process.stdout
    )
    compile_stderr = context.run.write_text(
        f"{prefix}/compile.stderr.log", compile_process.stderr
    )
    outcome, diagnostics = _compile_outcome(compile_process)
    layout: dict[str, Any] | None = None
    matches_expected: bool | None = None
    section_output: Path | None = None
    extract_stdout: Path | None = None
    extract_stderr: Path | None = None
    extraction_duration = 0
    if outcome == "pass":
        object_prefix = package.replace("-", "_")
        objects = sorted(build_root.rglob(f"{object_prefix}-*.o"))
        if len(objects) != 1:
            outcome = "tool-error"
            diagnostics.append(
                f"layout compile produced {len(objects)} probe objects; expected one"
            )
        else:
            raw_section = context.run.root / prefix / "section.bin"
            raw_section.parent.mkdir(parents=True, exist_ok=True)
            extract_argv = [
                objcopy,
                f"--dump-section={section}={raw_section}",
                str(objects[0]),
            ]
            context.run.write_json(
                f"{prefix}/extract-command.json",
                {"argv": extract_argv, "cwd": str(context.source_root)},
                schema="engine-command.schema.json",
            )
            extraction = _run(
                extract_argv,
                context=context,
                environment=environment,
                target=target,
            )
            extraction_duration = extraction.duration_ms
            extract_stdout = context.run.write_text(
                f"{prefix}/extract.stdout.log", extraction.stdout
            )
            extract_stderr = context.run.write_text(
                f"{prefix}/extract.stderr.log", extraction.stderr
            )
            if extraction.timed_out:
                outcome = "timeout"
                diagnostics.append("layout section extraction timed out")
            elif extraction.exit_code != 0 or not raw_section.is_file():
                outcome = "tool-error"
                diagnostics.append("llvm-objcopy could not extract the layout section")
            else:
                section_output = context.run.register_artifact(raw_section)
                try:
                    layout = _decode_layout(raw_section.read_bytes(), endianness)
                except ValueError as error:
                    outcome = "tool-error"
                    diagnostics.append(str(error))
                else:
                    matches_expected = layout == expected_layout
                    outcome = "pass" if matches_expected else "mismatch"
                    if not matches_expected:
                        diagnostics.append(
                            "target layout differs from the configured baseline"
                        )
    finished = datetime.now(UTC)
    result_seed = {
        "plan_id": plan_id,
        "outcome": outcome,
        "layout": layout,
        "exit": compile_process.returncode,
    }
    result = {
        "schema_version": 1,
        "result_id": evidence_id("RESULT", result_seed),
        "plan_id": plan_id,
        "target": target.id,
        "engine": "layout",
        "track": target.track,
        "properties": list(target.properties),
        "source_symbols": list(target.source_symbols),
        "outcome": outcome,
        "expected": target.policy.expected,
        "expectation_met": outcome == target.policy.expected,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": compile_process.duration_ms + extraction_duration,
        "process": {
            "exit_code": compile_process.exit_code,
            "signal": compile_process.signal,
            "timed_out": compile_process.timed_out,
        },
        "tool": {
            "cargo_version": _command_version(
                [cargo, "--version"], context.source_root, environment
            ),
            "llvm_objcopy_version": _first_line(
                _command_version(
                    [objcopy, "--version"], context.source_root, environment
                )
            ),
            "rust_toolchain": context.run.manifest["tool_versions"].get(
                "asterinas_rust_toolchain"
            ),
        },
        "artifacts": {
            "object": None,
            "section": _relative(section_output, context.run.root),
            "compile_stdout": compile_stdout.relative_to(context.run.root).as_posix(),
            "compile_stderr": compile_stderr.relative_to(context.run.root).as_posix(),
            "extract_stdout": _relative(extract_stdout, context.run.root),
            "extract_stderr": _relative(extract_stderr, context.run.root),
        },
        "diagnostics": diagnostics,
        "engine_details": {
            "target_triple": target_triple,
            "endianness": endianness,
            "record": record,
            "section": section,
            "layout": layout,
            "expected_layout": expected_layout,
            "matches_expected": matches_expected,
        },
    }
    context.run.write_json(
        f"{prefix}/result.json", result, schema="layout-result.schema.json"
    )
    return EngineExecution(result=result, schema="layout-result.schema.json")


def _run(
    argv: list[str],
    *,
    context: EngineContext,
    environment: dict[str, str],
    target: VerificationTarget,
) -> ProcessResult:
    try:
        return run_process(
            argv,
            cwd=context.source_root,
            environment=environment,
            timeout_seconds=target.limits.timeout_seconds,
            memory_bytes=target.limits.memory_bytes,
        )
    except OSError as error:
        return ProcessResult(
            stdout="",
            stderr=str(error),
            returncode=None,
            timed_out=False,
            duration_ms=0,
        )


def _compile_outcome(process: ProcessResult) -> tuple[str, list[str]]:
    if process.timed_out:
        return "timeout", ["layout cross-compilation timed out"]
    if process.signal is not None:
        return "crash", [f"layout compiler terminated by signal {process.signal}"]
    if process.exit_code == 0:
        return "pass", []
    combined = (process.stdout + process.stderr).lower()
    if any(marker in combined for marker in ("could not compile", "error[")):
        return "compile-error", ["layout probe did not compile"]
    return "tool-error", ["layout compiler exited without producing a probe"]


def _decode_layout(payload: bytes, endianness: str) -> dict[str, Any]:
    expected_size = _RECORD_WORDS * 8
    if len(payload) != expected_size:
        raise ValueError(
            f"layout section has {len(payload)} bytes; expected {expected_size}"
        )
    prefix = "<" if endianness == "little" else ">"
    magic, version, pointer_width, size, alignment, base, length = struct.unpack(
        f"{prefix}{_RECORD_WORDS}Q", payload
    )
    if magic != _MAGIC:
        raise ValueError("layout section has an invalid magic value")
    if version != 1:
        raise ValueError(f"unsupported layout record version: {version}")
    return {
        "pointer_width": pointer_width,
        "size": size,
        "alignment": alignment,
        "field_offsets": {"base": base, "len": length},
    }


def _normalized_expected(value: Any) -> dict[str, Any]:
    return {
        "pointer_width": int(value["pointer_width"]),
        "size": int(value["size"]),
        "alignment": int(value["alignment"]),
        "field_offsets": {
            str(name): int(offset)
            for name, offset in sorted(value["field_offsets"].items())
        },
    }


def _relative(path: Path | None, root: Path) -> str | None:
    return path.relative_to(root).as_posix() if path is not None else None


def _first_line(value: str | None) -> str | None:
    return value.splitlines()[0] if value else None


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
