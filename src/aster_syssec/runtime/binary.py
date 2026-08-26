from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..engine_results import evidence_id
from ..schemas import validate_instance
from ..source import (
    atomic_write_json,
    ensure_asterinas_checkout,
    inspect_source,
    require_disjoint_paths,
)
from .asterinas import _clone_source


class AsterinasStaticBinaryExporter:
    def __init__(
        self,
        *,
        make_executable: str = "make",
        nix_executable: str = "nix",
        nix_store_executable: str = "nix-store",
        readelf_executable: str = "readelf",
    ) -> None:
        self._make_executable = make_executable
        self._nix_executable = nix_executable
        self._nix_store_executable = nix_store_executable
        self._readelf_executable = readelf_executable

    def export(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_value = json.loads(json.dumps(request, ensure_ascii=False))
        validate_instance(request_value, "binary-export-request.schema.json")
        source_root = Path(request_value["source"]["path"]).resolve()
        evidence_root = Path(request_value["evidence_root"]).resolve()
        require_disjoint_paths(source_root, evidence_root)
        _require_source(request_value, source_root)
        evidence_root.mkdir(parents=True, exist_ok=False)

        request_path = atomic_write_json(
            evidence_root / "binary-export-request.json",
            request_value,
        )
        checkout = evidence_root / "checkout"
        _clone_source(source_root, checkout, request_value["source"]["revision"])
        case_relative = Path("test/initramfs/src/regression") / (
            request_value["guest_case"] + ".c"
        )
        source_case = checkout / case_relative
        source_sha256 = _sha256(source_case.read_bytes())
        artifacts_root = evidence_root / "artifacts"
        temporary_root = evidence_root / "tmp"
        artifacts_root.mkdir()
        temporary_root.mkdir()
        stdout_path = artifacts_root / "build-stdout.log"
        stderr_path = artifacts_root / "build-stderr.log"
        initramfs_root = checkout / "test/initramfs/build/initramfs"
        command = [
            self._make_executable,
            "-C",
            "test/initramfs",
            str(initramfs_root),
            "ENABLE_REGRESSION_TEST=true",
            "REGRESSION_TEST_PLATFORM=asterinas",
            f"TARGET_ARCH={request_value['target_arch']}",
        ]
        environment = os.environ.copy()
        environment["TMPDIR"] = str(temporary_root)
        _run_build(
            command,
            cwd=checkout,
            environment=environment,
            timeout_seconds=request_value["limits"]["build_timeout_seconds"],
            output_bytes=request_value["limits"]["output_bytes"],
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        if (
            _tracked_source_changed(checkout)
            or _sha256(source_case.read_bytes()) != source_sha256
        ):
            raise ValueError("Asterinas source changed during build")

        built_binary = initramfs_root / "test" / request_value["guest_case"]
        if not built_binary.is_file():
            raise ValueError("Asterinas initramfs build did not produce the guest case")
        resolved_binary = built_binary.resolve(strict=True)
        if resolved_binary.stat().st_mode & 0o111 == 0:
            raise ValueError("Asterinas initramfs guest case is not executable")
        store_output = _nix_store_output(resolved_binary)
        derivation = _query_derivation(
            self._nix_store_executable,
            store_output,
        )
        derivation_entry, derivation_bytes = _show_derivation(
            self._nix_executable,
            derivation,
        )
        derivation_path = _atomic_write_bytes(
            artifacts_root / "nix-derivation.json",
            derivation_bytes,
        )
        compiler_executable = _derivation_compiler(
            derivation_entry,
            nix_store_executable=self._nix_store_executable,
        )
        compiler_version = _capture_tool(
            [compiler_executable, "--version"],
            "compiler version",
        )
        compiler_version_path = _atomic_write_bytes(
            artifacts_root / "compiler-version.log",
            compiler_version,
        )
        linker_executable = _compiler_linker(compiler_executable)
        linker_version = _capture_tool(
            [linker_executable, "--version"],
            "linker version",
        )
        linker_version_path = _atomic_write_bytes(
            artifacts_root / "linker-version.log",
            linker_version,
        )

        exported_binary = artifacts_root / "static-binary" / built_binary.name
        _atomic_copy(resolved_binary, exported_binary)
        header = _capture_tool(
            [self._readelf_executable, "-hW", str(exported_binary)],
            "ELF header",
        )
        program_headers = _capture_tool(
            [self._readelf_executable, "-lW", str(exported_binary)],
            "ELF program headers",
        )
        dynamic = _capture_tool(
            [self._readelf_executable, "-dW", str(exported_binary)],
            "ELF dynamic section",
        )
        verification = _verify_static_elf(header, program_headers, dynamic)
        header_path = _atomic_write_bytes(artifacts_root / "readelf-header.log", header)
        program_headers_path = _atomic_write_bytes(
            artifacts_root / "readelf-program-headers.log",
            program_headers,
        )
        dynamic_path = _atomic_write_bytes(
            artifacts_root / "readelf-dynamic.log",
            dynamic,
        )

        binary = {
            "path": str(exported_binary),
            "sha256": _sha256(exported_binary.read_bytes()),
            "source_sha256": source_sha256,
            "compiler": _tool_identity(compiler_executable, compiler_version),
            "linker": _tool_identity(linker_executable, linker_version),
            "build_command": {
                "argv": command,
                "cwd": str(checkout),
            },
        }
        artifacts = {
            "request": _artifact(request_path, evidence_root),
            "binary": _artifact(exported_binary, evidence_root),
            "build_stdout": _artifact(stdout_path, evidence_root),
            "build_stderr": _artifact(stderr_path, evidence_root),
            "nix_derivation": _artifact(derivation_path, evidence_root),
            "compiler_version": _artifact(compiler_version_path, evidence_root),
            "linker_version": _artifact(linker_version_path, evidence_root),
            "readelf_header": _artifact(header_path, evidence_root),
            "readelf_program_headers": _artifact(
                program_headers_path,
                evidence_root,
            ),
            "readelf_dynamic": _artifact(dynamic_path, evidence_root),
        }
        request_sha256 = _sha256(request_path.read_bytes())
        provenance_seed = {
            "request_id": request_value["request_id"],
            "request_sha256": request_sha256,
            "binary_sha256": binary["sha256"],
        }
        provenance = {
            "schema_version": 1,
            "provenance_id": evidence_id("BINARY-PROVENANCE", provenance_seed),
            "request_id": request_value["request_id"],
            "request_sha256": request_sha256,
            "created_at": datetime.now(UTC).isoformat(),
            "target": request_value["target"],
            "guest_case": request_value["guest_case"],
            "target_arch": request_value["target_arch"],
            "source": {
                "path": str(source_root),
                "revision": request_value["source"]["revision"],
                "dirty_hash": request_value["source"]["dirty_hash"],
                "case_path": str(case_relative),
                "case_sha256": source_sha256,
            },
            "binary": binary,
            "nix": {
                "derivation": derivation,
                "output": str(store_output),
                "compiler_executable": compiler_executable,
                "linker_executable": linker_executable,
            },
            "verification": verification,
            "artifacts": artifacts,
            "diagnostics": [],
        }
        validate_instance(provenance, "binary-provenance.schema.json")
        atomic_write_json(evidence_root / "binary-provenance.json", provenance)
        return provenance


def _require_source(request: dict[str, Any], source_root: Path) -> None:
    ensure_asterinas_checkout(source_root)
    required = (
        source_root / "Makefile",
        source_root / "test/initramfs/Makefile",
        source_root / "test/initramfs/src/regression" / (request["guest_case"] + ".c"),
    )
    missing = [
        str(item.relative_to(source_root)) for item in required if not item.is_file()
    ]
    if missing:
        raise ValueError(f"Asterinas binary source is missing: {', '.join(missing)}")
    snapshot = inspect_source(source_root)
    expected = request["source"]
    if snapshot.revision != expected["revision"]:
        raise ValueError(
            "Asterinas source revision does not match binary export request"
        )
    if snapshot.dirty_hash != expected["dirty_hash"]:
        raise ValueError(
            "Asterinas source dirty hash does not match binary export request"
        )
    if snapshot.dirty_entries:
        raise ValueError("Asterinas binary export requires a clean checkout")


def _run_build(
    argv: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    output_bytes: int,
    stdout_path: Path,
    stderr_path: Path,
) -> None:
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=dict(environment),
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except OSError as error:
            raise ValueError(
                f"cannot start Asterinas initramfs build: {error}"
            ) from error
        started = time.monotonic()
        while process.poll() is None:
            if time.monotonic() - started >= timeout_seconds:
                _kill_process_group(process)
                process.wait()
                raise ValueError("Asterinas initramfs build timed out")
            if stdout_path.stat().st_size + stderr_path.stat().st_size > output_bytes:
                _kill_process_group(process)
                process.wait()
                raise ValueError("Asterinas initramfs build output exceeds the limit")
            time.sleep(0.05)
        if process.returncode != 0:
            raise ValueError(f"Asterinas initramfs build exited {process.returncode}")
    if stdout_path.stat().st_size + stderr_path.stat().st_size > output_bytes:
        raise ValueError("Asterinas initramfs build output exceeds the limit")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _tracked_source_changed(checkout: Path) -> bool:
    process = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--"],
        cwd=checkout,
        check=False,
    )
    if process.returncode not in (0, 1):
        raise ValueError("cannot verify the isolated Asterinas checkout")
    return process.returncode == 1


def _nix_store_output(binary: Path) -> Path:
    parts = binary.parts
    for index in range(len(parts) - 2):
        if parts[index : index + 2] == ("nix", "store"):
            return Path(*parts[: index + 3])
    raise ValueError("Asterinas initramfs binary is not backed by a Nix store output")


def _query_derivation(nix_store_executable: str, output: Path) -> str:
    value = (
        _capture_tool(
            [nix_store_executable, "--query", "--deriver", str(output)],
            "Nix output derivation",
        )
        .decode("utf-8", "strict")
        .strip()
    )
    if not value or value == "unknown-deriver":
        raise ValueError("Nix store output has no derivation")
    return value


def _show_derivation(
    nix_executable: str,
    derivation: str,
) -> tuple[dict[str, Any], bytes]:
    payload = _capture_tool(
        [nix_executable, "derivation", "show", derivation],
        "Nix derivation metadata",
    )
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError("Nix derivation metadata is not valid JSON") from error
    if not isinstance(value, dict):
        raise TypeError("Nix derivation metadata is not an object")
    entry = value.get(derivation)
    if entry is None:
        derivations = value.get("derivations")
        if isinstance(derivations, dict):
            entry = derivations.get(Path(derivation).name)
    if not isinstance(entry, dict):
        raise KeyError(
            "Nix derivation metadata does not contain the queried derivation"
        )
    return entry, payload


def _derivation_compiler(
    entry: dict[str, Any],
    *,
    nix_store_executable: str,
) -> str:
    environment = entry.get("env")
    if not isinstance(environment, dict):
        raise TypeError("Nix derivation environment is not an object")
    compiler = environment.get("CC")
    if not isinstance(compiler, str) or not compiler:
        raise ValueError("Nix derivation metadata has no compiler identity")
    if Path(compiler).is_absolute():
        return compiler
    search_path = environment.get("PATH")
    if isinstance(search_path, str) and search_path:
        resolved = shutil.which(compiler, path=search_path)
        if resolved is not None:
            return resolved
    stdenv = environment.get("stdenv")
    if not isinstance(stdenv, str) or not stdenv:
        raise ValueError("Nix derivation metadata cannot resolve its compiler")
    references = (
        _capture_tool(
            [nix_store_executable, "--query", "--references", stdenv],
            "Nix stdenv references",
        )
        .decode("utf-8", "strict")
        .splitlines()
    )
    candidates = [
        Path(reference) / "bin" / compiler
        for reference in references
        if (Path(reference) / "bin" / compiler).is_file()
    ]
    if len(candidates) != 1:
        raise ValueError("Nix stdenv does not identify exactly one compiler")
    return str(candidates[0])


def _compiler_linker(compiler: str) -> str:
    value = (
        _capture_tool(
            [compiler, "-print-prog-name=ld"],
            "compiler linker path",
        )
        .decode("utf-8", "strict")
        .strip()
    )
    if not value:
        raise ValueError("compiler did not report its linker")
    candidate = Path(value)
    if candidate.is_absolute():
        return str(candidate)
    adjacent = Path(compiler).resolve().parent / value
    if adjacent.is_file():
        return str(adjacent)
    resolved = shutil.which(value)
    if resolved is None:
        raise ValueError("compiler reported a linker that cannot be resolved")
    return resolved


def _capture_tool(argv: list[str], description: str) -> bytes:
    try:
        process = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot read {description}: {error}") from error
    if process.returncode != 0:
        message = process.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"cannot read {description}: {message or process.returncode}")
    return process.stdout


def _verify_static_elf(
    header: bytes,
    program_headers: bytes,
    dynamic: bytes,
) -> dict[str, Any]:
    header_text = header.decode("utf-8", "strict")
    program_text = program_headers.decode("utf-8", "strict")
    dynamic_text = dynamic.decode("utf-8", "strict")
    elf_class = _readelf_field(header_text, "Class")
    machine = _readelf_field(header_text, "Machine")
    if re.search(r"^\s*INTERP\s", program_text, re.MULTILINE):
        raise ValueError("exported guest case has an ELF interpreter")
    if re.search(r"\(NEEDED\)", dynamic_text):
        raise ValueError("exported guest case has dynamic library dependencies")
    return {
        "elf_class": elf_class,
        "machine": machine,
        "interpreter": None,
        "dynamic_dependencies": [],
        "statically_linked": True,
    }


def _readelf_field(output: str, name: str) -> str:
    match = re.search(rf"^\s*{re.escape(name)}:\s*(.+)$", output, re.MULTILINE)
    if match is None:
        raise ValueError(f"ELF header has no {name} field")
    return match.group(1).strip()


def _tool_identity(executable: str, version: bytes) -> str:
    text = version.decode("utf-8", "strict").splitlines()
    if not text:
        raise ValueError(f"tool has no version output: {executable}")
    return f"{executable} ({text[0]})"


def _artifact(path: Path, root: Path) -> dict[str, str]:
    return {
        "path": str(path.relative_to(root)),
        "sha256": _sha256(path.read_bytes()),
    }


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _atomic_write_bytes(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return path


def _atomic_copy(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    with source.open("rb") as source_stream, temporary.open("xb") as destination_stream:
        shutil.copyfileobj(source_stream, destination_stream)
        destination_stream.flush()
        os.fsync(destination_stream.fileno())
    temporary.chmod(source.stat().st_mode & 0o777)
    os.replace(temporary, destination)
    return destination
