from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
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
from .protocol import BEGIN_MARKER, END_MARKER, GuestProtocolError, parse_guest_result

_BOOT_MARKER = b"[kernel] running /init as the init process"
_PANIC_MARKERS = (b"kernel panic", b"panicked at ")


@dataclass(frozen=True)
class _ProcessObservation:
    stdout_path: Path
    stderr_path: Path
    returncode: int | None
    timed_out: bool
    duration_ms: int
    start_error: str | None = None
    timeout_phase: str | None = None
    stop_reason: str | None = None


class AsterinasQemuAdapter:
    def __init__(
        self,
        *,
        make_executable: str = "make",
        cargo_osdk_executable: str | None = None,
    ) -> None:
        self._make_executable = make_executable
        self._cargo_osdk_executable = cargo_osdk_executable or _installed_cargo_osdk()

    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_value = json.loads(json.dumps(request, ensure_ascii=False))
        validate_instance(request_value, "runtime-request.schema.json")
        if request_value["platform"] != "asterinas":
            raise ValueError("Asterinas QEMU adapter requires platform=asterinas")

        source_root = Path(request_value["source"]["path"]).resolve()
        evidence_root = Path(request_value["evidence_root"]).resolve()
        require_disjoint_paths(source_root, evidence_root)
        self._require_source(request_value, source_root)
        evidence_root.mkdir(parents=True, exist_ok=False)

        request_path = atomic_write_json(
            evidence_root / "runtime-request.json",
            request_value,
        )
        request_sha256 = _sha256(request_path.read_bytes())
        checkout = evidence_root / "checkout"
        _clone_source(source_root, checkout, request_value["source"]["revision"])

        build_root = evidence_root / "build/cargo-target"
        temporary_root = evidence_root / "tmp"
        artifacts_root = evidence_root / "artifacts"
        build_root.mkdir(parents=True)
        temporary_root.mkdir(parents=True)
        artifacts_root.mkdir(parents=True)
        stdout_path = artifacts_root / "stdout.log"
        stderr_path = artifacts_root / "stderr.log"
        environment = os.environ.copy()
        environment.update(
            {
                "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_DIR": str(build_root),
                "TMPDIR": str(temporary_root),
                "QEMU_HOSTFWD": "off",
                "RUSTUP_SKIP_UPDATE_CHECK": "1",
                "RUSTUP_TOOLCHAIN": _rust_toolchain(checkout),
            }
        )
        argv = _make_command(
            self._make_executable,
            request_value,
            cargo_osdk_executable=self._cargo_osdk_executable,
        )

        started_at = datetime.now(UTC)
        observation = _run_make(
            argv,
            cwd=checkout,
            environment=environment,
            boot_timeout_seconds=request_value["limits"]["boot_timeout_seconds"],
            test_timeout_seconds=request_value["limits"]["test_timeout_seconds"],
            max_output_bytes=request_value["limits"]["output_bytes"],
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        finished_at = datetime.now(UTC)

        qemu_log_path = checkout / "qemu.log"
        qemu_log = _read_qemu_log(
            qemu_log_path,
            max_output_bytes=request_value["limits"]["output_bytes"],
        )
        if observation.start_error is not None:
            return self._write_result(
                request=request_value,
                request_path=request_path,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="qemu-start-failure",
                guest_result=None,
                protocol_error=None,
                qemu_log=qemu_log,
                diagnostics=[observation.start_error],
            )
        if qemu_log is not None and _has_guest_panic(qemu_log):
            return self._write_result(
                request=request_value,
                request_path=request_path,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="guest-panic",
                guest_result=None,
                protocol_error=None,
                qemu_log=qemu_log,
                diagnostics=["guest log contains a kernel panic marker"],
            )
        if observation.timeout_phase == "boot":
            return self._write_result(
                request=request_value,
                request_path=request_path,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="guest-boot-timeout",
                guest_result=None,
                protocol_error=None,
                qemu_log=qemu_log,
                diagnostics=["guest did not reach init before the boot deadline"],
            )
        if observation.returncode not in (None, 0) and _BOOT_MARKER not in (
            qemu_log or b""
        ):
            return self._write_result(
                request=request_value,
                request_path=request_path,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="qemu-start-failure",
                guest_result=None,
                protocol_error=None,
                qemu_log=qemu_log,
                diagnostics=["Asterinas QEMU wrapper exited before guest init"],
            )
        if observation.timeout_phase == "test":
            case_started = BEGIN_MARKER.encode("ascii") in (qemu_log or b"")
            outcome = "test-timeout" if case_started else "guest-hang"
            diagnostic = (
                "guest case did not finish before the test deadline"
                if case_started
                else "guest reached init but made no case progress before the deadline"
            )
            return self._write_result(
                request=request_value,
                request_path=request_path,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome=outcome,
                guest_result=None,
                protocol_error=None,
                qemu_log=qemu_log,
                diagnostics=[diagnostic],
            )

        try:
            guest_result = parse_guest_result(
                qemu_log or b"",
                max_output_bytes=request_value["limits"]["output_bytes"],
            )
        except GuestProtocolError as error:
            return self._write_result(
                request=request_value,
                request_path=request_path,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="invalid-protocol",
                guest_result=None,
                protocol_error={"code": error.code, "message": str(error)},
                qemu_log=qemu_log,
                diagnostics=[f"guest protocol error: {error.code}"],
            )
        return self._write_result(
            request=request_value,
            request_path=request_path,
            request_sha256=request_sha256,
            evidence_root=evidence_root,
            started_at=started_at,
            finished_at=finished_at,
            observation=observation,
            outcome="normal",
            guest_result=guest_result,
            protocol_error=None,
            qemu_log=qemu_log,
            diagnostics=(
                ["stopped after complete guest result"]
                if observation.stop_reason == "result-complete"
                else []
            ),
        )

    def _write_result(
        self,
        *,
        request: dict[str, Any],
        request_path: Path,
        request_sha256: str,
        evidence_root: Path,
        started_at: datetime,
        finished_at: datetime,
        observation: _ProcessObservation,
        outcome: str,
        guest_result: dict[str, object] | None,
        protocol_error: dict[str, str] | None,
        qemu_log: bytes | None,
        diagnostics: list[str],
    ) -> dict[str, Any]:
        artifacts = {
            "request": _artifact(request_path, evidence_root),
            "stdout": _artifact(observation.stdout_path, evidence_root),
            "stderr": _artifact(observation.stderr_path, evidence_root),
        }
        if qemu_log is not None:
            qemu_log_path = _atomic_write_bytes(
                evidence_root / "artifacts/qemu.log", qemu_log
            )
            artifacts["qemu_log"] = _artifact(qemu_log_path, evidence_root)
        result_seed = {
            "request_id": request["request_id"],
            "outcome": outcome,
            "process": observation.returncode,
            "guest_result": guest_result,
        }
        result = {
            "schema_version": 1,
            "result_id": evidence_id("RUNTIME-RESULT", result_seed),
            "request_id": request["request_id"],
            "request_sha256": request_sha256,
            "target": request["target"],
            "platform": "asterinas",
            "outcome": outcome,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": observation.duration_ms,
            "process": {
                "exit_code": (
                    observation.returncode
                    if observation.returncode is not None
                    and observation.returncode >= 0
                    else None
                ),
                "signal": (
                    -observation.returncode
                    if observation.returncode is not None and observation.returncode < 0
                    else None
                ),
                "timed_out": observation.timed_out,
            },
            "guest_result": guest_result,
            "protocol_error": protocol_error,
            "tool": {
                "make": self._make_executable,
                "cargo_osdk": self._cargo_osdk_executable,
                "qemu": None,
            },
            "artifacts": artifacts,
            "diagnostics": diagnostics,
        }
        validate_instance(result, "runtime-result.schema.json")
        atomic_write_json(evidence_root / "runtime-result.json", result)
        return result

    @staticmethod
    def _require_source(request: dict[str, Any], source_root: Path) -> None:
        ensure_asterinas_checkout(source_root)
        guest_case = request["guest_case"]
        required = (
            source_root / "Makefile",
            source_root / "test/initramfs/src/regression/scripts/run_syssec_case.sh",
            source_root / f"test/initramfs/src/regression/{guest_case}.c",
        )
        missing = [
            str(path.relative_to(source_root))
            for path in required
            if not path.is_file()
        ]
        if missing:
            raise ValueError(f"Asterinas runtime seam is missing: {', '.join(missing)}")

        snapshot = inspect_source(source_root)
        expected = request["source"]
        if snapshot.revision != expected["revision"]:
            raise ValueError("Asterinas source revision does not match runtime request")
        if snapshot.dirty_hash != expected["dirty_hash"]:
            raise ValueError(
                "Asterinas source dirty hash does not match runtime request"
            )
        if snapshot.dirty_entries:
            raise ValueError("Asterinas runtime execution requires a clean checkout")


def _run_make(
    argv: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    boot_timeout_seconds: int,
    test_timeout_seconds: int,
    max_output_bytes: int,
    stdout_path: Path,
    stderr_path: Path,
) -> _ProcessObservation:
    started = time.monotonic()
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
            duration_ms = max(0, round((time.monotonic() - started) * 1000))
            message = f"cannot start Asterinas QEMU wrapper: {error}"
            stderr.write(message.encode("utf-8", "replace"))
            return _ProcessObservation(
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                returncode=None,
                timed_out=False,
                duration_ms=duration_ms,
                start_error=message,
            )

        timeout_phase: str | None = None
        stop_reason: str | None = None
        boot_seen_at: float | None = None
        qemu_log_path = cwd / "qemu.log"
        while process.poll() is None:
            now = time.monotonic()
            if (
                qemu_log_path.is_file()
                and qemu_log_path.stat().st_size > max_output_bytes
            ):
                stop_reason = "output-too-large"
                _kill_process_group(process)
                break
            qemu_log = (
                _read_qemu_log(qemu_log_path, max_output_bytes=max_output_bytes) or b""
            )
            if _has_guest_panic(qemu_log):
                stop_reason = "guest-panic"
                _kill_process_group(process)
                break
            if END_MARKER.encode("ascii") in qemu_log:
                stop_reason = "result-complete"
                _kill_process_group(process)
                break
            if boot_seen_at is None and _BOOT_MARKER in qemu_log:
                boot_seen_at = now
            if boot_seen_at is None and now - started >= boot_timeout_seconds:
                timeout_phase = "boot"
                _kill_process_group(process)
                break
            if boot_seen_at is not None and now - boot_seen_at >= test_timeout_seconds:
                timeout_phase = "test"
                _kill_process_group(process)
                break
            time.sleep(0.05)

        process.wait()
    duration_ms = max(0, round((time.monotonic() - started) * 1000))
    return _ProcessObservation(
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        returncode=process.returncode,
        timed_out=timeout_phase is not None,
        duration_ms=duration_ms,
        timeout_phase=timeout_phase,
        stop_reason=stop_reason,
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _has_guest_panic(qemu_log: bytes) -> bool:
    lowered = qemu_log.lower()
    return any(marker in lowered for marker in _PANIC_MARKERS)


def _read_qemu_log(path: Path, *, max_output_bytes: int) -> bytes | None:
    if not path.is_file():
        return None
    with path.open("rb") as stream:
        return stream.read(max_output_bytes + 1)


def _clone_source(source_root: Path, checkout: Path, revision: str) -> None:
    commands = (
        [
            "git",
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            str(source_root),
            str(checkout),
        ],
        ["git", "-C", str(checkout), "checkout", "--detach", revision],
    )
    for command in commands:
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=120,
        )
        if process.returncode != 0:
            message = process.stderr.decode("utf-8", "replace").strip()
            raise ValueError(f"cannot create isolated Asterinas checkout: {message}")


def _make_command(
    make_executable: str,
    request: dict[str, Any],
    *,
    cargo_osdk_executable: str | None,
) -> list[str]:
    execution = request["execution"]
    command = [make_executable]
    if cargo_osdk_executable is not None:
        command.append(f"--assume-old={cargo_osdk_executable}")
    command.extend(
        [
            "run_kernel",
            "AUTO_TEST=syssec",
            f"SYSSEC_CASE={request['guest_case']}",
            f"TARGET_ARCH={request['target_arch']}",
            f"ENABLE_KVM={1 if execution['acceleration'] == 'kvm' else 0}",
            "QEMU_HOSTFWD=off",
            f"SMP={execution['smp']}",
            f"MEM={_memory_argument(execution['memory_bytes'])}",
        ]
    )
    if cargo_osdk_executable is not None:
        command.append(f"CARGO_OSDK={cargo_osdk_executable}")
    return command


def _installed_cargo_osdk() -> str | None:
    candidate = Path.home() / ".cargo/bin/cargo-osdk"
    return str(candidate) if candidate.is_file() else None


def _rust_toolchain(checkout: Path) -> str:
    path = checkout / "rust-toolchain.toml"
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
        channel = value["toolchain"]["channel"]
    except (KeyError, OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError("cannot resolve the Asterinas Rust toolchain") from error
    if not isinstance(channel, str) or not channel:
        raise ValueError("Asterinas Rust toolchain channel is empty")
    return channel


def _memory_argument(memory_bytes: int) -> str:
    mebibyte = 1024 * 1024
    if memory_bytes % mebibyte:
        raise ValueError("QEMU memory_bytes must be a whole number of MiB")
    return f"{memory_bytes // mebibyte}M"


def _atomic_write_bytes(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return path


def _artifact(path: Path, root: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256(path.read_bytes()),
    }


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
