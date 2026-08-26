from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..engine_results import evidence_id
from ..schemas import validate_instance
from ..source import atomic_write_json
from .protocol import (
    BEGIN_MARKER,
    END_MARKER,
    GuestProtocolError,
    parse_guest_result,
)

_BOOT_MARKER = b"SYSSEC_GUEST_READY"
_PANIC_MARKERS = (b"kernel panic", b"panicked at ")
_TERMINATION_GRACE_SECONDS = 1.0


@dataclass(frozen=True)
class _ProcessObservation:
    qemu_log_path: Path
    stderr_path: Path
    returncode: int | None
    timed_out: bool
    duration_ms: int
    start_error: str | None = None
    timeout_phase: str | None = None
    stop_reason: str | None = None


class LinuxOracleAdapter:
    def __init__(
        self,
        *,
        oracle_metadata_path: str | Path,
        initramfs_packer_executable: str,
    ) -> None:
        self._oracle_metadata_path = Path(oracle_metadata_path).resolve()
        self._initramfs_packer_executable = initramfs_packer_executable

    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_value = json.loads(json.dumps(request, ensure_ascii=False))
        validate_instance(request_value, "runtime-request.schema.json")
        if request_value["platform"] != "linux-oracle":
            raise ValueError("Linux oracle adapter requires platform=linux-oracle")

        metadata_bytes = self._read_metadata(request_value)
        metadata = json.loads(metadata_bytes)
        validate_instance(metadata, "oracle-image.schema.json")
        self._require_matching_configuration(request_value, metadata)

        metadata_root = self._oracle_metadata_path.parent
        kernel_config = _resolve_input(metadata["kernel_config"]["path"], metadata_root)
        kernel_image = _resolve_input(metadata["kernel_image"]["path"], metadata_root)
        base_rootfs = _resolve_input(metadata["rootfs"]["path"], metadata_root)
        binary = Path(request_value["binary"]["path"]).resolve(strict=True)
        qemu = _resolve_executable(metadata["qemu"]["executable"])
        packer = _resolve_executable(self._initramfs_packer_executable)
        pinned_packer = _resolve_executable(metadata["packer"]["executable"])
        if packer != pinned_packer:
            raise ValueError("initramfs packer does not match oracle metadata")
        inputs = (
            (kernel_config, metadata["kernel_config"]["sha256"], "kernel config"),
            (kernel_image, metadata["kernel_image"]["sha256"], "kernel image"),
            (base_rootfs, metadata["rootfs"]["sha256"], "base rootfs"),
            (binary, request_value["binary"]["sha256"], "static binary"),
        )
        for path, expected_sha256, label in inputs:
            _require_file_hash(path, expected_sha256, label)
        if binary.stat().st_mode & 0o111 == 0:
            raise ValueError("Linux oracle static binary is not executable")

        output_limit = request_value["limits"]["output_bytes"]
        qemu_version = _tool_version(qemu, output_limit=output_limit)
        if not _qemu_version_matches(qemu_version, metadata["qemu"]["version"]):
            raise ValueError("QEMU version does not match oracle metadata")
        packer_version = _tool_version(packer, output_limit=output_limit)
        qemu_sha256 = _sha256_file(qemu)
        packer_sha256 = _sha256_file(packer)
        if qemu_sha256 != metadata["qemu"]["sha256"]:
            raise ValueError("QEMU hash does not match oracle metadata")
        if packer_version != metadata["packer"]["version"]:
            raise ValueError("initramfs packer version does not match oracle metadata")
        if packer_sha256 != metadata["packer"]["sha256"]:
            raise ValueError("initramfs packer hash does not match oracle metadata")

        evidence_root = Path(request_value["evidence_root"]).resolve()
        _require_disjoint_inputs(
            evidence_root,
            (
                metadata_root,
                self._oracle_metadata_path,
                kernel_config,
                kernel_image,
                base_rootfs,
                binary,
                qemu,
                packer,
            ),
        )
        evidence_root.mkdir(parents=True, exist_ok=False)
        artifacts_root = evidence_root / "artifacts"
        temporary_root = evidence_root / "tmp"
        artifacts_root.mkdir()
        temporary_root.mkdir()

        request_path = atomic_write_json(
            evidence_root / "runtime-request.json",
            request_value,
        )
        request_sha256 = _sha256(request_path.read_bytes())
        metadata_copy = _atomic_write_bytes(
            evidence_root / "oracle-image.json",
            metadata_bytes,
        )
        derived_initramfs = artifacts_root / "derived-initramfs.cpio.gz"
        packer_stdout = artifacts_root / "packer-stdout.log"
        packer_stderr = artifacts_root / "packer-stderr.log"
        packer_argv = [
            str(packer),
            "--base-rootfs",
            str(base_rootfs),
            "--binary",
            str(binary),
            "--output",
            str(derived_initramfs),
        ]
        _run_packer(
            packer_argv,
            cwd=evidence_root,
            temporary_root=temporary_root,
            timeout_seconds=request_value["limits"]["boot_timeout_seconds"],
            output_limit=output_limit,
            stdout_path=packer_stdout,
            stderr_path=packer_stderr,
        )
        for path, expected_sha256, label in inputs:
            if _sha256_file(path) != expected_sha256:
                raise ValueError(
                    f"Linux oracle {label} changed during initramfs packing"
                )
        if derived_initramfs.is_symlink() or not derived_initramfs.is_file():
            raise ValueError("derived initramfs must be a regular file under evidence")
        if not derived_initramfs.resolve(strict=True).is_relative_to(evidence_root):
            raise ValueError("derived initramfs must be a regular file under evidence")
        derived_sha256 = _sha256_file(derived_initramfs)

        qemu_log = artifacts_root / "qemu.log"
        qemu_stderr = artifacts_root / "qemu-stderr.log"
        qemu_argv = _qemu_command(
            qemu,
            metadata,
            kernel_image=kernel_image,
            derived_initramfs=derived_initramfs,
        )
        execution = {
            "schema_version": 1,
            "request_id": request_value["request_id"],
            "request_sha256": request_sha256,
            "oracle": {
                "id": metadata["id"],
                "metadata_sha256": _sha256(metadata_bytes),
                "linux_revision": metadata["linux_revision"],
                "kernel_config": {
                    "path": str(kernel_config),
                    "sha256": metadata["kernel_config"]["sha256"],
                },
                "kernel_image": {
                    "path": str(kernel_image),
                    "sha256": metadata["kernel_image"]["sha256"],
                },
                "base_rootfs": {
                    "path": str(base_rootfs),
                    "sha256": metadata["rootfs"]["sha256"],
                },
            },
            "binary": {
                "path": str(binary),
                "sha256": request_value["binary"]["sha256"],
                "source_sha256": request_value["binary"]["source_sha256"],
            },
            "derived_initramfs": {
                "path": str(derived_initramfs.relative_to(evidence_root)),
                "sha256": derived_sha256,
            },
            "packer": {
                "executable": str(packer),
                "version": packer_version,
                "sha256": packer_sha256,
                "argv": packer_argv,
                "cwd": str(evidence_root),
                "environment": _writable_environment(temporary_root),
            },
            "qemu": {
                "executable": str(qemu),
                "version": qemu_version,
                "sha256": qemu_sha256,
                "argv": qemu_argv,
                "cwd": str(evidence_root),
                "environment": _writable_environment(temporary_root),
                "machine": metadata["qemu"]["machine"],
                "cpu": metadata["qemu"]["cpu"],
                "acceleration": metadata["qemu"]["acceleration"],
                "memory_bytes": metadata["qemu"]["memory_bytes"],
                "smp": metadata["qemu"]["smp"],
            },
        }
        validate_instance(execution, "linux-execution.schema.json")
        execution_path = atomic_write_json(
            artifacts_root / "linux-execution.json",
            execution,
        )

        started_at = datetime.now(UTC)
        observation = _run_qemu(
            qemu_argv,
            cwd=evidence_root,
            temporary_root=temporary_root,
            boot_timeout_seconds=request_value["limits"]["boot_timeout_seconds"],
            test_timeout_seconds=request_value["limits"]["test_timeout_seconds"],
            output_limit=output_limit,
            qemu_log_path=qemu_log,
            stderr_path=qemu_stderr,
        )
        finished_at = datetime.now(UTC)
        output = qemu_log.read_bytes()
        artifacts = {
            "request": _artifact(request_path, evidence_root),
            "oracle_metadata": _artifact(metadata_copy, evidence_root),
            "execution": _artifact(execution_path, evidence_root),
            "derived_initramfs": _artifact(derived_initramfs, evidence_root),
            "packer_stdout": _artifact(packer_stdout, evidence_root),
            "packer_stderr": _artifact(packer_stderr, evidence_root),
            "qemu_log": _artifact(qemu_log, evidence_root),
            "qemu_stderr": _artifact(qemu_stderr, evidence_root),
        }
        tool = {
            "qemu": qemu_version,
            "qemu_executable": str(qemu),
            "qemu_sha256": qemu_sha256,
            "machine": metadata["qemu"]["machine"],
            "cpu": metadata["qemu"]["cpu"],
            "acceleration": metadata["qemu"]["acceleration"],
            "memory_bytes": str(metadata["qemu"]["memory_bytes"]),
            "smp": str(metadata["qemu"]["smp"]),
            "initramfs_packer": packer_version,
            "initramfs_packer_executable": str(packer),
            "initramfs_packer_sha256": packer_sha256,
            "oracle_metadata_sha256": _sha256(metadata_bytes),
            "kernel_config_sha256": metadata["kernel_config"]["sha256"],
            "kernel_image_sha256": metadata["kernel_image"]["sha256"],
            "base_rootfs_sha256": metadata["rootfs"]["sha256"],
            "derived_initramfs_sha256": derived_sha256,
            "binary_sha256": request_value["binary"]["sha256"],
        }
        if observation.start_error is not None:
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="qemu-start-failure",
                guest_result=None,
                protocol_error=None,
                tool=tool,
                artifacts=artifacts,
                diagnostics=[observation.start_error],
            )
        if _has_guest_panic(output):
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="guest-panic",
                guest_result=None,
                protocol_error=None,
                tool=tool,
                artifacts=artifacts,
                diagnostics=["Linux oracle log contains a kernel panic marker"],
            )
        if observation.stop_reason == "output-too-large":
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="invalid-protocol",
                guest_result=None,
                protocol_error={
                    "code": "output-too-large",
                    "message": "combined QEMU output exceeds the configured limit",
                },
                tool=tool,
                artifacts=artifacts,
                diagnostics=["Linux oracle QEMU output exceeded its limit"],
            )
        if observation.timeout_phase == "boot":
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="guest-boot-timeout",
                guest_result=None,
                protocol_error=None,
                tool=tool,
                artifacts=artifacts,
                diagnostics=["Linux oracle guest was not ready before the deadline"],
            )
        if observation.returncode is not None and _BOOT_MARKER not in output:
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="qemu-start-failure",
                guest_result=None,
                protocol_error=None,
                tool=tool,
                artifacts=artifacts,
                diagnostics=["QEMU exited before the Linux oracle guest was ready"],
            )
        if (
            observation.timeout_phase == "test"
            and BEGIN_MARKER.encode("ascii") not in output
        ):
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="guest-hang",
                guest_result=None,
                protocol_error=None,
                tool=tool,
                artifacts=artifacts,
                diagnostics=["Linux oracle guest was ready but made no case progress"],
            )
        if observation.timeout_phase == "test":
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="test-timeout",
                guest_result=None,
                protocol_error=None,
                tool=tool,
                artifacts=artifacts,
                diagnostics=["Linux oracle guest case exceeded its deadline"],
            )
        if observation.timeout_phase is not None:
            raise ValueError(
                f"Linux oracle timed out during {observation.timeout_phase}"
            )

        try:
            guest_result = parse_guest_result(
                output,
                max_output_bytes=output_limit,
            )
        except GuestProtocolError as error:
            return _write_result(
                request=request_value,
                request_sha256=request_sha256,
                evidence_root=evidence_root,
                started_at=started_at,
                finished_at=finished_at,
                observation=observation,
                outcome="invalid-protocol",
                guest_result=None,
                protocol_error={"code": error.code, "message": str(error)},
                tool=tool,
                artifacts=artifacts,
                diagnostics=[f"Linux oracle guest protocol error: {error.code}"],
            )
        return _write_result(
            request=request_value,
            request_sha256=request_sha256,
            evidence_root=evidence_root,
            started_at=started_at,
            finished_at=finished_at,
            observation=observation,
            outcome="normal",
            guest_result=guest_result,
            protocol_error=None,
            tool=tool,
            artifacts=artifacts,
            diagnostics=(
                ["stopped after complete guest result"]
                if observation.stop_reason == "result-complete"
                else []
            ),
        )

    def _read_metadata(self, request: dict[str, Any]) -> bytes:
        try:
            payload = self._oracle_metadata_path.read_bytes()
        except OSError as error:
            raise ValueError("cannot read Linux oracle metadata") from error
        if _sha256(payload) != request["oracle"]["metadata_sha256"]:
            raise ValueError("Linux oracle metadata hash does not match request")
        return payload

    @staticmethod
    def _require_matching_configuration(
        request: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        if metadata["id"] != request["oracle"]["id"]:
            raise ValueError("Linux oracle ID does not match runtime request")
        if metadata["target_arch"] != request["target_arch"]:
            raise ValueError("Linux oracle architecture does not match runtime request")
        for field in ("acceleration", "memory_bytes", "smp"):
            if metadata["qemu"][field] != request["execution"][field]:
                raise ValueError(f"Linux oracle {field} does not match runtime request")


def _write_result(
    *,
    request: dict[str, Any],
    request_sha256: str,
    evidence_root: Path,
    started_at: datetime,
    finished_at: datetime,
    observation: _ProcessObservation,
    outcome: str,
    guest_result: dict[str, object] | None,
    protocol_error: dict[str, str] | None,
    tool: dict[str, str],
    artifacts: dict[str, dict[str, str]],
    diagnostics: list[str],
) -> dict[str, Any]:
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
        "platform": "linux-oracle",
        "outcome": outcome,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": observation.duration_ms,
        "process": _process_result(observation),
        "guest_result": guest_result,
        "protocol_error": protocol_error,
        "tool": tool,
        "artifacts": artifacts,
        "diagnostics": diagnostics,
    }
    validate_instance(result, "runtime-result.schema.json")
    atomic_write_json(evidence_root / "runtime-result.json", result)
    return result


def _run_packer(
    argv: list[str],
    *,
    cwd: Path,
    temporary_root: Path,
    timeout_seconds: int,
    output_limit: int,
    stdout_path: Path,
    stderr_path: Path,
) -> None:
    environment = _isolated_environment(temporary_root)
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except OSError as error:
            raise ValueError(f"cannot start initramfs packer: {error}") from error
        started = time.monotonic()
        stop_reason: str | None = None
        while process.poll() is None:
            if stdout_path.stat().st_size + stderr_path.stat().st_size > output_limit:
                stop_reason = "output-too-large"
                _stop_process_group(process)
                break
            if time.monotonic() - started >= timeout_seconds:
                stop_reason = "timeout"
                _stop_process_group(process)
                break
            time.sleep(0.05)
        process.wait()
    if stdout_path.stat().st_size + stderr_path.stat().st_size > output_limit:
        stop_reason = "output-too-large"
        _bound_combined_output(
            stdout_path,
            stderr_path,
            output_limit=output_limit,
        )
    if stop_reason == "output-too-large":
        raise ValueError("initramfs packer output exceeds the limit")
    if stop_reason == "timeout":
        raise ValueError("initramfs packer timed out")
    if process.returncode != 0:
        raise ValueError(f"initramfs packer exited {process.returncode}")


def _run_qemu(
    argv: list[str],
    *,
    cwd: Path,
    temporary_root: Path,
    boot_timeout_seconds: int,
    test_timeout_seconds: int,
    output_limit: int,
    qemu_log_path: Path,
    stderr_path: Path,
) -> _ProcessObservation:
    environment = _isolated_environment(temporary_root)
    started = time.monotonic()
    with qemu_log_path.open("wb") as qemu_log, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=environment,
                stdout=qemu_log,
                stderr=stderr,
                start_new_session=True,
            )
        except OSError as error:
            duration_ms = max(0, round((time.monotonic() - started) * 1000))
            message = f"cannot start Linux oracle QEMU: {error}"
            stderr.write(message.encode("utf-8", "replace"))
            return _ProcessObservation(
                qemu_log_path=qemu_log_path,
                stderr_path=stderr_path,
                returncode=None,
                timed_out=False,
                duration_ms=duration_ms,
                start_error=message,
            )

        boot_seen_at: float | None = None
        timeout_phase: str | None = None
        stop_reason: str | None = None
        while process.poll() is None:
            now = time.monotonic()
            if qemu_log_path.stat().st_size + stderr_path.stat().st_size > output_limit:
                stop_reason = "output-too-large"
                _stop_process_group(process)
                break
            output = _read_bounded(qemu_log_path, output_limit=output_limit)
            if _has_guest_panic(output):
                stop_reason = "guest-panic"
                _stop_process_group(process)
                break
            if END_MARKER.encode("ascii") in output:
                stop_reason = "result-complete"
                _stop_process_group(process)
                break
            if boot_seen_at is None and _BOOT_MARKER in output:
                boot_seen_at = now
            if boot_seen_at is None and now - started >= boot_timeout_seconds:
                timeout_phase = "boot"
                _stop_process_group(process)
                break
            if boot_seen_at is not None and now - boot_seen_at >= test_timeout_seconds:
                timeout_phase = "test"
                _stop_process_group(process)
                break
            time.sleep(0.05)
        process.wait()
    if qemu_log_path.stat().st_size + stderr_path.stat().st_size > output_limit:
        stop_reason = "output-too-large"
        _bound_combined_output(
            qemu_log_path,
            stderr_path,
            output_limit=output_limit,
        )
    duration_ms = max(0, round((time.monotonic() - started) * 1000))
    return _ProcessObservation(
        qemu_log_path=qemu_log_path,
        stderr_path=stderr_path,
        returncode=process.returncode,
        timed_out=timeout_phase is not None,
        duration_ms=duration_ms,
        timeout_phase=timeout_phase,
        stop_reason=stop_reason,
    )


def _qemu_command(
    executable: Path,
    metadata: dict[str, Any],
    *,
    kernel_image: Path,
    derived_initramfs: Path,
) -> list[str]:
    qemu = metadata["qemu"]
    return [
        str(executable),
        "-machine",
        f"{qemu['machine']},accel={qemu['acceleration']}",
        "-cpu",
        qemu["cpu"],
        "-m",
        _memory_argument(qemu["memory_bytes"]),
        "-smp",
        str(qemu["smp"]),
        "-kernel",
        str(kernel_image),
        "-initrd",
        str(derived_initramfs),
        "-append",
        "console=ttyS0 panic=-1",
        "-nographic",
        "-no-reboot",
        "-nic",
        "none",
    ]


def _tool_version(executable: Path, *, output_limit: int) -> str:
    try:
        process = subprocess.run(
            [str(executable), "--version"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot read tool version: {executable}") from error
    output = process.stdout + process.stderr
    if process.returncode != 0 or len(output) > output_limit:
        raise ValueError(f"cannot read tool version: {executable}")
    lines = output.decode("utf-8", "replace").splitlines()
    if not lines:
        raise ValueError(f"tool version is empty: {executable}")
    return lines[0].strip()


def _qemu_version_matches(identity: str, expected: str) -> bool:
    if identity == expected:
        return True
    match = re.search(r"\bversion\s+([^\s]+)", identity, re.IGNORECASE)
    return match is not None and match.group(1) == expected


def _resolve_input(value: str, metadata_root: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = metadata_root / path
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"Linux oracle input is missing: {value}") from error
    if not resolved.is_file():
        raise ValueError(f"Linux oracle input is not a file: {value}")
    return resolved


def _writable_environment(temporary_root: Path) -> dict[str, str]:
    return {
        "TMPDIR": str(temporary_root),
        "HOME": str(temporary_root / "home"),
        "XDG_CACHE_HOME": str(temporary_root / "xdg-cache"),
        "XDG_CONFIG_HOME": str(temporary_root / "xdg-config"),
        "XDG_STATE_HOME": str(temporary_root / "xdg-state"),
    }


def _isolated_environment(temporary_root: Path) -> dict[str, str]:
    writable = _writable_environment(temporary_root)
    for value in writable.values():
        Path(value).mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(writable)
    return environment


def _resolve_executable(value: str) -> Path:
    candidate = shutil.which(value)
    if candidate is None:
        raise ValueError(f"executable is unavailable: {value}")
    path = Path(candidate).resolve(strict=True)
    if not path.is_file() or path.stat().st_mode & 0o111 == 0:
        raise ValueError(f"executable is unavailable: {value}")
    return path


def _require_file_hash(path: Path, expected: str, label: str) -> None:
    if _sha256_file(path) != expected:
        raise ValueError(f"Linux oracle {label} hash does not match metadata")


def _require_disjoint_inputs(evidence_root: Path, inputs: tuple[Path, ...]) -> None:
    for item in inputs:
        if evidence_root == item or evidence_root.is_relative_to(item):
            raise ValueError("Linux oracle evidence root overlaps a pinned input")
        if item.is_relative_to(evidence_root):
            raise ValueError("Linux oracle evidence root contains a pinned input")


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        process.poll()
        if not _process_group_exists(process_group):
            return
        time.sleep(0.02)
    if _process_group_exists(process_group):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_bounded(path: Path, *, output_limit: int) -> bytes:
    with path.open("rb") as stream:
        return stream.read(output_limit + 1)


def _bound_combined_output(
    qemu_log_path: Path,
    stderr_path: Path,
    *,
    output_limit: int,
) -> None:
    remaining = output_limit
    for path in (qemu_log_path, stderr_path):
        with path.open("r+b") as stream:
            retained = stream.read(remaining)
            stream.seek(0)
            stream.write(retained)
            stream.truncate()
        remaining -= len(retained)


def _has_guest_panic(output: bytes) -> bool:
    lowered = output.lower()
    return any(marker in lowered for marker in _PANIC_MARKERS)


def _memory_argument(memory_bytes: int) -> str:
    mebibyte = 1024 * 1024
    if memory_bytes % mebibyte:
        raise ValueError("QEMU memory_bytes must be a whole number of MiB")
    return f"{memory_bytes // mebibyte}M"


def _process_result(observation: _ProcessObservation) -> dict[str, int | bool | None]:
    return {
        "exit_code": (
            observation.returncode
            if observation.returncode is not None and observation.returncode >= 0
            else None
        ),
        "signal": (
            -observation.returncode
            if observation.returncode is not None and observation.returncode < 0
            else None
        ),
        "timed_out": observation.timed_out,
    }


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
        "sha256": _sha256_file(path),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
