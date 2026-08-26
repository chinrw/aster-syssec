from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from aster_syssec.runtime import LinuxOracleAdapter
from aster_syssec.schemas import validate_instance

GUEST_RESULT = {
    "case_id": "pipe-partial-efault-read",
    "exit_kind": "normal",
    "return": -1,
    "errno": 14,
    "first_byte": 65,
    "remaining_return": 2,
    "remaining_errno": 0,
    "remaining_byte_0": 65,
    "remaining_byte_1": 66,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\nset -eu\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _write_packer(path: Path) -> Path:
    return _write_executable(
        path,
        """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'syssec-initramfs-packer 1.0\n'
    exit 0
fi
[ "$1" = --base-rootfs ]
base_rootfs="$2"
[ "$3" = --binary ]
binary="$4"
[ "$5" = --output ]
output="$6"
printf 'derived-initramfs:' > "$output"
cat "$base_rootfs" "$binary" >> "$output"
printf 'packer stdout\n'
printf 'packer stderr\n' >&2
""",
    )


def _write_normal_qemu(path: Path) -> Path:
    return _write_executable(
        path,
        """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
args=" $* "
for expected in '-machine q35,accel=tcg' '-cpu max' '-m 128M' '-smp 1' '-nic none' '-nographic' '-no-reboot'; do
    case "$args" in
        *" $expected "*) ;;
        *) printf 'missing argument: %s\n' "$expected" >&2; exit 64 ;;
    esac
done
printf '%s\n' \
    'SYSSEC_GUEST_READY' \
    'SYSSEC_RESULT_BEGIN' \
    '{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}' \
    'SYSSEC_RESULT_END'
printf 'qemu stderr\n' >&2
""",
    )


def _write_oracle(root: Path, qemu: Path, packer: Path) -> Path:
    oracle_root = root / "oracle"
    inputs = oracle_root / "inputs"
    inputs.mkdir(parents=True)
    kernel_config = inputs / "linux.config"
    kernel_image = inputs / "bzImage"
    rootfs = inputs / "initramfs.cpio.gz"
    kernel_config.write_bytes(b"CONFIG_TCG_TCG2=y\n")
    kernel_image.write_bytes(b"linux-kernel-fixture\n")
    rootfs.write_bytes(b"base-initramfs-fixture\n")
    metadata = {
        "schema_version": 1,
        "id": "linux-x86-64",
        "target_arch": "x86_64",
        "linux_revision": "1" * 40,
        "kernel_config": {
            "path": str(kernel_config),
            "sha256": _sha256(kernel_config),
        },
        "kernel_image": {
            "path": str(kernel_image),
            "sha256": _sha256(kernel_image),
        },
        "rootfs": {"path": str(rootfs), "sha256": _sha256(rootfs)},
        "qemu": {
            "executable": str(qemu),
            "version": "QEMU emulator version 10.1.0",
            "sha256": _sha256(qemu),
            "machine": "q35",
            "cpu": "max",
            "acceleration": "tcg",
            "memory_bytes": 128 * 1024 * 1024,
            "smp": 1,
        },
        "packer": {
            "executable": str(packer),
            "version": "syssec-initramfs-packer 1.0",
            "sha256": _sha256(packer),
        },
    }
    metadata_path = oracle_root / "oracle-image.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metadata_path


def _runtime_request(
    root: Path,
    *,
    binary: Path,
    metadata: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "request_id": "RUNTIME-REQUEST-0123456789ABCDEF",
        "created_at": "2026-08-26T00:00:00Z",
        "target": "pipe-partial-efault-linux-diff",
        "target_config_sha256": "a" * 64,
        "guest_case": "io/file_io/partial_efault_json",
        "target_arch": "x86_64",
        "platform": "linux-oracle",
        "source": {
            "path": str(root / "asterinas-source"),
            "revision": "2" * 40,
            "dirty_hash": "0" * 64,
        },
        "binary": {
            "path": str(binary),
            "sha256": _sha256(binary),
            "source_sha256": "b" * 64,
            "compiler": "GCC fixture",
            "linker": "GNU ld fixture",
            "build_command": {
                "argv": ["make", "build-initramfs"],
                "cwd": str(root / "asterinas-source"),
            },
        },
        "oracle": {
            "id": "linux-x86-64",
            "metadata_sha256": _sha256(metadata),
        },
        "evidence_root": str(evidence_root),
        "execution": {
            "acceleration": "tcg",
            "host_forwarding": False,
            "memory_bytes": 128 * 1024 * 1024,
            "smp": 1,
        },
        "limits": {
            "boot_timeout_seconds": 2,
            "test_timeout_seconds": 2,
            "output_bytes": 64 * 1024,
        },
    }


class LinuxOracleAdapterTests(unittest.TestCase):
    def test_runs_the_exact_binary_in_a_pinned_networkless_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_normal_qemu(root / "qemu-system-x86_64")
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(request)

            self.assertEqual(result["platform"], "linux-oracle")
            self.assertEqual(result["outcome"], "normal")
            self.assertEqual(result["guest_result"], GUEST_RESULT)
            self.assertEqual(result["tool"]["binary_sha256"], _sha256(binary))
            self.assertEqual(result["tool"]["qemu"], "QEMU emulator version 10.1.0")
            self.assertEqual(result["tool"]["acceleration"], "tcg")
            validate_instance(result, "runtime-result.schema.json")
            self.assertEqual(
                json.loads((evidence_root / "runtime-result.json").read_text()),
                result,
            )
            for relative in (
                "runtime-request.json",
                "oracle-image.json",
                "artifacts/linux-execution.json",
                "artifacts/derived-initramfs.cpio.gz",
                "artifacts/packer-stdout.log",
                "artifacts/packer-stderr.log",
                "artifacts/qemu.log",
                "artifacts/qemu-stderr.log",
            ):
                self.assertTrue((evidence_root / relative).is_file(), relative)
            execution = json.loads(
                (evidence_root / "artifacts/linux-execution.json").read_text()
            )
            validate_instance(execution, "linux-execution.schema.json")
            self.assertEqual(execution["binary"]["sha256"], _sha256(binary))
            self.assertEqual(
                execution["derived_initramfs"]["sha256"],
                _sha256(evidence_root / "artifacts/derived-initramfs.cpio.gz"),
            )
            self.assertEqual(execution["qemu"]["argv"][-2:], ["-nic", "none"])
            for artifact in result["artifacts"].values():
                payload = (evidence_root / artifact["path"]).read_bytes()
                self.assertEqual(
                    artifact["sha256"], hashlib.sha256(payload).hexdigest()
                )

    def test_nonzero_exit_before_guest_ready_is_a_qemu_start_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
printf 'QEMU fixture failed before boot\n' >&2
exit 2
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(
                _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
            )

            self.assertEqual(result["outcome"], "qemu-start-failure")
            self.assertEqual(result["process"]["exit_code"], 2)
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_zero_exit_before_guest_ready_is_also_a_qemu_start_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
exit 0
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(
                _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
            )

            self.assertEqual(result["outcome"], "qemu-start-failure")
            self.assertEqual(result["process"]["exit_code"], 0)
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_missing_guest_ready_marker_is_a_boot_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
sleep 5
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )
            request["limits"]["boot_timeout_seconds"] = 1

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(request)

            self.assertEqual(result["outcome"], "guest-boot-timeout")
            self.assertTrue(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_kernel_panic_precedes_qemu_exit_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
printf 'Kernel panic - not syncing: fixture\n'
sleep 5
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(
                _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
            )

            self.assertEqual(result["outcome"], "guest-panic")
            self.assertFalse(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_ready_guest_without_case_progress_is_a_guest_hang(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
printf 'SYSSEC_GUEST_READY\n'
sleep 5
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )
            request["limits"]["test_timeout_seconds"] = 1

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(request)

            self.assertEqual(result["outcome"], "guest-hang")
            self.assertTrue(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_started_case_without_end_marker_is_a_test_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
printf '%s\n' 'SYSSEC_GUEST_READY' 'SYSSEC_RESULT_BEGIN'
sleep 5
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )
            request["limits"]["test_timeout_seconds"] = 1

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(request)

            self.assertEqual(result["outcome"], "test-timeout")
            self.assertTrue(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_exited_guest_with_invalid_markers_records_protocol_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
printf 'SYSSEC_GUEST_READY\n'
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(
                _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
            )

            self.assertEqual(result["outcome"], "invalid-protocol")
            self.assertEqual(
                result["protocol_error"]["code"],
                "missing-begin-marker",
            )
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_combined_qemu_output_limit_is_an_output_too_large_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
printf '%s\n' 'SYSSEC_GUEST_READY' 'SYSSEC_RESULT_BEGIN'
head -c 2048 /dev/zero | tr '\000' X >&2
sleep 5
""",
            )
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )
            request["limits"]["output_bytes"] = 1024

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(request)

            self.assertEqual(result["outcome"], "invalid-protocol")
            self.assertEqual(result["protocol_error"]["code"], "output-too-large")
            self.assertFalse(result["process"]["timed_out"])
            self.assertLessEqual(
                (evidence_root / "artifacts/qemu.log").stat().st_size
                + (evidence_root / "artifacts/qemu-stderr.log").stat().st_size,
                1024,
            )
            validate_instance(result, "runtime-result.schema.json")

    def test_declared_input_hashes_are_checked_before_evidence_creation(self) -> None:
        for changed_input in (
            "metadata",
            "binary",
            "kernel_config",
            "kernel_image",
            "rootfs",
            "qemu",
            "packer",
        ):
            with (
                self.subTest(changed_input=changed_input),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                binary = root / "partial_efault_json"
                binary.write_bytes(b"static-binary-fixture\n")
                binary.chmod(0o755)
                qemu = _write_normal_qemu(root / "qemu-system-x86_64")
                packer = _write_packer(root / "initramfs-packer")
                metadata = _write_oracle(root, qemu, packer)
                evidence_root = root / "evidence"
                request = _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
                if changed_input == "metadata":
                    metadata.write_text(
                        metadata.read_text(encoding="utf-8") + " ",
                        encoding="utf-8",
                    )
                elif changed_input == "binary":
                    binary.write_bytes(b"changed-static-binary\n")
                elif changed_input == "qemu":
                    qemu.write_text(
                        qemu.read_text(encoding="utf-8") + "# changed\n",
                        encoding="utf-8",
                    )
                elif changed_input == "packer":
                    packer.write_text(
                        packer.read_text(encoding="utf-8") + "# changed\n",
                        encoding="utf-8",
                    )
                else:
                    metadata_value = json.loads(metadata.read_text(encoding="utf-8"))
                    Path(metadata_value[changed_input]["path"]).write_bytes(
                        b"changed-oracle-input\n"
                    )

                with self.assertRaisesRegex(ValueError, "hash"):
                    LinuxOracleAdapter(
                        oracle_metadata_path=metadata,
                        initramfs_packer_executable=str(packer),
                    ).execute(request)

                self.assertFalse(evidence_root.exists())

    def test_evidence_root_cannot_be_inside_the_pinned_oracle_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_normal_qemu(root / "qemu-system-x86_64")
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = metadata.parent / "runtime-evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )

            with self.assertRaisesRegex(ValueError, "overlaps"):
                LinuxOracleAdapter(
                    oracle_metadata_path=metadata,
                    initramfs_packer_executable=str(packer),
                ).execute(request)

            self.assertFalse(evidence_root.exists())

    def test_qemu_version_mismatch_fails_before_evidence_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_normal_qemu(root / "qemu-system-x86_64")
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            metadata_value = json.loads(metadata.read_text(encoding="utf-8"))
            metadata_value["qemu"]["version"] = "QEMU emulator version 9.2.0"
            metadata.write_text(
                json.dumps(metadata_value, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )

            with self.assertRaisesRegex(ValueError, "QEMU version"):
                LinuxOracleAdapter(
                    oracle_metadata_path=metadata,
                    initramfs_packer_executable=str(packer),
                ).execute(request)

            self.assertFalse(evidence_root.exists())

    def test_semantic_qemu_version_metadata_matches_the_tool_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu = _write_normal_qemu(root / "qemu-system-x86_64")
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            metadata_value = json.loads(metadata.read_text(encoding="utf-8"))
            metadata_value["qemu"]["version"] = "10.1.0"
            metadata.write_text(
                json.dumps(metadata_value, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            evidence_root = root / "evidence"

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(
                _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
            )

            self.assertEqual(result["outcome"], "normal")
            self.assertEqual(result["tool"]["qemu"], "QEMU emulator version 10.1.0")

    def test_packer_cannot_change_the_verified_static_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu_started = root / "qemu-started"
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                f"""if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
touch '{qemu_started}'
printf '%s\n' \
    'SYSSEC_GUEST_READY' \
    'SYSSEC_RESULT_BEGIN' \
    '{{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}}' \
    'SYSSEC_RESULT_END'
""",
            )
            packer = _write_executable(
                root / "initramfs-packer",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'syssec-initramfs-packer 1.0\n'
    exit 0
fi
printf 'changed-by-packer\n' > "$4"
printf 'derived-initramfs\n' > "$6"
""",
            )
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )

            with self.assertRaisesRegex(
                ValueError,
                "changed during initramfs packing",
            ):
                LinuxOracleAdapter(
                    oracle_metadata_path=metadata,
                    initramfs_packer_executable=str(packer),
                ).execute(request)

            self.assertFalse(qemu_started.exists())
            self.assertFalse((evidence_root / "runtime-result.json").exists())

    def test_packer_output_limit_stops_before_qemu(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            qemu_started = root / "qemu-started"
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                f"""if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
touch '{qemu_started}'
""",
            )
            packer = _write_executable(
                root / "initramfs-packer",
                """if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'syssec-initramfs-packer 1.0\n'
    exit 0
fi
head -c 2048 /dev/zero | tr '\000' X >&2
sleep 5
""",
            )
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"
            request = _runtime_request(
                root,
                binary=binary,
                metadata=metadata,
                evidence_root=evidence_root,
            )
            request["limits"]["output_bytes"] = 1024

            with self.assertRaisesRegex(ValueError, "output exceeds"):
                LinuxOracleAdapter(
                    oracle_metadata_path=metadata,
                    initramfs_packer_executable=str(packer),
                ).execute(request)

            self.assertFalse(qemu_started.exists())
            self.assertLessEqual(
                (evidence_root / "artifacts/packer-stdout.log").stat().st_size
                + (evidence_root / "artifacts/packer-stderr.log").stat().st_size,
                1024,
            )

    def test_packer_cannot_escape_evidence_with_a_derived_rootfs_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            outside = root / "outside-initramfs"
            outside.write_bytes(b"outside-rootfs\n")
            qemu_started = root / "qemu-started"
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                f"""if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
touch '{qemu_started}'
""",
            )
            packer = _write_executable(
                root / "initramfs-packer",
                f"""if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'syssec-initramfs-packer 1.0\n'
    exit 0
fi
ln -s '{outside}' "$6"
""",
            )
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"

            with self.assertRaisesRegex(ValueError, "regular file"):
                LinuxOracleAdapter(
                    oracle_metadata_path=metadata,
                    initramfs_packer_executable=str(packer),
                ).execute(
                    _runtime_request(
                        root,
                        binary=binary,
                        metadata=metadata,
                        evidence_root=evidence_root,
                    )
                )

            self.assertFalse(qemu_started.exists())

    def test_packer_and_qemu_writable_environment_stays_under_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            evidence_root = root / "evidence"
            expected_tmp = evidence_root / "tmp"
            expected_home = expected_tmp / "home"
            qemu = _write_executable(
                root / "qemu-system-x86_64",
                f"""if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'QEMU emulator version 10.1.0\n'
    exit 0
fi
[ "$TMPDIR" = '{expected_tmp}' ]
[ "$HOME" = '{expected_home}' ]
printf '%s\n' \
    'SYSSEC_GUEST_READY' \
    'SYSSEC_RESULT_BEGIN' \
    '{{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}}' \
    'SYSSEC_RESULT_END'
""",
            )
            packer = _write_executable(
                root / "initramfs-packer",
                f"""if [ "$#" -eq 1 ] && [ "$1" = --version ]; then
    printf 'syssec-initramfs-packer 1.0\n'
    exit 0
fi
[ "$TMPDIR" = '{expected_tmp}' ]
[ "$HOME" = '{expected_home}' ]
printf 'derived-initramfs\n' > "$6"
""",
            )
            metadata = _write_oracle(root, qemu, packer)

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(
                _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
            )

            self.assertEqual(result["outcome"], "normal")
            execution = json.loads(
                (evidence_root / "artifacts/linux-execution.json").read_text()
            )
            self.assertEqual(
                execution["packer"]["environment"]["HOME"],
                str(expected_home),
            )
            self.assertEqual(
                execution["qemu"]["environment"]["TMPDIR"],
                str(expected_tmp),
            )

    def test_complete_result_terminates_the_entire_qemu_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "partial_efault_json"
            binary.write_bytes(b"static-binary-fixture\n")
            binary.chmod(0o755)
            survivor = root / "qemu-child-survived"
            qemu = root / "qemu-system-x86_64"
            qemu.write_text(
                f"""#!{sys.executable}
import os
import signal
import sys
import time
from pathlib import Path

if sys.argv[1:] == ["--version"]:
    print("QEMU emulator version 10.1.0")
    raise SystemExit(0)
ready_read, ready_write = os.pipe()
if os.fork() == 0:
    os.close(ready_read)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    os.write(ready_write, b"1")
    os.close(ready_write)
    time.sleep(2)
    Path({str(survivor)!r}).touch()
    os._exit(0)
os.close(ready_write)
os.read(ready_read, 1)
os.close(ready_read)
print("SYSSEC_GUEST_READY")
print("SYSSEC_RESULT_BEGIN")
print('{{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}}')
print("SYSSEC_RESULT_END", flush=True)
time.sleep(5)
""",
                encoding="utf-8",
            )
            qemu.chmod(0o755)
            packer = _write_packer(root / "initramfs-packer")
            metadata = _write_oracle(root, qemu, packer)
            evidence_root = root / "evidence"

            result = LinuxOracleAdapter(
                oracle_metadata_path=metadata,
                initramfs_packer_executable=str(packer),
            ).execute(
                _runtime_request(
                    root,
                    binary=binary,
                    metadata=metadata,
                    evidence_root=evidence_root,
                )
            )
            time.sleep(2.3)

            self.assertEqual(result["outcome"], "normal")
            self.assertEqual(result["process"]["signal"], 15)
            self.assertFalse(survivor.exists())
