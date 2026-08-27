from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aster_syssec.runtime import AsterinasQemuAdapter
from aster_syssec.schemas import validate_instance
from aster_syssec.source import inspect_source
from tests.helpers import init_git_repository, write_fixture

SHA256 = "a" * 64
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


def _newc_entry(name: str, payload: bytes, mode: int) -> bytes:
    name_payload = name.encode() + b"\0"
    fields = (
        1,
        mode,
        0,
        0,
        1,
        0,
        len(payload),
        0,
        0,
        0,
        0,
        len(name_payload),
        0,
    )
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    name_padding = b"\0" * (-(len(header) + len(name_payload)) % 4)
    data_padding = b"\0" * (-len(payload) % 4)
    return header + name_payload + name_padding + payload + data_padding


def _write_initramfs_fixture(path: Path, binary: bytes) -> None:
    member = "nix/store/fixture-io-test/io/file_io/partial_efault_json"
    archive = _newc_entry(member, binary, 0o100755)
    archive += _newc_entry("TRAILER!!!", b"", 0)
    path.write_bytes(gzip.compress(archive, mtime=0))


def write_runtime_source(root: Path) -> Path:
    write_fixture(root)
    files = {
        "Makefile": "run_kernel:\n\t@true\n",
        "test/initramfs/src/regression/scripts/run_syssec_case.sh": (
            '#!/bin/sh\nexec "$1"\n'
        ),
        "test/initramfs/src/regression/io/file_io/partial_efault_json.c": (
            "int main(void) { return 0; }\n"
        ),
        "artifacts/partial_efault_json": "#!/bin/sh\nexit 0\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "artifacts/partial_efault_json").chmod(0o755)
    _write_initramfs_fixture(
        root / "artifacts/initramfs.cpio.gz",
        (root / "artifacts/partial_efault_json").read_bytes(),
    )
    init_git_repository(root)
    return root


def runtime_request(source: Path, evidence_root: Path) -> dict[str, Any]:
    snapshot = inspect_source(source)
    binary = source / "artifacts/partial_efault_json"
    source_case = (
        source / "test/initramfs/src/regression/io/file_io/partial_efault_json.c"
    )
    return {
        "schema_version": 1,
        "request_id": "RUNTIME-REQUEST-0123456789ABCDEF",
        "created_at": "2026-08-25T00:00:00Z",
        "target": "pipe-partial-efault-linux-diff",
        "target_config_sha256": SHA256,
        "guest_case": "io/file_io/partial_efault_json",
        "target_arch": "x86_64",
        "platform": "asterinas",
        "source": {
            "path": str(source),
            "revision": snapshot.revision,
            "dirty_hash": snapshot.dirty_hash,
        },
        "binary": {
            "path": str(binary),
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source_sha256": hashlib.sha256(source_case.read_bytes()).hexdigest(),
            "compiler": "clang fixture",
            "linker": "lld fixture",
            "build_command": {
                "argv": ["make", "build-initramfs"],
                "cwd": str(source),
            },
        },
        "oracle": {
            "id": "linux-x86-64",
            "metadata_sha256": "c" * 64,
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


def write_normal_make(path: Path) -> Path:
    path.write_text(
        """#!/bin/sh
set -eu
guest_binary=test/initramfs/build/initramfs/test/io/file_io/partial_efault_json
mkdir -p "$(dirname "$guest_binary")"
cp artifacts/partial_efault_json "$guest_binary"
chmod 0755 "$guest_binary"
args=" $* "
[ "${RUSTUP_TOOLCHAIN:-}" = nightly-test ] || exit 65
[ "${CARGO_NET_OFFLINE:-}" = true ] || exit 66
for expected in run_kernel AUTO_TEST=syssec SYSSEC_CASE=io/file_io/partial_efault_json TARGET_ARCH=x86_64 ENABLE_KVM=0 QEMU_HOSTFWD=off SMP=1 MEM=128M; do
    case "$args" in
        *" $expected "*) ;;
        *) echo "missing argument: $expected" >&2; exit 64 ;;
    esac
done
printf '%s\n' \
    '[kernel] running /init as the init process' \
    'SYSSEC_RESULT_BEGIN' \
    '{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}' \
    'SYSSEC_RESULT_END' > qemu.log
printf 'make stdout\n'
printf 'make stderr\n' >&2
""",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def write_make(path: Path, body: str) -> Path:
    prefix = """#!/bin/sh
set -eu
guest_binary=test/initramfs/build/initramfs/test/io/file_io/partial_efault_json
mkdir -p "$(dirname "$guest_binary")"
cp artifacts/partial_efault_json "$guest_binary"
chmod 0755 "$guest_binary"
"""
    path.write_text(prefix + body, encoding="utf-8")
    path.chmod(0o755)
    return path


class AsterinasQemuAdapterTests(unittest.TestCase):
    def test_normal_guest_result_is_recorded_without_dirtying_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_normal_make(root / "fake-make")

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "normal")
            self.assertEqual(result["guest_result"], GUEST_RESULT)
            self.assertEqual(
                result["tool"]["binary_sha256"],
                runtime_request(source, root / "unused")["binary"]["sha256"],
            )
            validate_instance(result, "runtime-result.schema.json")
            self.assertEqual(
                json.loads((evidence_root / "runtime-result.json").read_text()),
                result,
            )
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=source,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )
            for relative in (
                "runtime-request.json",
                "artifacts/stdout.log",
                "artifacts/stderr.log",
                "artifacts/qemu.log",
            ):
                self.assertTrue((evidence_root / relative).is_file(), relative)
            request_payload = (evidence_root / "runtime-request.json").read_bytes()
            self.assertEqual(
                result["request_sha256"],
                hashlib.sha256(request_payload).hexdigest(),
            )
            for artifact in result["artifacts"].values():
                payload = (evidence_root / artifact["path"]).read_bytes()
                self.assertEqual(
                    artifact["sha256"], hashlib.sha256(payload).hexdigest()
                )

    def test_normal_result_rejects_a_different_guest_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """printf 'different guest binary\n' > "$guest_binary"
chmod 0755 "$guest_binary"
printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'SYSSEC_RESULT_BEGIN' \\
    '{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}' \\
    'SYSSEC_RESULT_END' > qemu.log
""",
            )

            with self.assertRaisesRegex(ValueError, "guest binary hash"):
                AsterinasQemuAdapter(make_executable=str(make)).execute(
                    runtime_request(source, evidence_root)
                )

            self.assertFalse((evidence_root / "runtime-result.json").exists())

    def test_normal_result_verifies_binary_from_boot_initramfs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """rm -rf test/initramfs/build/initramfs
mkdir -p "$CARGO_TARGET_DIR/osdk/iso_root/boot"
cp artifacts/initramfs.cpio.gz \
    "$CARGO_TARGET_DIR/osdk/iso_root/boot/initramfs.cpio.gz"
printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'SYSSEC_RESULT_BEGIN' \\
    '{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}' \\
    'SYSSEC_RESULT_END' > qemu.log
""",
            )

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "normal")
            self.assertEqual(
                result["artifacts"]["verified_guest_binary"]["sha256"],
                runtime_request(source, root / "unused")["binary"]["sha256"],
            )
            self.assertEqual(
                result["tool"]["guest_binary_member"],
                "nix/store/fixture-io-test/io/file_io/partial_efault_json",
            )

    def test_complete_guest_result_stops_a_wrapper_that_does_not_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'SYSSEC_RESULT_BEGIN' \\
    '{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}' \\
    'SYSSEC_RESULT_END' > qemu.log
sleep 5
""",
            )

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "normal")
            self.assertFalse(result["process"]["timed_out"])
            self.assertIn(
                "stopped after complete guest result",
                result["diagnostics"],
            )
            validate_instance(result, "runtime-result.schema.json")

    def test_large_build_output_does_not_block_guest_supervision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """head -c 1048576 /dev/zero
printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'SYSSEC_RESULT_BEGIN' \\
    '{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}' \\
    'SYSSEC_RESULT_END' > qemu.log
""",
            )

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "normal")
            self.assertGreater(
                (evidence_root / "artifacts/stdout.log").stat().st_size,
                64 * 1024,
            )
            validate_instance(result, "runtime-result.schema.json")

    def test_pinned_cargo_osdk_is_not_rebuilt_by_the_isolated_clone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """args=" $* "
for expected in --assume-old=/opt/cargo-osdk CARGO_OSDK=/opt/cargo-osdk; do
    case "$args" in
        *" $expected "*) ;;
        *) echo "missing argument: $expected" >&2; exit 64 ;;
    esac
done
printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'SYSSEC_RESULT_BEGIN' \\
    '{"case_id":"pipe-partial-efault-read","exit_kind":"normal"}' \\
    'SYSSEC_RESULT_END' > qemu.log
""",
            )

            result = AsterinasQemuAdapter(
                make_executable=str(make),
                cargo_osdk_executable="/opt/cargo-osdk",
                build_environment="asterinas/dev@sha256:" + "a" * 64,
            ).execute(runtime_request(source, evidence_root))

            self.assertEqual(result["outcome"], "normal")
            self.assertEqual(
                result["tool"]["build_environment"],
                "asterinas/dev@sha256:" + "a" * 64,
            )
            validate_instance(result, "runtime-result.schema.json")

    def test_process_start_failure_is_recorded_as_a_runtime_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"

            result = AsterinasQemuAdapter(
                make_executable=str(root / "missing-make")
            ).execute(runtime_request(source, evidence_root))

            self.assertEqual(result["outcome"], "qemu-start-failure")
            self.assertIsNone(result["guest_result"])
            self.assertFalse(result["process"]["timed_out"])
            validate_instance(result, "runtime-result.schema.json")
            self.assertTrue((evidence_root / "runtime-result.json").is_file())

    def test_nonzero_exit_before_boot_is_recorded_as_start_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                "printf 'build failed\\n' >&2\nexit 2\n",
            )

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "qemu-start-failure")
            self.assertEqual(result["process"]["exit_code"], 2)
            self.assertFalse(result["process"]["timed_out"])
            validate_instance(result, "runtime-result.schema.json")

    def test_missing_boot_marker_is_recorded_as_a_boot_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(root / "fake-make", "sleep 5\n")
            request = runtime_request(source, evidence_root)
            request["limits"]["boot_timeout_seconds"] = 1

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(request)

            self.assertEqual(result["outcome"], "guest-boot-timeout")
            self.assertTrue(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_kernel_panic_is_recorded_without_waiting_for_a_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'Kernel panic - not syncing: fixture' > qemu.log
sleep 5
""",
            )

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "guest-panic")
            self.assertFalse(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_pre_init_kernel_panic_takes_precedence_over_start_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """printf '%s\n' \\
    'Kernel panic - not syncing: early fixture' > qemu.log
sleep 5
""",
            )

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "guest-panic")
            self.assertFalse(result["process"]["timed_out"])
            validate_instance(result, "runtime-result.schema.json")

    def test_booted_guest_without_case_progress_is_recorded_as_a_hang(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """printf '%s\n' \\
    '[kernel] running /init as the init process' > qemu.log
sleep 5
""",
            )
            request = runtime_request(source, evidence_root)
            request["limits"]["test_timeout_seconds"] = 1

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(request)

            self.assertEqual(result["outcome"], "guest-hang")
            self.assertTrue(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_started_case_without_end_marker_is_recorded_as_test_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'SYSSEC_RESULT_BEGIN' > qemu.log
sleep 5
""",
            )
            request = runtime_request(source, evidence_root)
            request["limits"]["test_timeout_seconds"] = 1

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(request)

            self.assertEqual(result["outcome"], "test-timeout")
            self.assertTrue(result["process"]["timed_out"])
            self.assertIsNone(result["guest_result"])
            validate_instance(result, "runtime-result.schema.json")

    def test_exited_guest_with_invalid_protocol_records_the_parser_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                "printf '%s\n' '[kernel] running /init as the init process' > qemu.log\n",
            )

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(
                runtime_request(source, evidence_root)
            )

            self.assertEqual(result["outcome"], "invalid-protocol")
            self.assertEqual(
                result["protocol_error"]["code"],
                "missing-begin-marker",
            )
            self.assertIsNone(result["guest_result"])
            self.assertFalse(result["process"]["timed_out"])
            validate_instance(result, "runtime-result.schema.json")

    def test_oversized_guest_log_is_stopped_and_recorded_as_invalid_protocol(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_runtime_source(root / "source")
            evidence_root = root / "evidence"
            make = write_make(
                root / "fake-make",
                """printf '%s\n' \\
    '[kernel] running /init as the init process' \\
    'SYSSEC_RESULT_BEGIN' > qemu.log
head -c 2048 /dev/zero | tr '\\000' X >> qemu.log
sleep 5
""",
            )
            request = runtime_request(source, evidence_root)
            request["limits"]["output_bytes"] = 1024

            result = AsterinasQemuAdapter(make_executable=str(make)).execute(request)

            self.assertEqual(result["outcome"], "invalid-protocol")
            self.assertEqual(result["protocol_error"]["code"], "output-too-large")
            self.assertFalse(result["process"]["timed_out"])
            validate_instance(result, "runtime-result.schema.json")
