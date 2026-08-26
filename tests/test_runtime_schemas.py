from __future__ import annotations

import json
import unittest
from pathlib import Path

from aster_syssec.schemas import validate_instance

SHA256 = "a" * 64
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def normal_runtime_result() -> dict[str, object]:
    return {
        "schema_version": 1,
        "result_id": "RUNTIME-RESULT-0123456789ABCDEF",
        "request_id": "RUNTIME-REQUEST-0123456789ABCDEF",
        "request_sha256": SHA256,
        "target": "pipe-partial-efault-linux-diff",
        "platform": "asterinas",
        "outcome": "normal",
        "started_at": "2026-08-24T00:00:00Z",
        "finished_at": "2026-08-24T00:01:00Z",
        "duration_ms": 60_000,
        "process": {"exit_code": 0, "signal": None, "timed_out": False},
        "guest_result": {
            "case_id": "pipe-partial-efault-read",
            "exit_kind": "normal",
            "return": -1,
            "errno": 14,
        },
        "protocol_error": None,
        "tool": {"qemu": "10.1.0"},
        "artifacts": {
            "qemu_log": {"path": "qemu.log", "sha256": SHA256},
        },
        "diagnostics": [],
    }


class RuntimeSchemaTests(unittest.TestCase):
    def test_packaged_partial_efault_target_is_schema_valid(self) -> None:
        target_path = (
            PROJECT_ROOT
            / "src/aster_syssec/data/runtime-targets"
            / "pipe-partial-efault-linux-diff.json"
        )
        target = json.loads(target_path.read_text(encoding="utf-8"))

        validate_instance(target, "runtime-target.schema.json")

    def test_runtime_target_accepts_the_partial_efault_contract(self) -> None:
        target = {
            "schema_version": 1,
            "id": "pipe-partial-efault-linux-diff",
            "track": "user-memory-partial-io",
            "case_id": "pipe-partial-efault-read",
            "guest_case": "io/file_io/partial_efault_json",
            "target_arch": "x86_64",
            "properties": [
                "PARTIAL-PROGRESS-CONSISTENCY",
                "LINUX-ABI-CONTRACT",
            ],
            "source_symbols": ["SYS_read", "readv"],
            "oracle": "linux-x86-64",
            "comparator": "partial-efault-pipe-read-v1",
            "limits": {
                "boot_timeout_seconds": 120,
                "test_timeout_seconds": 30,
                "output_bytes": 1024 * 1024,
                "memory_bytes": 2 * 1024 * 1024 * 1024,
                "smp": 1,
            },
            "expected": "match",
        }

        validate_instance(target, "runtime-target.schema.json")

    def test_oracle_image_pins_linux_and_vm_inputs(self) -> None:
        image = {
            "schema_version": 1,
            "id": "linux-x86-64",
            "target_arch": "x86_64",
            "linux_revision": "1" * 40,
            "kernel_config": {"path": "oracle/linux.config", "sha256": SHA256},
            "kernel_image": {"path": "oracle/bzImage", "sha256": SHA256},
            "rootfs": {"path": "oracle/initramfs.cpio.gz", "sha256": SHA256},
            "qemu": {
                "executable": "qemu-system-x86_64",
                "version": "10.1.0",
                "sha256": SHA256,
                "machine": "q35",
                "cpu": "max",
                "acceleration": "tcg",
                "memory_bytes": 2 * 1024 * 1024 * 1024,
                "smp": 1,
            },
            "packer": {
                "executable": "syssec-initramfs-packer",
                "version": "syssec-initramfs-packer 1.0.0",
                "sha256": SHA256,
            },
        }

        validate_instance(image, "oracle-image.schema.json")

    def test_runtime_request_binds_source_binary_and_oracle_hashes(self) -> None:
        request = {
            "schema_version": 1,
            "request_id": "RUNTIME-REQUEST-0123456789ABCDEF",
            "created_at": "2026-08-24T00:00:00Z",
            "target": "pipe-partial-efault-linux-diff",
            "target_config_sha256": SHA256,
            "guest_case": "io/file_io/partial_efault_json",
            "target_arch": "x86_64",
            "platform": "asterinas",
            "source": {
                "path": "/source/asterinas",
                "revision": "1" * 40,
                "dirty_hash": "0" * 64,
            },
            "binary": {
                "path": "artifacts/partial_efault_json",
                "sha256": SHA256,
                "source_sha256": "b" * 64,
                "compiler": "clang 21.1.0",
                "linker": "LLD 21.1.0",
                "build_command": {
                    "argv": ["make", "build-initramfs"],
                    "cwd": "/source/asterinas",
                },
            },
            "oracle": {
                "id": "linux-x86-64",
                "metadata_sha256": "c" * 64,
            },
            "evidence_root": "/evidence/runtime-request",
            "execution": {
                "acceleration": "tcg",
                "host_forwarding": False,
                "memory_bytes": 2 * 1024 * 1024 * 1024,
                "smp": 1,
            },
            "limits": {
                "boot_timeout_seconds": 120,
                "test_timeout_seconds": 30,
                "output_bytes": 1024 * 1024,
            },
        }

        validate_instance(request, "runtime-request.schema.json")

    def test_runtime_result_records_a_normal_guest_execution(self) -> None:
        validate_instance(normal_runtime_result(), "runtime-result.schema.json")

    def test_normal_runtime_result_requires_a_guest_result(self) -> None:
        result = normal_runtime_result()
        result["guest_result"] = None

        with self.assertRaises(ValueError):
            validate_instance(result, "runtime-result.schema.json")

    def test_oracle_comparison_records_a_positive_contract_baseline(self) -> None:
        fields = [
            {
                "name": name,
                "relation": "equal",
                "asterinas": value,
                "linux": value,
                "matched": True,
            }
            for name, value in (
                ("return", -1),
                ("errno", 14),
                ("first_byte", 65),
                ("remaining_return", 2),
                ("remaining_errno", 0),
                ("remaining_byte_0", 65),
                ("remaining_byte_1", 66),
            )
        ]
        comparison = {
            "schema_version": 1,
            "comparison_id": "ORACLE-COMPARISON-0123456789ABCDEF",
            "compared_at": "2026-08-24T00:02:00Z",
            "target": "pipe-partial-efault-linux-diff",
            "case_id": "pipe-partial-efault-read",
            "comparator": "partial-efault-pipe-read-v1",
            "binary_sha256": SHA256,
            "asterinas_result": {
                "result_id": "RUNTIME-RESULT-0123456789ABCDEF",
                "sha256": "b" * 64,
            },
            "linux_result": {
                "result_id": "RUNTIME-RESULT-FEDCBA9876543210",
                "sha256": "c" * 64,
            },
            "status": "match",
            "disposition": "baseline",
            "fields": fields,
            "diagnostics": [],
        }

        validate_instance(comparison, "oracle-comparison.schema.json")

    def test_oracle_mismatch_cannot_be_promoted_past_candidate(self) -> None:
        comparison = {
            "schema_version": 1,
            "comparison_id": "ORACLE-COMPARISON-0123456789ABCDEF",
            "compared_at": "2026-08-24T00:02:00Z",
            "target": "pipe-partial-efault-linux-diff",
            "case_id": "pipe-partial-efault-read",
            "comparator": "partial-efault-pipe-read-v1",
            "binary_sha256": SHA256,
            "asterinas_result": {
                "result_id": "RUNTIME-RESULT-0123456789ABCDEF",
                "sha256": "b" * 64,
            },
            "linux_result": {
                "result_id": "RUNTIME-RESULT-FEDCBA9876543210",
                "sha256": "c" * 64,
            },
            "status": "mismatch",
            "disposition": "baseline",
            "fields": [
                {
                    "name": "errno",
                    "relation": "equal",
                    "asterinas": 14,
                    "linux": 0,
                    "matched": False,
                }
            ],
            "diagnostics": [],
        }

        with self.assertRaises(ValueError):
            validate_instance(comparison, "oracle-comparison.schema.json")

        comparison["disposition"] = "candidate"
        validate_instance(comparison, "oracle-comparison.schema.json")

        comparison["fields"][0]["matched"] = True
        with self.assertRaises(ValueError):
            validate_instance(comparison, "oracle-comparison.schema.json")

    def test_oracle_match_rejects_a_mismatched_field(self) -> None:
        comparison = {
            "schema_version": 1,
            "comparison_id": "ORACLE-COMPARISON-0123456789ABCDEF",
            "compared_at": "2026-08-24T00:02:00Z",
            "target": "pipe-partial-efault-linux-diff",
            "case_id": "pipe-partial-efault-read",
            "comparator": "partial-efault-pipe-read-v1",
            "binary_sha256": SHA256,
            "asterinas_result": {
                "result_id": "RUNTIME-RESULT-0123456789ABCDEF",
                "sha256": "b" * 64,
            },
            "linux_result": {
                "result_id": "RUNTIME-RESULT-FEDCBA9876543210",
                "sha256": "c" * 64,
            },
            "status": "match",
            "disposition": "baseline",
            "fields": [
                {
                    "name": "errno",
                    "relation": "equal",
                    "asterinas": 14,
                    "linux": 0,
                    "matched": False,
                }
            ],
            "diagnostics": [],
        }

        with self.assertRaises(ValueError):
            validate_instance(comparison, "oracle-comparison.schema.json")
