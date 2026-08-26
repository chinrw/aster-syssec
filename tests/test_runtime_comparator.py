from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aster_syssec.runtime import PartialEfaultComparator
from aster_syssec.schemas import validate_instance

BINARY_SHA256 = "a" * 64
FIELDS = {
    "return": -1,
    "errno": 14,
    "first_byte": 65,
    "remaining_return": 2,
    "remaining_errno": 0,
    "remaining_byte_0": 65,
    "remaining_byte_1": 66,
}


def _runtime_result(
    platform: str,
    *,
    result_id: str,
    fields: dict[str, int] | None = None,
    binary_sha256: str | None = BINARY_SHA256,
    outcome: str = "normal",
) -> dict[str, Any]:
    guest_result: dict[str, Any] | None
    protocol_error: dict[str, str] | None
    if outcome == "normal":
        guest_result = {
            "case_id": "pipe-partial-efault-read",
            "exit_kind": "normal",
            **(FIELDS if fields is None else fields),
        }
        protocol_error = None
    else:
        guest_result = None
        protocol_error = {
            "code": "missing-begin-marker",
            "message": "guest output has no result begin marker",
        }
    tool = {"qemu": "fixture"}
    if binary_sha256 is not None:
        tool["binary_sha256"] = binary_sha256
    return {
        "schema_version": 1,
        "result_id": result_id,
        "request_id": "RUNTIME-REQUEST-0123456789ABCDEF",
        "request_sha256": "b" * 64,
        "target": "pipe-partial-efault-linux-diff",
        "platform": platform,
        "outcome": outcome,
        "started_at": "2026-08-26T00:00:00Z",
        "finished_at": "2026-08-26T00:00:01Z",
        "duration_ms": 1000,
        "process": {"exit_code": 0, "signal": None, "timed_out": False},
        "guest_result": guest_result,
        "protocol_error": protocol_error,
        "tool": tool,
        "artifacts": {},
        "diagnostics": [],
    }


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


class PartialEfaultComparatorTests(unittest.TestCase):
    def _compare(
        self,
        root: Path,
        *,
        asterinas: dict[str, Any] | None = None,
        linux: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], Path, Path, Path]:
        asterinas_path = _write_json(
            root / "asterinas-result.json",
            asterinas
            or _runtime_result(
                "asterinas",
                result_id="RUNTIME-RESULT-AAAAAAAAAAAAAAAA",
            ),
        )
        linux_path = _write_json(
            root / "linux-result.json",
            linux
            or _runtime_result(
                "linux-oracle",
                result_id="RUNTIME-RESULT-BBBBBBBBBBBBBBBB",
            ),
        )
        output_path = root / "oracle-comparison.json"
        comparison = PartialEfaultComparator().compare(
            asterinas_result_path=asterinas_path,
            linux_result_path=linux_path,
            output_path=output_path,
        )
        return comparison, asterinas_path, linux_path, output_path

    def test_matching_contract_becomes_a_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            comparison, asterinas_path, linux_path, output_path = self._compare(
                Path(directory)
            )

            self.assertEqual(comparison["status"], "match")
            self.assertEqual(comparison["disposition"], "baseline")
            self.assertEqual(comparison["binary_sha256"], BINARY_SHA256)
            self.assertTrue(all(field["matched"] for field in comparison["fields"]))
            self.assertEqual(
                comparison["asterinas_result"]["sha256"],
                hashlib.sha256(asterinas_path.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                comparison["linux_result"]["sha256"],
                hashlib.sha256(linux_path.read_bytes()).hexdigest(),
            )
            self.assertEqual(json.loads(output_path.read_text()), comparison)
            validate_instance(comparison, "oracle-comparison.schema.json")

    def test_field_difference_remains_a_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            linux_fields = {**FIELDS, "errno": 0}
            linux = _runtime_result(
                "linux-oracle",
                result_id="RUNTIME-RESULT-BBBBBBBBBBBBBBBB",
                fields=linux_fields,
            )

            comparison, _, _, _ = self._compare(Path(directory), linux=linux)

            self.assertEqual(comparison["status"], "mismatch")
            self.assertEqual(comparison["disposition"], "candidate")
            errno = next(
                field for field in comparison["fields"] if field["name"] == "errno"
            )
            self.assertFalse(errno["matched"])
            validate_instance(comparison, "oracle-comparison.schema.json")

    def test_nonnormal_runtime_result_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            linux = _runtime_result(
                "linux-oracle",
                result_id="RUNTIME-RESULT-BBBBBBBBBBBBBBBB",
                outcome="invalid-protocol",
            )

            comparison, _, _, _ = self._compare(Path(directory), linux=linux)

            self.assertEqual(comparison["status"], "incomplete")
            self.assertEqual(comparison["disposition"], "incomplete")
            self.assertIn(
                "linux-oracle outcome is invalid-protocol", comparison["diagnostics"]
            )
            validate_instance(comparison, "oracle-comparison.schema.json")

    def test_missing_or_different_binary_provenance_is_incomplete(self) -> None:
        cases = {
            "missing": None,
            "different": "c" * 64,
        }
        for name, asterinas_binary in cases.items():
            with (
                self.subTest(name=name),
                tempfile.TemporaryDirectory() as directory,
            ):
                asterinas = _runtime_result(
                    "asterinas",
                    result_id="RUNTIME-RESULT-AAAAAAAAAAAAAAAA",
                    binary_sha256=asterinas_binary,
                )

                comparison, _, _, _ = self._compare(
                    Path(directory),
                    asterinas=asterinas,
                )

                self.assertEqual(comparison["status"], "incomplete")
                self.assertEqual(comparison["binary_sha256"], None)
                validate_instance(comparison, "oracle-comparison.schema.json")

    def test_wrong_platform_is_rejected_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            linux = _runtime_result(
                "asterinas",
                result_id="RUNTIME-RESULT-BBBBBBBBBBBBBBBB",
            )

            with self.assertRaisesRegex(ValueError, "linux-oracle platform"):
                self._compare(root, linux=linux)

            self.assertFalse((root / "oracle-comparison.json").exists())

    def test_existing_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "oracle-comparison.json"
            output.write_text("keep\n", encoding="utf-8")
            asterinas = _write_json(
                root / "asterinas-result.json",
                _runtime_result(
                    "asterinas",
                    result_id="RUNTIME-RESULT-AAAAAAAAAAAAAAAA",
                ),
            )
            linux = _write_json(
                root / "linux-result.json",
                _runtime_result(
                    "linux-oracle",
                    result_id="RUNTIME-RESULT-BBBBBBBBBBBBBBBB",
                ),
            )

            with self.assertRaisesRegex(ValueError, "already exists"):
                PartialEfaultComparator().compare(
                    asterinas_result_path=asterinas,
                    linux_result_path=linux,
                    output_path=output,
                )

            self.assertEqual(output.read_text(encoding="utf-8"), "keep\n")
