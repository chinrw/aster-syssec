from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aster_syssec.config import load_registry
from aster_syssec.runs import RunContext
from aster_syssec.source import inspect_source
from tests.helpers import init_git_repository, write_fixture


class RunContextTests(unittest.TestCase):
    def test_nested_non_git_source_does_not_inherit_parent_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source = write_fixture(parent / "source")
            init_git_repository(parent)

            snapshot = inspect_source(source)

        self.assertIsNone(snapshot.revision)
        self.assertEqual(snapshot.git_dir_kind, "absent")

    def test_writes_manifest_before_outputs_and_records_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            registry = load_registry()
            run = RunContext.start(
                work_root=base / "work",
                command="doctor",
                source_root=source,
                registry=registry,
                parameters={"example": True},
            )
            manifest = run.root / "run-manifest.json"
            self.assertTrue(manifest.exists())
            self.assertEqual(json.loads(manifest.read_text())["status"], "running")

            output = run.write_json("doctor.json", {"status": "ok"})
            run.complete([output])
            completed = json.loads(manifest.read_text())

        self.assertEqual(completed["status"], "completed")
        self.assertEqual(
            [item["path"] for item in completed["outputs"]], ["doctor.json"]
        )
        self.assertEqual(
            completed["outputs"][0]["size"], len('{\n  "status": "ok"\n}\n')
        )
        self.assertEqual(len(completed["outputs"][0]["sha256"]), 64)
        self.assertIsNotNone(completed["finished_at"])
        self.assertIn("reviewer", completed)
        self.assertEqual(len(completed["reviewer"]["content_sha256"]), 64)

    def test_completion_rejects_an_artifact_modified_after_registration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            run = RunContext.start(
                work_root=base / "work",
                command="doctor",
                source_root=source,
                registry=load_registry(),
                parameters={},
            )
            output = run.write_text("doctor/report.md", "original\n")
            output.write_text("tampered\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "changed after registration"):
                run.complete([output])

    def test_completion_rejects_a_source_change_after_run_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            run = RunContext.start(
                work_root=base / "work",
                command="inventory",
                source_root=source,
                registry=load_registry(),
                parameters={},
            )
            read = source / "kernel/core/src/syscall/read.rs"
            read.write_text(
                read.read_text(encoding="utf-8") + "\n// changed\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(ValueError, "source changed during run"):
                run.complete()

    def test_json_artifact_is_validated_against_its_declared_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            run = RunContext.start(
                work_root=base / "work",
                command="review",
                source_root=source,
                registry=load_registry(),
                parameters={},
            )

            with self.assertRaisesRegex(ValueError, "finding.schema.json"):
                run.write_json(
                    "review/invalid-finding.json",
                    {"schema_version": 1},
                    schema="finding.schema.json",
                )

    def test_run_cannot_transition_after_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            run = RunContext.start(
                work_root=base / "work",
                command="doctor",
                source_root=source,
                registry=load_registry(),
                parameters={},
            )
            run.complete()

            with self.assertRaisesRegex(ValueError, "already completed"):
                run.fail(RuntimeError("late failure"))


if __name__ == "__main__":
    unittest.main()
