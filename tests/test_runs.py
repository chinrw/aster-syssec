from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aster_syssec.config import load_registry
from aster_syssec.runs import RunContext
from tests.helpers import write_fixture


class RunContextTests(unittest.TestCase):
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
        self.assertEqual(completed["outputs"], ["doctor.json"])
        self.assertIsNotNone(completed["finished_at"])


if __name__ == "__main__":
    unittest.main()
