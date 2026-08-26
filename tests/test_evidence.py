from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aster_syssec.cli import main
from aster_syssec.config import load_registry
from aster_syssec.runs import RunContext
from tests.helpers import write_fixture


class EvidencePackTests(unittest.TestCase):
    def test_pack_copies_only_verified_manifest_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "evidence"
            run = RunContext.start(
                work_root=work,
                command="run-profile",
                source_root=source,
                registry=load_registry(),
                parameters={"profile": "nightly"},
            )
            result = run.write_json("profile/result.json", {"status": "pass"})
            run.complete([result])
            (work / "cache/kani").mkdir(parents=True)
            (work / "cache/kani/bundle.tar.gz").write_bytes(b"not evidence")
            (run.root / "build").mkdir()
            (run.root / "build/rebuildable.o").write_bytes(b"not evidence")
            output = base / "upload"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "evidence",
                        "pack",
                        "--work-root",
                        str(work),
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            summary = json.loads(stdout.getvalue())
            index = json.loads((output / "evidence-pack.json").read_text())
            relative_run = run.root.relative_to(work)
            manifest_copied = (output / relative_run / "run-manifest.json").is_file()
            result_copied = (output / relative_run / "profile/result.json").is_file()
            cache_copied = (output / "cache").exists()
            build_copied = (output / relative_run / "build").exists()

        self.assertEqual(status, 0)
        self.assertEqual(summary["manifests"], 1)
        self.assertEqual(summary["files"], 3)
        self.assertEqual(len(summary["content_sha256"]), 64)
        self.assertEqual(index["content_sha256"], summary["content_sha256"])
        self.assertEqual(len(index["files"]), 2)
        self.assertTrue(manifest_copied)
        self.assertTrue(result_copied)
        self.assertFalse(cache_copied)
        self.assertFalse(build_copied)

    def test_pack_rejects_a_symlink_output_without_writing_its_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "evidence"
            run = RunContext.start(
                work_root=work,
                command="run-profile",
                source_root=source,
                registry=load_registry(),
                parameters={"profile": "nightly"},
            )
            run.write_json("profile/result.json", {"status": "pass"})
            run.complete()
            target = base / "outside"
            output = base / "upload"
            output.symlink_to(target, target_is_directory=True)
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "evidence",
                        "pack",
                        "--work-root",
                        str(work),
                        "--output",
                        str(output),
                    ]
                )

            target_created = target.exists()

        self.assertEqual(status, 2)
        self.assertFalse(target_created)
        self.assertIn("must not be a symlink", stderr.getvalue())

    def test_pack_rejects_a_tampered_registered_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "evidence"
            run = RunContext.start(
                work_root=work,
                command="run-profile",
                source_root=source,
                registry=load_registry(),
                parameters={"profile": "nightly"},
            )
            result = run.write_json("profile/result.json", {"status": "pass"})
            run.complete()
            result.write_text('{"status":"tampered"}\n', encoding="utf-8")
            output = base / "upload"
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "evidence",
                        "pack",
                        "--work-root",
                        str(work),
                        "--output",
                        str(output),
                    ]
                )
            output_created = output.exists()

        self.assertEqual(status, 2)
        self.assertFalse(output_created)
        self.assertIn("artifact hash or size mismatch", stderr.getvalue())

    def test_pack_enforces_the_total_file_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "evidence"
            run = RunContext.start(
                work_root=work,
                command="run-profile",
                source_root=source,
                registry=load_registry(),
                parameters={"profile": "nightly"},
            )
            run.write_json("profile/result.json", {"status": "pass"})
            run.complete()
            output = base / "upload"
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "evidence",
                        "pack",
                        "--work-root",
                        str(work),
                        "--output",
                        str(output),
                        "--max-files",
                        "2",
                    ]
                )
            output_created = output.exists()

        self.assertEqual(status, 2)
        self.assertFalse(output_created)
        self.assertIn("file budget: 3 > 2", stderr.getvalue())

    def test_pack_enforces_the_total_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "evidence"
            run = RunContext.start(
                work_root=work,
                command="run-profile",
                source_root=source,
                registry=load_registry(),
                parameters={"profile": "nightly"},
            )
            run.write_json("profile/result.json", {"status": "pass"})
            run.complete()
            output = base / "upload"
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "evidence",
                        "pack",
                        "--work-root",
                        str(work),
                        "--output",
                        str(output),
                        "--max-bytes",
                        "1",
                    ]
                )
            output_created = output.exists()

        self.assertEqual(status, 2)
        self.assertFalse(output_created)
        self.assertIn("byte budget", stderr.getvalue())

    def test_pack_retains_freshly_verified_artifacts_from_a_failed_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "evidence"
            run = RunContext.start(
                work_root=work,
                command="run-profile",
                source_root=source,
                registry=load_registry(),
                parameters={"profile": "nightly"},
            )
            run.write_text("engine/stderr.log", "tool failed\n")
            run.fail(RuntimeError("engine failed"))
            output = base / "upload"

            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "evidence",
                        "pack",
                        "--work-root",
                        str(work),
                        "--output",
                        str(output),
                    ]
                )
            index = json.loads((output / "evidence-pack.json").read_text())
            relative_run = run.root.relative_to(work)
            log_copied = (output / relative_run / "engine/stderr.log").is_file()

        self.assertEqual(status, 0)
        self.assertEqual(index["manifests"][0]["status"], "failed")
        self.assertTrue(log_copied)


if __name__ == "__main__":
    unittest.main()
