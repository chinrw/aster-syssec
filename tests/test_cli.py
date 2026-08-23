from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aster_syssec.cli import main
from tests.helpers import write_fixture, write_specula_inputs


class CliTests(unittest.TestCase):
    def test_rejects_work_root_inside_source_before_creating_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = write_fixture(Path(tmp) / "source")
            work = source / ".syssec"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "inventory",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                    ]
                )

            self.assertEqual(status, 2)
            self.assertFalse(work.exists())
            self.assertIn("must not overlap", stderr.getvalue())

    def test_rejects_work_root_that_contains_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            source = write_fixture(work / "source")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "review",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--path",
                        "kernel/core/src/syscall/read.rs",
                    ]
                )

            self.assertEqual(status, 2)
            self.assertFalse((work / "runs").exists())
            self.assertIn("must not overlap", stderr.getvalue())

    def test_inventory_writes_evidence_and_check_fails_only_after_completion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "work"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "inventory",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--check",
                        "--json",
                    ]
                )
            manifest_path = next(work.rglob("run-manifest.json"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            matrix_exists = (
                manifest_path.parent / "catalog/syscall-matrix.md"
            ).is_file()

        self.assertEqual(status, 1)
        self.assertEqual(manifest["status"], "completed")
        self.assertIn(
            "catalog/syscalls.json", [item["path"] for item in manifest["outputs"]]
        )
        self.assertTrue(all(len(item["sha256"]) == 64 for item in manifest["outputs"]))
        self.assertTrue(matrix_exists)

    def test_review_never_reports_confirmed_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "review",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--path",
                        "kernel/core/src/syscall/recvmsg.rs",
                        "--json",
                    ]
                )
            summary = json.loads(output.getvalue())
            findings_path = next(work.rglob("findings.json"))
            findings = json.loads(findings_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(summary["confirmed_findings"], 0)
        self.assertGreater(summary["candidates"], 0)
        self.assertTrue(
            all(item["status"] == "candidate" for item in findings["candidates"])
        )

    def test_model_blocks_linked_worktree_without_explicit_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            (source / ".git").write_text("gitdir: /does/not/exist\n", encoding="utf-8")
            profile, specula = write_specula_inputs(base)
            work = base / "work"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "model",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--track",
                        "socket-cmsg-iovec",
                        "--specula-profile",
                        str(profile),
                        "--specula-repo",
                        str(specula),
                        "--json",
                    ]
                )
            handoff = json.loads(
                next(work.rglob("handoff.json")).read_text(encoding="utf-8")
            )

        self.assertEqual(status, 1)
        self.assertFalse(handoff["ready"])
        self.assertIsNone(handoff["nix_command"])
        self.assertIn("linked worktree", handoff["blockers"][0])

    def test_agent_review_is_a_handoff_not_an_implicit_agent_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "work"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "agent-review",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--path",
                        "kernel/core/src/syscall/recvmsg.rs",
                        "--json",
                    ]
                )
            handoff = json.loads(
                next(work.rglob("handoff.json")).read_text(encoding="utf-8")
            )
            command = next(work.rglob("command.sh")).read_text(encoding="utf-8")

        self.assertEqual(status, 0)
        self.assertFalse(handoff["executed_by_syssec"])
        self.assertTrue(handoff["executes_agents"])
        self.assertIn("aster_code_review.sh files", command)


if __name__ == "__main__":
    unittest.main()
