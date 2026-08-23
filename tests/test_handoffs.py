from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from aster_syssec.agent_review import prepare_aster_code_review
from aster_syssec.cli import main
from aster_syssec.config import load_registry
from aster_syssec.handoff import verify_handoff
from aster_syssec.specula import prepare_handoff
from tests.helpers import init_git_repository, write_fixture, write_specula_inputs


class HandoffTests(unittest.TestCase):
    def test_agent_handoff_preflight_accepts_unchanged_inputs_and_rejects_tampering(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            init_git_repository(source)
            run_root = base / "run"
            plan = prepare_aster_code_review(
                source_root=source,
                run_root=run_root,
                agent_profile="codex",
                per_persona_context="yes",
                paths=["kernel/core/src/syscall/read.rs"],
            )
            handoff_path = run_root / "agent-review/handoff.json"
            handoff_path.parent.mkdir(parents=True, exist_ok=True)
            handoff_path.write_text(json.dumps(plan.evidence), encoding="utf-8")

            verified = verify_handoff(handoff_path)
            command = plan.command_with_preflight(handoff_path)
            assert command is not None
            git = shutil.which("git")
            assert git is not None
            executed = subprocess.run(
                ["/bin/sh", "-c", command.splitlines()[0]],
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": str(Path(git).parent)},
            )
            launcher = source / ".agents/skills/aster-code-review/aster_code_review.sh"
            launcher.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "(working tree|input) changed"):
                verify_handoff(handoff_path)

        self.assertTrue(verified["verified"])
        self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_agent_handoff_preflight_rejects_a_new_source_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            init_git_repository(source)
            run_root = base / "run"
            plan = prepare_aster_code_review(
                source_root=source,
                run_root=run_root,
                agent_profile="codex",
                per_persona_context="auto",
                paths=["kernel/core/src/syscall/read.rs"],
            )
            handoff_path = run_root / "agent-review/handoff.json"
            handoff_path.parent.mkdir(parents=True, exist_ok=True)
            handoff_path.write_text(json.dumps(plan.evidence), encoding="utf-8")
            read = source / "kernel/core/src/syscall/read.rs"
            read.write_text(
                read.read_text(encoding="utf-8") + "\n// later\n", encoding="utf-8"
            )
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            subprocess.run(
                ["git", "commit", "-m", "later"],
                cwd=source,
                check=True,
                capture_output=True,
            )

            with self.assertRaisesRegex(ValueError, "HEAD changed"):
                verify_handoff(handoff_path)

    def test_agent_diff_handoff_pins_merge_base_and_requires_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            base_revision = init_git_repository(source)
            subprocess.run(
                ["git", "branch", "review-base", base_revision], cwd=source, check=True
            )
            read = source / "kernel/core/src/syscall/read.rs"
            read.write_text(
                read.read_text(encoding="utf-8") + "\n// changed\n", encoding="utf-8"
            )
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            subprocess.run(
                ["git", "commit", "-m", "change"],
                cwd=source,
                check=True,
                capture_output=True,
            )

            plan = prepare_aster_code_review(
                source_root=source,
                run_root=base / "run",
                agent_profile="codex",
                per_persona_context="yes",
                base="review-base",
            )
            handoff = plan.evidence
            command = plan.command_with_preflight(
                base / "run/agent-review/handoff.json"
            )
            assert command is not None

        self.assertIn("base_revision", handoff)
        self.assertEqual(handoff["base_revision"], base_revision)
        self.assertIn(base_revision, command)
        self.assertNotIn("aster_code_review.sh diff review-base", command)
        self.assertIn("verify-handoff", command)

    def test_default_specula_run_ids_do_not_collide_in_the_same_second(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            init_git_repository(source)
            profile, specula = write_specula_inputs(base)
            track = load_registry().tracks["socket-cmsg-iovec"]
            fixed = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
            with patch("aster_syssec.specula.datetime") as clock:
                clock.now.return_value = fixed
                first = prepare_handoff(
                    source_root=source,
                    profile_root=profile,
                    specula_repo=specula,
                    track=track,
                    stage="dry-run",
                    run_root=base / "run-one",
                )
                second = prepare_handoff(
                    source_root=source,
                    profile_root=profile,
                    specula_repo=specula,
                    track=track,
                    stage="dry-run",
                    run_root=base / "run-two",
                )

        self.assertNotEqual(
            first.evidence["execution_identity"]["run_id"],
            second.evidence["execution_identity"]["run_id"],
        )

    def test_linked_worktree_export_preserves_independent_git_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repository = write_fixture(base / "repository")
            revision = init_git_repository(repository)
            linked = base / "linked"
            subprocess.run(
                ["git", "worktree", "add", "--detach", str(linked), revision],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            profile, specula = write_specula_inputs(base)
            work = base / "work"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(
                    [
                        "model",
                        "--asterinas",
                        str(linked),
                        "--work-root",
                        str(work),
                        "--track",
                        "socket-cmsg-iovec",
                        "--specula-profile",
                        str(profile),
                        "--specula-repo",
                        str(specula),
                        "--export-linked",
                        "--json",
                    ]
                )
            handoff_path = next(work.rglob("specula/handoff.json"))
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            artifact = Path(handoff["artifact"])

            self.assertEqual(status, 0)
            self.assertIn("history_available", handoff["source_export"])
            self.assertTrue(handoff["source_export"]["history_available"])
            self.assertTrue((artifact / ".git").is_dir())

            exported_revision = subprocess.run(
                ["git", "-C", str(artifact), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        self.assertEqual(exported_revision, revision)


if __name__ == "__main__":
    unittest.main()
