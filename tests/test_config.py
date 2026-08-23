from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aster_syssec.cli import main
from aster_syssec.config import load_registry
from aster_syssec.doctor import run_doctor
from tests.helpers import write_fixture


def write_config(
    root: Path,
    *,
    engine: str = "static",
    source_root: str = "kernel/core/src/syscall/read.rs",
    syscall: str = "read",
) -> Path:
    (root / "tracks").mkdir(parents=True)
    (root / "invariants.toml").write_text(
        '[[properties]]\nid = "BOUNDARY-VALIDATION"\ndescription = "Validate input"\n',
        encoding="utf-8",
    )
    (root / "tracks/test.toml").write_text(
        f"""
id = "test-track"
description = "Test track"
syscalls = ["{syscall}"]
source_roots = ["{source_root}"]
properties = ["BOUNDARY-VALIDATION"]
engines = ["{engine}"]
guidance = "guidance/test.md"
specula_readiness = "analysis-only"
target = "test|asterinas/asterinas|Rust|Test contract"
""".lstrip(),
        encoding="utf-8",
    )
    return root


class ConfigTests(unittest.TestCase):
    def test_config_check_writes_schema_validated_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            config = write_config(base / "config")
            profile = base / "profile"
            guidance = profile / "guidance/test.md"
            guidance.parent.mkdir(parents=True)
            guidance.write_text("# Test\n", encoding="utf-8")
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "config-check",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--config-root",
                        str(config),
                        "--specula-profile",
                        str(profile),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            manifest = json.loads(next(work.rglob("run-manifest.json")).read_text())

        self.assertEqual(status, 0)
        self.assertEqual(result, {"issues": [], "status": "ok"})
        artifact = next(
            item for item in manifest["outputs"] if item["path"].endswith(".json")
        )
        self.assertEqual(
            artifact["schema"], "https://asterinas.dev/syssec/config-check.schema.json"
        )

    def test_unknown_engine_fails_while_loading_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = write_config(Path(tmp), engine="imaginary-engine")

            with self.assertRaisesRegex(ValueError, "unknown engine"):
                load_registry(config)

    def test_doctor_fails_closed_for_missing_track_source_and_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            config = write_config(
                base / "config",
                source_root="kernel/core/src/removed-module",
                syscall="not_a_syscall",
            )
            profile = base / "profile"
            profile.mkdir()
            (profile / "specula-asterinas-hybrid.json").write_text(
                '{"version":1,"default_profile":"review","profiles":{"review":{}},"phases":{}}',
                encoding="utf-8",
            )

            result = run_doctor(source, load_registry(config), profile_root=profile)

        by_id = {check.id: check for check in result.checks}
        self.assertEqual(result.status, "fail")
        self.assertEqual(by_id["config-source-root:test-track"].status, "FAIL")
        self.assertEqual(by_id["config-guidance:test-track"].status, "FAIL")
        self.assertEqual(
            by_id["config-syscall:test-track:not_a_syscall"].status, "WARN"
        )
        self.assertEqual(by_id["config-empty-track:test-track"].status, "FAIL")

    def test_doctor_uses_the_same_strict_specula_config_validation_as_handoff(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            config = write_config(base / "config")
            profile = base / "profile"
            guidance = profile / "guidance/test.md"
            guidance.parent.mkdir(parents=True)
            guidance.write_text("# Test\n", encoding="utf-8")
            (profile / "specula-asterinas-hybrid.json").write_text(
                '{"version":1,"default_profile":"review","profiles":{"review":{}},'
                '"phases":{"analyze":"missing"}}',
                encoding="utf-8",
            )

            result = run_doctor(source, load_registry(config), profile_root=profile)

        check = next(
            item for item in result.checks if item.id == "specula-agent-config"
        )
        self.assertEqual(check.status, "FAIL")
        self.assertIn("missing profiles", check.detail)


if __name__ == "__main__":
    unittest.main()
