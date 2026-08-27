from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aster_syssec.cli import main
from aster_syssec.config import load_registry
from aster_syssec.handoff import verify_handoff
from aster_syssec.models import Track
from aster_syssec.provenance import file_sha256
from aster_syssec.schemas import validate_instance
from aster_syssec.specula import prepare_handoff
from aster_syssec.specula_gates import (
    create_gate_request,
    verify_gate_approval,
)
from tests.helpers import init_git_repository, write_fixture, write_specula_inputs


class SpeculaGateTests(unittest.TestCase):
    def test_phase_commands_use_direct_specula_interfaces_and_mutable_export(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            revision = init_git_repository(source)
            profile, specula = write_specula_inputs(base)
            track = load_registry().tracks["fd-object-lifetime"]
            plan = prepare_handoff(
                source_root=source,
                profile_root=profile,
                specula_repo=specula,
                track=track,
                stage="analysis",
                run_root=base / "run",
            )
            handoff = plan.evidence
            handoff_path = base / "run/specula/handoff.json"
            handoff_path.write_text(json.dumps(handoff), encoding="utf-8")

            self.assertTrue(handoff["ready"])
            self.assertEqual(handoff["schema_version"], 2)
            self.assertEqual(handoff["phase"], "analyze")
            self.assertEqual(handoff["safety_class"], "model")
            self.assertEqual(handoff["artifact_initial"]["revision"], revision)
            command = handoff["phase_command"]["argv"]
            self.assertEqual(command[command.index("specula") + 1], "analyze")
            nixpkgs = handoff["phase_command"]["nixpkgs_reference"]
            self.assertRegex(nixpkgs, r"^github:NixOS/nixpkgs/[0-9a-f]{40}$")
            self.assertIn(f"{nixpkgs}#jdk21", handoff["phase_command"]["nix_argv"])
            self.assertIn(f"{nixpkgs}#maven", handoff["phase_command"]["nix_argv"])
            self.assertNotIn("--keep-original", handoff["direct_command"])
            self.assertEqual(
                handoff["execution_identity"]["phase_target"], track.target
            )
            self.assertEqual(len(plan.artifacts), 1)
            self.assertEqual(plan.artifacts[0].name, "source.bundle")
            self.assertTrue(verify_handoff(handoff_path)["verified"])

            artifact_read = (
                Path(handoff["artifact"]) / "kernel/core/src/syscall/read.rs"
            )
            artifact_read.write_text(
                artifact_read.read_text(encoding="utf-8") + "\n// instrumented\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "artifact working tree changed"):
                verify_handoff(handoff_path)

            blocked = prepare_handoff(
                source_root=source,
                profile_root=profile,
                specula_repo=specula,
                track=track,
                stage="specgen",
                run_root=base / "blocked-run",
            ).evidence
            validate_instance(blocked, "specula-handoff.schema.json")
            self.assertFalse(blocked["ready"])
            self.assertIn("approved analysis gate", blocked["blockers"][0])
            self.assertIsNone(blocked["phase_command"])

    def test_four_hash_gates_end_in_candidate_only_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            init_git_repository(source)
            profile, specula = write_specula_inputs(base)
            track = load_registry().tracks["fd-object-lifetime"]

            analysis, analysis_handoff = self._prepare_phase(
                base, source, profile, specula, track, "analysis", None
            )
            self._write_analysis(analysis)
            analysis_approval = self._gate_and_approve(
                base, source, analysis_handoff, "analysis"
            )

            specgen, spec_handoff = self._prepare_phase(
                base,
                source,
                profile,
                specula,
                track,
                "specgen",
                analysis_approval,
            )
            self.assertEqual(
                specgen["execution_identity"]["phase_target"],
                "asterinas-fd-object-lifetime",
            )
            self.assertEqual(specgen["gate_approval"]["gate"], "analysis")
            self._write_spec(specgen)
            spec_approval = self._gate_and_approve(base, source, spec_handoff, "spec")

            harness, harness_handoff = self._prepare_phase(
                base,
                source,
                profile,
                specula,
                track,
                "harness",
                spec_approval,
            )
            self._write_harness(harness)
            trace_approval = self._gate_and_approve(
                base, source, harness_handoff, "trace"
            )

            validate, validate_handoff = self._prepare_phase(
                base,
                source,
                profile,
                specula,
                track,
                "validate",
                trace_approval,
            )
            self._write_counterexample(validate)
            mapping_approval = self._gate_and_approve(
                base, source, validate_handoff, "counterexample-mapping"
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "model-import",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(base / "import-work"),
                        "--track",
                        track.id,
                        "--approval",
                        str(mapping_approval),
                        "--json",
                    ]
                )
            summary = json.loads(stdout.getvalue())
            result = json.loads(Path(summary["result"]).read_text(encoding="utf-8"))

            self.assertEqual(status, 0)
            self.assertEqual(result["engine"], "specula")
            self.assertEqual(result["status"], "candidate")
            self.assertEqual(result["safety_class"], "model")
            self.assertEqual(result["tlc_result"]["outcome"], "counterexample")
            validate_instance(result, "specula-result.schema.json")
            with self.assertRaisesRegex(ValueError, "Additional properties"):
                validate_instance(
                    dict(result, reproducer="not allowed"),
                    "specula-result.schema.json",
                )

    def test_model_gate_cli_registers_only_frozen_phase_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            init_git_repository(source)
            profile, specula = write_specula_inputs(base)
            model_work = base / "model-work"
            with contextlib.redirect_stdout(io.StringIO()):
                model_status = main(
                    [
                        "model",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(model_work),
                        "--track",
                        "fd-object-lifetime",
                        "--stage",
                        "analysis",
                        "--specula-profile",
                        str(profile),
                        "--specula-repo",
                        str(specula),
                        "--json",
                    ]
                )
            handoff_path = next(model_work.rglob("specula/handoff.json"))
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            self._write_analysis(handoff)
            gate_work = base / "gate-work"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                gate_status = main(
                    [
                        "model-gate",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(gate_work),
                        "--handoff",
                        str(handoff_path),
                        "--json",
                    ]
                )
            summary = json.loads(stdout.getvalue())
            manifest = json.loads(
                next(gate_work.rglob("run-manifest.json")).read_text(encoding="utf-8")
            )
            output_paths = {item["path"] for item in manifest["outputs"]}
            output_records = {item["path"]: item for item in manifest["outputs"]}

            self.assertEqual(model_status, 0)
            self.assertEqual(gate_status, 0)
            self.assertEqual(summary["gate"], "analysis")
            self.assertEqual(manifest["status"], "completed")
            self.assertIn("specula-gate/request.json", output_paths)
            self.assertIn("specula-gate/inputs/handoff.json", output_paths)
            self.assertEqual(
                output_records["specula-gate/inputs/handoff.json"]["schema"],
                "https://asterinas.dev/syssec/specula-handoff.schema.json",
            )
            self.assertIn("specula-gate/artifacts/modeling-brief.md", output_paths)
            self.assertTrue(all("source-export" not in path for path in output_paths))

    def test_approval_fails_closed_after_artifact_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            init_git_repository(source)
            profile, specula = write_specula_inputs(base)
            track = load_registry().tracks["fd-object-lifetime"]
            handoff, handoff_path = self._prepare_phase(
                base, source, profile, specula, track, "analysis", None
            )
            self._write_analysis(handoff)
            approval = self._gate_and_approve(base, source, handoff_path, "analysis")
            verified = verify_gate_approval(approval, expected_gate="analysis")
            artifact = next(
                item
                for item in verified["request"]["artifacts"]
                if item["role"] == "modeling-brief"
            )
            artifact_path = Path(verified["request_path"]).parent / artifact["path"]
            artifact_path.write_text("changed\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "artifact (size )?changed"):
                verify_gate_approval(approval, expected_gate="analysis")

    def _prepare_phase(
        self,
        base: Path,
        source: Path,
        profile: Path,
        specula: Path,
        track: Track,
        stage: str,
        approval: Path | None,
    ) -> tuple[dict[str, Any], Path]:
        run_root = base / f"{stage}-run"
        plan = prepare_handoff(
            source_root=source,
            profile_root=profile,
            specula_repo=specula,
            track=track,
            stage=stage,
            run_root=run_root,
            gate_approval=approval,
        )
        handoff_path = run_root / "specula/handoff.json"
        handoff_path.write_text(json.dumps(plan.evidence), encoding="utf-8")
        verify_handoff(handoff_path)
        return plan.evidence, handoff_path

    def _gate_and_approve(
        self, base: Path, source: Path, handoff_path: Path, gate: str
    ) -> Path:
        gate_root = base / f"{gate}-gate"
        request, _ = create_gate_request(
            handoff_path=handoff_path,
            run_root=gate_root,
        )
        request_path = gate_root / "specula-gate/request.json"
        request_path.write_text(
            json.dumps(request, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(request["source"]["revision"], _head(source))
        approval_path = base / f"{gate}-approval.json"
        approval = {
            "schema_version": 1,
            "kind": "specula-gate-approval",
            "gate_id": request["gate_id"],
            "gate": request["gate"],
            "request_path": str(request_path),
            "request_sha256": file_sha256(request_path),
            "decision": "approved",
            "approved_by": "Fixture Reviewer",
            "approved_at": "2026-08-28T12:00:00+00:00",
            "notes": "fixture approval",
        }
        approval_path.write_text(
            json.dumps(approval, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        verify_gate_approval(approval_path, expected_gate=gate)
        return approval_path

    @staticmethod
    def _output(handoff: dict[str, Any]) -> Path:
        return Path(str(handoff["workspace"])) / ".specula-output"

    def _write_analysis(self, handoff: dict[str, Any]) -> None:
        output = self._output(handoff)
        output.mkdir(parents=True, exist_ok=True)
        (output / "modeling-brief.md").write_text("# Brief\n", encoding="utf-8")
        (output / "analysis-report.md").write_text("# Report\n", encoding="utf-8")

    def _write_spec(self, handoff: dict[str, Any]) -> None:
        output = self._output(handoff)
        spec = output / "spec"
        spec.mkdir(parents=True, exist_ok=True)
        for name in (
            "base.tla",
            "base.cfg",
            "MC.tla",
            "MC.cfg",
            "brief-coverage.md",
            "Trace.tla",
            "Trace.cfg",
            "instrumentation-spec.md",
        ):
            (spec / name).write_text(f"fixture {name}\n", encoding="utf-8")

    def _write_harness(self, handoff: dict[str, Any]) -> None:
        output = self._output(handoff)
        harness = output / "harness"
        traces = output / "traces"
        harness.mkdir(parents=True, exist_ok=True)
        traces.mkdir(parents=True, exist_ok=True)
        (harness / "apply.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (harness / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (harness / "INSTRUMENTATION.md").write_text("# Guide\n", encoding="utf-8")
        (traces / "visibility.ndjson").write_text(
            '{"action":"reserve"}\n', encoding="utf-8"
        )

    def _write_counterexample(self, handoff: dict[str, Any]) -> None:
        output = self._output(handoff)
        bundle = {
            "schema_version": 1,
            "model_bounds": {"fds": 2, "processes": 2},
            "tlc_result": {
                "outcome": "counterexample",
                "invariant": "ReservedSlotIsInvisible",
            },
            "counterexample_states": [
                {"index": 0, "reserved": [], "visible": []},
                {"index": 1, "reserved": [3], "visible": [3]},
            ],
            "source_anchors": [
                {
                    "path": "kernel/aster-nix/src/file_table.rs",
                    "symbol": "FdReservation::new",
                }
            ],
            "trace_mapping": [{"state": 1, "action": "Reserve", "source_anchor": 0}],
        }
        (output / "counterexample-bundle.json").write_text(
            json.dumps(bundle), encoding="utf-8"
        )


def _head(source: Path) -> str:
    import subprocess

    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
