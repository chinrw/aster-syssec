from __future__ import annotations

import json
import unittest
from pathlib import Path


class CiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.asterinas_revision = json.loads(
            (root / "flake.lock").read_text(encoding="utf-8")
        )["nodes"]["asterinas-src"]["locked"]["rev"]

    def test_host_job_checks_out_the_locked_asterinas_revision(self) -> None:
        self.assertIn(f"ref: {self.asterinas_revision}", self.workflow)

    def test_manual_profile_choice_and_concurrency_are_explicit(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("description: Verification profile", self.workflow)
        self.assertIn("- pr", self.workflow)
        self.assertIn("- nightly", self.workflow)
        self.assertIn("github.event_name == 'schedule' && 'nightly'", self.workflow)
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && inputs.profile",
            self.workflow,
        )

    def test_host_job_uploads_only_the_budgeted_evidence_pack(self) -> None:
        self.assertIn(
            "SYSSEC_JOB_ROOT: ${{ runner.temp }}/aster-syssec-host", self.workflow
        )
        self.assertIn(
            "SYSSEC_WORK_ROOT: ${{ runner.temp }}/aster-syssec-host/evidence",
            self.workflow,
        )
        self.assertIn(
            "SYSSEC_UPLOAD_ROOT: ${{ runner.temp }}/aster-syssec-host/upload",
            self.workflow,
        )
        self.assertIn("- name: Pack host-verification evidence", self.workflow)
        self.assertIn("syssec evidence pack", self.workflow)
        self.assertIn("--max-bytes 52428800", self.workflow)
        self.assertIn("--max-files 5000", self.workflow)
        self.assertIn("path: ${{ env.SYSSEC_UPLOAD_ROOT }}", self.workflow)
        self.assertNotIn("path: ${{ runner.temp }}/aster-syssec-host\n", self.workflow)

    def test_nightly_primes_locked_fuzz_dependencies_in_the_job_cache(self) -> None:
        self.assertIn("- name: Prime locked fuzz dependencies", self.workflow)
        self.assertIn("if: env.SYSSEC_PROFILE == 'nightly'", self.workflow)
        self.assertIn(
            "CARGO_HOME: ${{ runner.temp }}/aster-syssec-host/cache/cargo",
            self.workflow,
        )
        self.assertIn(
            "SYSSEC_CACHE_ROOT: ${{ runner.temp }}/aster-syssec-host/cache",
            self.workflow,
        )
        self.assertIn("cargo fetch", self.workflow)
        self.assertIn("--locked", self.workflow)
        self.assertIn("asterinas/kernel/libs/aster-uapi/fuzz/Cargo.toml", self.workflow)
        self.assertIn(
            "ci-${{ github.workflow }}-${{ github.event_name }}-"
            "${{ inputs.profile || 'auto' }}-${{ github.ref }}",
            self.workflow,
        )


if __name__ == "__main__":
    unittest.main()
