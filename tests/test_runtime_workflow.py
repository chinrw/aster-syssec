from __future__ import annotations

import json
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RuntimeWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (PROJECT_ROOT / ".github/workflows/runtime.yml").read_text(
            encoding="utf-8"
        )
        cls.flake = (PROJECT_ROOT / "flake.nix").read_text(encoding="utf-8")
        cls.make_wrapper = (PROJECT_ROOT / "scripts/ci-runtime-make.sh").read_text(
            encoding="utf-8"
        )
        cls.cargo_osdk_patch = (
            PROJECT_ROOT / "nix/cargo-osdk-runtime-source.patch"
        ).read_text(encoding="utf-8")
        cls.asterinas_revision = json.loads(
            (PROJECT_ROOT / "flake.lock").read_text(encoding="utf-8")
        )["nodes"]["asterinas-src"]["locked"]["rev"]

    def test_runtime_runs_only_manually_and_weekly(self) -> None:
        triggers = self.workflow.split("permissions:", 1)[0]

        self.assertIn("workflow_dispatch:", triggers)
        self.assertIn("schedule:", triggers)
        self.assertIn('cron: "47 18 * * 3"', triggers)
        self.assertNotIn("pull_request:", triggers)
        self.assertNotIn("push:", triggers)
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_runtime_inputs_are_immutable_and_networkless(self) -> None:
        self.assertIn(
            f"ref: {self.asterinas_revision}",
            self.workflow,
        )
        self.assertIn(
            "asterinas/dev@sha256:"
            "a32c639c66899de90875f4b1aa8614926ec172957bb27c59a93c94fdde4da934",
            self.workflow,
        )
        self.assertIn("--network=none", self.make_wrapper)
        self.assertIn(
            'cargoLock.lockFile = "${asterinas-src}/osdk/Cargo.lock";', self.flake
        )
        self.assertIn("pkgs.rustPlatform.fetchCargoVendor", self.flake)
        self.assertIn(
            'hash = "sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=";',
            self.flake,
        )
        self.assertIn("asterinasRustStdCargoVendor", self.flake)
        self.assertIn(
            'src = "${rustToolchain}/lib/rustlib/src/rust/library";', self.flake
        )
        self.assertIn(
            'hash = "sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=";',
            self.flake,
        )
        self.assertIn("asterinasWorkspaceCargoVendor", self.flake)
        self.assertIn("nix develop .#formal --command true", self.workflow)
        self.assertIn("nix develop .#default --command true", self.workflow)
        self.assertIn("nix develop --offline .#formal", self.workflow)
        self.assertIn("nix develop --offline .#default", self.workflow)
        self.assertIn("CARGO_NET_OFFLINE", self.make_wrapper)
        self.assertIn("QEMU_HOSTFWD", self.make_wrapper)
        self.assertNotIn("--privileged", self.make_wrapper)
        self.assertNotIn("--device", self.make_wrapper)
        self.assertNotIn("/dev", self.make_wrapper)

    def test_pinned_cargo_osdk_copies_the_workspace_lockfile(self) -> None:
        self.assertIn('join("Cargo.lock")', self.cargo_osdk_patch)
        self.assertIn("lock_exists", self.cargo_osdk_patch)
        self.assertIn("fs::copy", self.cargo_osdk_patch)

    def test_runtime_uses_the_explicit_profile_and_records_the_image(self) -> None:
        self.assertIn("--profile partial-efault-baseline", self.workflow)
        self.assertIn("--asterinas-build-environment", self.workflow)
        self.assertIn(
            "--cargo-osdk-executable /root/.cargo/bin/cargo-osdk", self.workflow
        )
        self.assertIn("nix build .#linux-oracle-bundle", self.workflow)
        self.assertIn("nix build .#linux-oracle-packer", self.workflow)
        self.assertIn("nix build .#cargo-osdk", self.workflow)
        self.assertIn("nix build .#asterinas-cargo-vendor", self.workflow)
        self.assertIn('--out-link "$SYSSEC_JOB_ROOT/inputs/', self.workflow)
        self.assertIn("scripts/ci-runtime-make.sh", self.workflow)

    def test_runtime_uploads_only_the_budgeted_evidence_pack(self) -> None:
        self.assertIn(
            "SYSSEC_WORK_ROOT: /tmp/aster-syssec-runtime/evidence",
            self.workflow,
        )
        self.assertIn(
            "SYSSEC_UPLOAD_ROOT: /tmp/aster-syssec-runtime/upload",
            self.workflow,
        )
        self.assertIn("syssec evidence pack", self.workflow)
        self.assertIn("--max-bytes 52428800", self.workflow)
        self.assertIn("--max-files 5000", self.workflow)
        self.assertIn("path: ${{ env.SYSSEC_UPLOAD_ROOT }}", self.workflow)
        self.assertNotIn("path: /tmp/aster-syssec-runtime\n", self.workflow)


if __name__ == "__main__":
    unittest.main()
