from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aster_syssec.cli import main
from aster_syssec.config import load_registry
from aster_syssec.inventory import InventoryBuilder
from aster_syssec.profiles import load_profile_registry
from aster_syssec.safety import SafetyClass
from aster_syssec.targets import load_target_registry
from tests.helpers import init_git_repository, write_fixture


class PackagedProfileTests(unittest.TestCase):
    def test_pr_profile_runs_the_bounded_host_verification_set(self) -> None:
        profile = load_profile_registry().require("pr")

        self.assertEqual(
            profile.targets,
            (
                "iovec-negative-length",
                "iovec-nonnegative-length",
                "iovec-entry-address-no-wrap",
                "iovec-supported-index-offset",
                "iovec-truncation-budget",
                "cmsg-alignment-no-wrap",
                "cmsg-parser-progress",
                "cmsg-payload-round-trip",
                "message-name-length-signedness",
                "message-iovec-count-limit",
                "timespec-nonnegative-seconds",
                "timespec-normalized-nanoseconds",
                "user-iovec-layout",
                "control-message-header-layout",
                "user-message-header-layout",
                "user-timespec-layout",
                "user-iovec-x86-64",
                "fd-reservation-visibility",
            ),
        )

    def test_nightly_profile_runs_all_packaged_targets(self) -> None:
        profiles = load_profile_registry()
        nightly = profiles.require("nightly")
        targets = load_target_registry(load_registry()).targets

        self.assertEqual(set(nightly.targets), set(targets))
        self.assertNotIn("full Kani", nightly.external_required)
        self.assertNotIn("Miri host tests", nightly.external_required)
        self.assertNotIn("Loom models", nightly.external_required)
        self.assertFalse(nightly.fail_fast)

    def test_default_profiles_and_targets_are_core_only(self) -> None:
        profiles = load_profile_registry()
        targets = load_target_registry(load_registry()).targets

        self.assertEqual(profiles.require("pr").safety_class, SafetyClass.CORE)
        self.assertEqual(profiles.require("nightly").safety_class, SafetyClass.CORE)
        self.assertEqual(profiles.require("release").safety_class, SafetyClass.CORE)
        self.assertTrue(
            all(
                target.safety.safety_class is SafetyClass.CORE
                for target in targets.values()
            )
        )

    def test_profile_without_a_safety_class_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profiles.toml"
            profile.write_text(
                """
version = 1

[profiles.test]
implemented_commands = []
targets = []
external_required = []
""".lstrip(),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(TypeError, "must declare safety_class"):
                load_profile_registry(profile)


def write_kani_target(root: Path) -> Path:
    target = root / "kani/iovec-entry-address-no-wrap.toml"
    target.parent.mkdir(parents=True)
    target.write_text(
        """
version = 1
id = "iovec-entry-address-no-wrap"
engine = "kani"
track = "user-memory-partial-io"
properties = ["BOUNDARY-VALIDATION", "LINUX-ABI-CONTRACT"]
package = "aster-uapi"
harness = "proof_iovec_entry_address_no_wrap"
source_symbols = ["iovec_entry_addr"]

[safety]
class = "core"
agent_mode = "allowed"
network = false
may_generate_reproducer = false
requires_authorization = false

[limits]
timeout_seconds = 300
memory_bytes = 8589934592
unwind = 32

[policy]
expected = "pass"
pr_blocking = true
""".lstrip(),
        encoding="utf-8",
    )
    return root


def write_miri_target(root: Path) -> Path:
    target = root / "miri/user-iovec-layout.toml"
    target.parent.mkdir(parents=True)
    target.write_text(
        """
version = 1
id = "user-iovec-layout"
engine = "miri"
track = "abi-integer-layout"
properties = ["NO-UNINITIALIZED-COPYOUT", "LINUX-ABI-CONTRACT"]
package = "aster-uapi"
test = "user_iovec_layout_matches_the_linux_abi"
target_triple = "x86_64-unknown-linux-gnu"
source_symbols = ["UserIoVec"]

[safety]
class = "core"
agent_mode = "allowed"
network = false
may_generate_reproducer = false
requires_authorization = false

[limits]
timeout_seconds = 300
memory_bytes = 8589934592

[policy]
expected = "pass"
pr_blocking = true
""".lstrip(),
        encoding="utf-8",
    )
    return root


def write_layout_target(root: Path) -> Path:
    target = root / "layout/user-iovec-x86-64.toml"
    target.parent.mkdir(parents=True)
    target.write_text(
        """
version = 1
id = "user-iovec-x86-64"
engine = "layout"
track = "abi-integer-layout"
properties = ["NO-UNINITIALIZED-COPYOUT", "LINUX-ABI-CONTRACT"]
package = "aster-uapi"
manifest_path = "kernel/libs/aster-uapi/Cargo.toml"
target_triple = "x86_64-unknown-none"
feature = "syssec-layout"
record = "UserIoVec"
section = ".syssec.layout"
endianness = "little"
source_symbols = ["UserIoVec", "USER_IOVEC_LAYOUT"]

[safety]
class = "core"
agent_mode = "allowed"
network = false
may_generate_reproducer = false
requires_authorization = false

[expected_layout]
pointer_width = 64
size = 16
alignment = 8

[expected_layout.field_offsets]
base = 0
len = 8

[limits]
timeout_seconds = 300
memory_bytes = 8589934592

[policy]
expected = "pass"
pr_blocking = true
""".lstrip(),
        encoding="utf-8",
    )
    return root


def write_fuzz_target(root: Path) -> Path:
    target = root / "fuzz/iovec-host-fuzz.toml"
    target.parent.mkdir(parents=True)
    target.write_text(
        """
version = 1
id = "iovec-host-fuzz"
engine = "fuzz"
track = "user-memory-partial-io"
properties = ["BOUNDARY-VALIDATION", "PARTIAL-PROGRESS-CONSISTENCY"]
package = "aster-uapi-fuzz"
manifest_path = "kernel/libs/aster-uapi/fuzz/Cargo.toml"
fuzz_target = "fuzz_iovec"
runs = 100
max_input_size = 32
sanitizer = "none"
source_symbols = ["UserIoVec", "truncate_iovec_len", "iovec_entry_addr"]

[safety]
class = "core"
agent_mode = "allowed"
network = false
may_generate_reproducer = false
requires_authorization = false

[limits]
timeout_seconds = 300
memory_bytes = 8589934592

[policy]
expected = "pass"
pr_blocking = true
""".lstrip(),
        encoding="utf-8",
    )
    return root


def write_loom_target(root: Path) -> Path:
    target = root / "loom/fd-reservation-visibility.toml"
    target.parent.mkdir(parents=True)
    target.write_text(
        """
version = 1
id = "fd-reservation-visibility"
engine = "loom"
track = "fd-object-lifetime"
properties = ["OBJECT-IDENTITY-STABILITY", "FAILURE-ATOMICITY"]
package = "aster-fd-protocol"
test = "reserved_slot_cannot_be_closed_or_reused_before_install"
target_triple = "x86_64-unknown-linux-gnu"
max_branches = 1000
max_preemptions = 3
source_symbols = ["FdSlot"]

[safety]
class = "core"
agent_mode = "allowed"
network = false
may_generate_reproducer = false
requires_authorization = false

[limits]
timeout_seconds = 300
memory_bytes = 8589934592

[policy]
expected = "pass"
pr_blocking = true
""".lstrip(),
        encoding="utf-8",
    )
    return root


def write_minimal_registry(root: Path) -> Path:
    (root / "tracks").mkdir(parents=True)
    (root / "invariants.toml").write_text(
        '[[properties]]\nid = "BOUNDARY-VALIDATION"\ndescription = "Validate input"\n',
        encoding="utf-8",
    )
    (root / "tracks/test.toml").write_text(
        """
id = "test-track"
description = "Test track"
syscalls = ["read"]
source_roots = ["kernel/core/src/syscall/read.rs"]
properties = ["BOUNDARY-VALIDATION"]
engines = ["static"]
guidance = "guidance/test.md"
specula_readiness = "analysis-only"
target = "test|asterinas/asterinas|Rust|Test contract"
""".lstrip(),
        encoding="utf-8",
    )
    return root


class TargetCliTests(unittest.TestCase):
    def test_packaged_target_registry_contains_the_verified_vertical_slice(
        self,
    ) -> None:
        targets = load_target_registry(load_registry())

        self.assertEqual(len(targets.targets), 22)
        self.assertEqual(
            {target.engine for target in targets.targets.values()},
            {"fuzz", "kani", "layout", "loom", "miri"},
        )

    def test_engine_doctor_reports_callable_kani_tool_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "kani" ] && [ "$2" = "--version" ]; then
    echo "Kani 0.67.0"
    exit 0
fi
exit 2
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            output = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(["engine", "doctor", "--engine", "kani", "--json"])

        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "adapter": "implemented",
                "engine": "kani",
                "executable": str(cargo),
                "status": "available",
                "version": "Kani 0.67.0",
            },
        )

    def test_targets_list_returns_validated_target_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target_root = write_kani_target(Path(tmp) / "targets")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "targets",
                        "list",
                        "--target-root",
                        str(target_root),
                        "--json",
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            [
                {
                    "engine": "kani",
                    "expected": "pass",
                    "id": "iovec-entry-address-no-wrap",
                    "pr_blocking": True,
                    "properties": [
                        "BOUNDARY-VALIDATION",
                        "LINUX-ABI-CONTRACT",
                    ],
                    "safety": {
                        "agent_mode": "allowed",
                        "class": "core",
                        "may_generate_reproducer": False,
                        "network": False,
                        "requires_authorization": False,
                    },
                    "track": "user-memory-partial-io",
                }
            ],
        )

    def test_main_cli_refuses_to_execute_a_lab_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            target_root = write_kani_target(base / "targets")
            target = target_root / "kani/iovec-entry-address-no-wrap.toml"
            content = target.read_text(encoding="utf-8")
            content = content.replace('class = "core"', 'class = "lab"')
            content = content.replace(
                'agent_mode = "allowed"', 'agent_mode = "manual-only"'
            )
            content = content.replace(
                "may_generate_reproducer = false",
                "may_generate_reproducer = true",
            )
            content = content.replace(
                "requires_authorization = false",
                "requires_authorization = true",
            )
            target.write_text(content, encoding="utf-8")
            work = base / "work"
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                status = main(
                    [
                        "run-target",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--target",
                        "iovec-entry-address-no-wrap",
                    ]
                )

        self.assertEqual(status, 2)
        self.assertIn("does not execute lab targets", stderr.getvalue())
        self.assertFalse(work.exists())

    def test_targets_check_proves_package_symbols_and_harness_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            (source / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["kernel/libs/aster-uapi"]\n',
                encoding="utf-8",
            )
            package = source / "kernel/libs/aster-uapi"
            package.mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src").mkdir()
            (package / "src/lib.rs").write_text(
                """
pub fn iovec_entry_addr() {}

#[kani::proof]
fn proof_iovec_entry_address_no_wrap() {
    iovec_entry_addr();
}
""".lstrip(),
                encoding="utf-8",
            )
            target_root = write_kani_target(base / "targets")
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "targets",
                        "check",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            manifest = json.loads(next(work.rglob("run-manifest.json")).read_text())

        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["targets"], 1)
        artifact = next(
            item for item in manifest["outputs"] if item["path"] == "targets/check.json"
        )
        self.assertEqual(
            artifact["schema"],
            "https://asterinas.dev/syssec/target-check.schema.json",
        )

    def test_run_target_records_isolated_successful_kani_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            package = source / "kernel/libs/aster-uapi"
            (package / "src").mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src/lib.rs").write_text(
                """
pub fn iovec_entry_addr() {}

#[kani::proof]
fn proof_iovec_entry_address_no_wrap() {
    iovec_entry_addr();
}
""".lstrip(),
                encoding="utf-8",
            )
            target_root = write_kani_target(base / "targets")
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "kani" ] && [ "$2" = "--version" ]; then
    echo "Kani 0.67.0"
    exit 0
fi
case " $* " in
  *" --locked "*) echo "error: unexpected argument '--locked' found" >&2; exit 2 ;;
esac
echo "VERIFICATION:- SUCCESSFUL"
echo "Complete - 1 successfully verified harnesses, 0 failures, 1 total."
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            work = base / "work"
            cache = base / "job-cache"
            output = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "SYSSEC_CACHE_ROOT": str(cache),
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "run-target",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--target",
                        "iovec-entry-address-no-wrap",
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            run_root = next(work.rglob("run-manifest.json")).parent
            manifest = json.loads((run_root / "run-manifest.json").read_text())
            command = json.loads(
                (
                    run_root / "engines/kani/iovec-entry-address-no-wrap/command.json"
                ).read_text()
            )
            environment_evidence = json.loads(
                (
                    run_root
                    / "engines/kani/iovec-entry-address-no-wrap/environment.json"
                ).read_text()
            )
            work_cache_created = (work / "cache").exists()

        self.assertEqual(status, 0)
        self.assertEqual(result["outcome"], "pass")
        self.assertEqual(result["target"], "iovec-entry-address-no-wrap")
        outputs = {item["path"]: item for item in manifest["outputs"]}
        prefix = "engines/kani/iovec-entry-address-no-wrap"
        self.assertEqual(
            outputs[f"{prefix}/result.json"]["schema"],
            "https://asterinas.dev/syssec/kani-result.schema.json",
        )
        self.assertIn(f"{prefix}/stdout.log", outputs)
        self.assertIn(f"{prefix}/stderr.log", outputs)
        self.assertIn(f"{prefix}/plan.json", outputs)
        self.assertIn(f"{prefix}/command.json", outputs)
        self.assertIn(f"{prefix}/environment.json", outputs)
        self.assertIn("concrete-playback", command["argv"])
        self.assertNotIn("inplace", command["argv"])
        self.assertEqual(
            environment_evidence["variables"]["KANI_HOME"],
            str(cache.resolve() / "kani"),
        )
        self.assertEqual(
            environment_evidence["variables"]["RUSTUP_HOME"],
            str(cache.resolve() / "kani-rustup"),
        )
        self.assertFalse(work_cache_created)

    def test_kani_counterexample_records_printed_concrete_playback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            package = source / "kernel/libs/aster-uapi"
            (package / "src").mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src/lib.rs").write_text(
                """
#[kani::proof]
fn proof_negative_control() {
    let value: u8 = kani::any();
    assert!(value != 255);
}
""".lstrip(),
                encoding="utf-8",
            )
            target_root = base / "targets"
            target = target_root / "kani/negative-control.toml"
            target.parent.mkdir(parents=True)
            target.write_text(
                """
version = 1
id = "negative-control"
engine = "kani"
track = "abi-integer-layout"
properties = ["BOUNDARY-VALIDATION"]
package = "aster-uapi"
harness = "proof_negative_control"
source_symbols = ["proof_negative_control"]

[safety]
class = "core"
agent_mode = "allowed"
network = false
may_generate_reproducer = false
requires_authorization = false

[limits]
timeout_seconds = 300
memory_bytes = 8589934592
unwind = 8

[policy]
expected = "counterexample"
pr_blocking = false
""".lstrip(),
                encoding="utf-8",
            )
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "kani" ] && [ "$2" = "--version" ]; then
    echo "cargo-kani 0.67.0"
    exit 0
fi
cat <<'EOF'
CBMC 6.8.0 (cbmc-6.8.0)
Check 1: proofs::proof_negative_control.assertion.1
 - Status: FAILURE
VERIFICATION:- FAILED
Concrete playback unit test for `proofs::proof_negative_control`:
```
#[test]
fn kani_concrete_playback_negative_control() {
    let concrete_vals = vec![vec![255]];
}
```
Complete - 0 successfully verified harnesses, 1 failures, 1 total.
EOF
exit 1
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            work = base / "work"
            output = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "run-target",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--target",
                        "negative-control",
                        "--json",
                    ]
                )
            run_root = next(work.rglob("run-manifest.json")).parent
            prefix = run_root / "engines/kani/negative-control"
            result = json.loads((prefix / "result.json").read_text())
            playback = (prefix / "concrete-playback.rs").read_text()

        self.assertEqual(status, 0, result)
        self.assertEqual(result["outcome"], "counterexample")
        self.assertEqual(result["tool"]["cbmc_version"], "6.8.0 (cbmc-6.8.0)")
        self.assertEqual(
            result["engine_details"]["checks"]["failed_checks"],
            ["proofs::proof_negative_control.assertion.1"],
        )
        self.assertIn("kani_concrete_playback_negative_control", playback)

    def test_run_target_records_isolated_successful_miri_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            package = source / "kernel/libs/aster-uapi"
            (package / "src").mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src/lib.rs").write_text(
                """
pub struct UserIoVec;

#[test]
fn user_iovec_layout_matches_the_linux_abi() {}
""".lstrip(),
                encoding="utf-8",
            )
            target_root = write_miri_target(base / "targets")
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "miri" ] && [ "$2" = "--version" ]; then
    echo "miri 0.1.0 (test)"
    exit 0
fi
echo "running 1 test"
echo "test tests::user_iovec_layout_matches_the_linux_abi ... ok"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out"
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            work = base / "work"
            cache = base / "job-cache"
            output = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "SYSSEC_CACHE_ROOT": str(cache),
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "run-target",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--target",
                        "user-iovec-layout",
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            run_root = next(work.rglob("run-manifest.json")).parent
            manifest = json.loads((run_root / "run-manifest.json").read_text())
            prefix = "engines/miri/user-iovec-layout"
            environment_evidence = json.loads(
                (run_root / prefix / "environment.json").read_text()
            )

        self.assertEqual(status, 0)
        self.assertEqual(result["outcome"], "pass")
        outputs = {item["path"]: item for item in manifest["outputs"]}
        self.assertEqual(
            outputs[f"{prefix}/result.json"]["schema"],
            "https://asterinas.dev/syssec/miri-result.schema.json",
        )
        self.assertIn(f"{prefix}/stdout.log", outputs)
        self.assertIn(f"{prefix}/stderr.log", outputs)
        self.assertIn("CARGO_TARGET_DIR", environment_evidence["variables"])
        self.assertIn("XDG_CACHE_HOME", environment_evidence["variables"])
        self.assertEqual(
            environment_evidence["variables"]["XDG_CACHE_HOME"],
            str(cache.resolve() / "miri"),
        )

    def test_run_target_extracts_target_layout_from_an_object_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            (source / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["kernel/libs/aster-uapi"]\n',
                encoding="utf-8",
            )
            package = source / "kernel/libs/aster-uapi"
            (package / "src").mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src/lib.rs").write_text(
                """
pub struct UserIoVec;
pub const USER_IOVEC_LAYOUT: [usize; 4] = [16, 8, 0, 8];
""".lstrip(),
                encoding="utf-8",
            )
            (source / "Cargo.lock").write_text(
                'version = 4\n\n[[package]]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            target_root = write_layout_target(base / "targets")
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                f"""#!{sys.executable}
import os
from pathlib import Path
import sys

if sys.argv[1:] == ["--version"]:
    print("cargo 1.99.0")
    raise SystemExit(0)
target = sys.argv[sys.argv.index("--target") + 1]
output = Path(os.environ["CARGO_TARGET_DIR"]) / target / "debug/deps/aster_uapi-test.o"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(b"object")
print("Finished dev profile")
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            objcopy = fake_bin / "llvm-objcopy"
            objcopy.write_text(
                f"""#!{sys.executable}
from pathlib import Path
import struct
import sys

argument = next(item for item in sys.argv if item.startswith("--dump-section="))
destination = argument.split("=", 2)[2]
magic = int.from_bytes(b"SYSLAY01", "little")
Path(destination).write_bytes(struct.pack("<7Q", magic, 1, 64, 16, 8, 0, 8))
""",
                encoding="utf-8",
            )
            objcopy.chmod(0o755)
            work = base / "work"
            output = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "run-target",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--target",
                        "user-iovec-x86-64",
                        "--json",
                    ]
                )
            summary = json.loads(output.getvalue())
            run_root = next(work.rglob("run-manifest.json")).parent
            result = json.loads(
                (run_root / "engines/layout/user-iovec-x86-64/result.json").read_text()
            )
            manifest = json.loads((run_root / "run-manifest.json").read_text())

        self.assertEqual(status, 0, result)
        self.assertEqual(summary["outcome"], "pass")
        self.assertTrue(result["engine_details"]["matches_expected"])
        self.assertEqual(
            result["engine_details"]["layout"]["field_offsets"],
            {"base": 0, "len": 8},
        )
        self.assertIsNone(result["artifacts"]["object"])
        self.assertIsNotNone(result["artifacts"]["section"])
        self.assertFalse(
            any(
                item["path"].startswith("build/layout/") for item in manifest["outputs"]
            )
        )

    def test_run_target_replays_a_bounded_host_fuzz_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            fuzz = source / "kernel/libs/aster-uapi/fuzz"
            (fuzz / "fuzz_targets").mkdir(parents=True)
            (fuzz / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi-fuzz"\nversion = "0.0.0"\n',
                encoding="utf-8",
            )
            (fuzz / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (fuzz / "fuzz_targets/fuzz_iovec.rs").write_text(
                """
use aster_uapi::{UserIoVec, iovec_entry_addr, truncate_iovec_len};
fn fuzz_iovec() {}
""".lstrip(),
                encoding="utf-8",
            )
            target_root = write_fuzz_target(base / "targets")
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "fuzz" ] && [ "$2" = "--version" ]; then
    echo "cargo-fuzz 0.13.2"
    exit 0
fi
echo "INFO: Running with entropic power schedule"
echo "Done 100 runs in 0 second(s)"
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            work = base / "work"
            cache = base / "job-cache"
            output = io.StringIO()
            environment = {
                "CARGO_HOME": str(cache / "cargo"),
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "SYSSEC_CACHE_ROOT": str(cache),
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "run-target",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--target",
                        "iovec-host-fuzz",
                        "--json",
                    ]
                )
            summary = json.loads(output.getvalue())
            run_root = next(work.rglob("run-manifest.json")).parent
            result = json.loads(
                (run_root / "engines/fuzz/iovec-host-fuzz/result.json").read_text()
            )
            manifest = json.loads((run_root / "run-manifest.json").read_text())
            environment_evidence = json.loads(
                (run_root / "engines/fuzz/iovec-host-fuzz/environment.json").read_text()
            )
            work_corpus_created = (work / "corpus").exists()

        self.assertEqual(status, 0, result)
        self.assertEqual(summary["outcome"], "pass")
        self.assertEqual(result["engine_details"]["completed_runs"], 100)
        self.assertEqual(result["engine_details"]["crash_inputs"], [])
        self.assertIsNone(result["artifacts"]["fuzz_project"])
        self.assertIsNone(result["artifacts"]["corpus"])
        self.assertIsNone(result["artifacts"]["crashes"])
        self.assertFalse(
            any(
                item["path"].startswith(
                    ("inputs/fuzz/", "corpus/fuzz/", "crashes/fuzz/")
                )
                for item in manifest["outputs"]
            )
        )
        self.assertEqual(
            environment_evidence["variables"]["CARGO_HOME"],
            str((cache / "cargo").resolve()),
        )
        self.assertIn(
            str((cache / "corpus/host/iovec-host-fuzz").resolve()),
            environment_evidence["writable_roots"],
        )
        self.assertFalse(work_corpus_created)

    def test_run_target_records_a_bounded_loom_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            package = source / "kernel/libs/aster-fd-protocol"
            (package / "src").mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-fd-protocol"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src/lib.rs").write_text(
                """
pub enum FdSlot<T> { Reserved, Installed(T) }

#[test]
fn reserved_slot_cannot_be_closed_or_reused_before_install() {}
""".lstrip(),
                encoding="utf-8",
            )
            (source / "Cargo.lock").write_text(
                'version = 4\n\n[[package]]\nname = "loom"\nversion = "0.7.2"\n',
                encoding="utf-8",
            )
            target_root = write_loom_target(base / "targets")
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "--version" ]; then
    echo "cargo 1.99.0"
    exit 0
fi
echo "running 1 test"
echo "test tests::reserved_slot_cannot_be_closed_or_reused_before_install ... ok"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            work = base / "work"
            output = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "run-target",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--target",
                        "fd-reservation-visibility",
                        "--json",
                    ]
                )
            summary = json.loads(output.getvalue())
            run_root = next(work.rglob("run-manifest.json")).parent
            result = json.loads(
                (
                    run_root / "engines/loom/fd-reservation-visibility/result.json"
                ).read_text()
            )

        self.assertEqual(status, 0, result)
        self.assertEqual(summary["outcome"], "pass")
        self.assertEqual(result["tool"]["loom_version"], "0.7.2")
        self.assertEqual(result["engine_details"]["max_preemptions"], 3)

    def test_run_profile_executes_declared_targets_and_records_policy_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            package = source / "kernel/libs/aster-uapi"
            (package / "src").mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src/lib.rs").write_text(
                """
pub fn iovec_entry_addr() {}

#[kani::proof]
fn proof_iovec_entry_address_no_wrap() {
    iovec_entry_addr();
}
""".lstrip(),
                encoding="utf-8",
            )
            target_root = write_kani_target(base / "targets")
            profile_config = base / "profiles.toml"
            profile_config.write_text(
                """
version = 1

[profiles.pr]
safety_class = "core"
implemented_commands = []
targets = ["iovec-entry-address-no-wrap"]
external_required = []
fail_fast = true
""".lstrip(),
                encoding="utf-8",
            )
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "kani" ] && [ "$2" = "--version" ]; then
    echo "Kani 0.67.0"
    exit 0
fi
case " $* " in
  *" --locked "*) echo "error: unexpected argument '--locked' found" >&2; exit 2 ;;
esac
echo "VERIFICATION:- SUCCESSFUL"
echo "Complete - 1 successfully verified harnesses, 0 failures, 1 total."
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            work = base / "work"
            output = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "run",
                        "--profile",
                        "pr",
                        "--profile-config",
                        str(profile_config),
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            manifest = json.loads(next(work.rglob("run-manifest.json")).read_text())

        self.assertEqual(status, 0)
        self.assertEqual(result["profile"], "pr")
        self.assertEqual(result["safety_class"], "core")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["target_results"][0]["safety_class"], "core")
        self.assertEqual(result["target_results"][0]["outcome"], "pass")
        profile_result = next(
            item
            for item in manifest["outputs"]
            if item["path"] == "profile/result.json"
        )
        self.assertEqual(
            profile_result["schema"],
            "https://asterinas.dev/syssec/profile-result.schema.json",
        )

    def test_non_fail_fast_profile_records_every_target_and_failed_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            package = source / "kernel/libs/aster-uapi"
            (package / "src").mkdir(parents=True)
            (package / "Cargo.toml").write_text(
                '[package]\nname = "aster-uapi"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package / "src/lib.rs").write_text(
                """
pub fn iovec_entry_addr() {}

#[kani::proof]
fn proof_iovec_entry_address_no_wrap() {
    iovec_entry_addr();
}

#[kani::proof]
fn proof_second_target() {
    iovec_entry_addr();
}
""".lstrip(),
                encoding="utf-8",
            )
            target_root = write_kani_target(base / "targets")
            first_target = target_root / "kani/iovec-entry-address-no-wrap.toml"
            second_target = target_root / "kani/iovec-second-proof.toml"
            second_target.write_text(
                first_target.read_text(encoding="utf-8")
                .replace(
                    'id = "iovec-entry-address-no-wrap"',
                    'id = "iovec-second-proof"',
                )
                .replace(
                    'harness = "proof_iovec_entry_address_no_wrap"',
                    'harness = "proof_second_target"',
                ),
                encoding="utf-8",
            )
            profile_config = base / "profiles.toml"
            profile_config.write_text(
                """
version = 1

[profiles.nightly]
safety_class = "core"
implemented_commands = []
targets = ["iovec-entry-address-no-wrap", "iovec-second-proof"]
external_required = []
fail_fast = false
""".lstrip(),
                encoding="utf-8",
            )
            fake_bin = base / "bin"
            fake_bin.mkdir()
            cargo = fake_bin / "cargo"
            cargo.write_text(
                """#!/bin/sh
if [ "$1" = "kani" ] && [ "$2" = "--version" ]; then
    echo "Kani 0.67.0"
    exit 0
fi
case " $* " in
  *" proof_iovec_entry_address_no_wrap "*)
    echo "VERIFICATION:- FAILED"
    echo "Complete - 0 successfully verified harnesses, 1 failures, 1 total."
    exit 1
    ;;
esac
echo "VERIFICATION:- SUCCESSFUL"
echo "Complete - 1 successfully verified harnesses, 0 failures, 1 total."
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            work = base / "work"
            stdout = io.StringIO()
            environment = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                contextlib.redirect_stdout(stdout),
            ):
                status = main(
                    [
                        "run",
                        "--profile",
                        "nightly",
                        "--profile-config",
                        str(profile_config),
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                    ]
                )
            console = stdout.getvalue()
            result = json.loads(next(work.rglob("profile/result.json")).read_text())

        self.assertEqual(status, 1)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(len(result["target_results"]), 2)
        self.assertEqual(
            [item["outcome"] for item in result["target_results"]],
            ["counterexample", "pass"],
        )
        self.assertEqual(result["failed_targets"], ["iovec-entry-address-no-wrap"])
        self.assertEqual(
            result["target_results"][0]["result_path"],
            "engines/kani/iovec-entry-address-no-wrap/result.json",
        )
        self.assertEqual(
            result["target_results"][0]["run_manifest"], "run-manifest.json"
        )
        self.assertEqual(len(result["target_results"][0]["result_sha256"]), 64)
        self.assertIn("target: iovec-entry-address-no-wrap", console)
        self.assertIn("engine: kani", console)
        self.assertIn("expected: pass", console)
        self.assertIn("observed: counterexample", console)
        self.assertIn(
            "result: engines/kani/iovec-entry-address-no-wrap/result.json", console
        )

    def test_run_profile_executes_implemented_config_check_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            (source / "kernel/core/src/syscall/missing.rs").write_text(
                "pub(super) fn sys_missing(value: usize) -> Result<SyscallReturn> { Ok(value.into()) }\n",
                encoding="utf-8",
            )
            config_root = write_minimal_registry(base / "config")
            profile_config = base / "profiles.toml"
            profile_config.write_text(
                """
version = 1

[profiles.pr]
safety_class = "core"
implemented_commands = ["config-check"]
targets = []
external_required = []
fail_fast = true
""".lstrip(),
                encoding="utf-8",
            )
            target_root = base / "targets"
            target_root.mkdir()
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run",
                        "--profile",
                        "pr",
                        "--profile-config",
                        str(profile_config),
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--config-root",
                        str(config_root),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            manifest = json.loads(next(work.rglob("run-manifest.json")).read_text())

        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            result["command_results"],
            [{"command": "config-check", "outcome": "pass"}],
        )
        outputs = {item["path"] for item in manifest["outputs"]}
        self.assertIn("profile/commands/config-check.json", outputs)

    def test_run_profile_executes_implemented_inventory_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            (source / "kernel/core/src/syscall/missing.rs").write_text(
                "pub(super) fn sys_missing(value: usize) -> Result<SyscallReturn> { Ok(value.into()) }\n",
                encoding="utf-8",
            )
            config_root = write_minimal_registry(base / "config")
            profile_config = base / "profiles.toml"
            profile_config.write_text(
                """
version = 1

[profiles.nightly]
safety_class = "core"
implemented_commands = ["inventory --check"]
targets = []
external_required = []
fail_fast = true
""".lstrip(),
                encoding="utf-8",
            )
            target_root = base / "targets"
            target_root.mkdir()
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run",
                        "--profile",
                        "nightly",
                        "--profile-config",
                        str(profile_config),
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--config-root",
                        str(config_root),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            manifest = json.loads(next(work.rglob("run-manifest.json")).read_text())

        self.assertEqual(status, 0)
        self.assertEqual(
            result["command_results"],
            [{"command": "inventory --check", "outcome": "pass"}],
        )
        outputs = {item["path"] for item in manifest["outputs"]}
        self.assertIn("profile/commands/inventory/syscalls.json", outputs)
        self.assertIn("profile/commands/inventory/drift.json", outputs)

    def test_run_profile_executes_implemented_static_review_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            config_root = write_minimal_registry(base / "config")
            profile_config = base / "profiles.toml"
            profile_config.write_text(
                """
version = 1

[profiles.nightly]
safety_class = "core"
implemented_commands = ["review"]
targets = []
external_required = []
fail_fast = true
""".lstrip(),
                encoding="utf-8",
            )
            target_root = base / "targets"
            target_root.mkdir()
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run",
                        "--profile",
                        "nightly",
                        "--profile-config",
                        str(profile_config),
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--config-root",
                        str(config_root),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            manifest = json.loads(next(work.rglob("run-manifest.json")).read_text())

        self.assertEqual(status, 0)
        self.assertEqual(
            result["command_results"],
            [{"command": "review", "outcome": "pass"}],
        )
        outputs = {item["path"] for item in manifest["outputs"]}
        self.assertIn("profile/commands/review/findings.json", outputs)
        self.assertIn("profile/commands/review/report.md", outputs)

    def test_pr_profile_resolves_changed_review_from_cli_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            init_git_repository(source)
            read = source / "kernel/core/src/syscall/read.rs"
            read.write_text(
                read.read_text(encoding="utf-8") + "\n// changed for review\n",
                encoding="utf-8",
            )
            config_root = write_minimal_registry(base / "config")
            profile_config = base / "profiles.toml"
            profile_config.write_text(
                """
version = 1

[profiles.pr]
safety_class = "core"
implemented_commands = ["review --changed-from"]
targets = []
external_required = []
fail_fast = true
""".lstrip(),
                encoding="utf-8",
            )
            target_root = base / "targets"
            target_root.mkdir()
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run",
                        "--profile",
                        "pr",
                        "--changed-from",
                        "HEAD",
                        "--profile-config",
                        str(profile_config),
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--config-root",
                        str(config_root),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            selection = json.loads(
                next(work.rglob("profile/commands/review/selection.json")).read_text()
            )

        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(selection["changed_from"], "HEAD")
        self.assertEqual(selection["files"], ["kernel/core/src/syscall/read.rs"])

    def test_release_profile_applies_catalog_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "asterinas")
            (source / "kernel/core/src/syscall/missing.rs").write_text(
                "pub(super) fn sys_missing(value: usize) -> Result<SyscallReturn> { Ok(value.into()) }\n",
                encoding="utf-8",
            )
            config_root = write_minimal_registry(base / "config")
            baseline = base / "baseline.json"
            baseline.write_text(
                json.dumps(
                    InventoryBuilder(source, load_registry(config_root))
                    .build()
                    .to_dict()
                ),
                encoding="utf-8",
            )
            profile_config = base / "profiles.toml"
            profile_config.write_text(
                """
version = 1

[profiles.release]
safety_class = "core"
implemented_commands = ["inventory --check --baseline"]
targets = []
external_required = []
fail_fast = true
""".lstrip(),
                encoding="utf-8",
            )
            target_root = base / "targets"
            target_root.mkdir()
            work = base / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run",
                        "--profile",
                        "release",
                        "--baseline",
                        str(baseline),
                        "--profile-config",
                        str(profile_config),
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--target-root",
                        str(target_root),
                        "--config-root",
                        str(config_root),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())

        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(
            result["command_results"],
            [{"command": "inventory --check --baseline", "outcome": "pass"}],
        )


if __name__ == "__main__":
    unittest.main()
