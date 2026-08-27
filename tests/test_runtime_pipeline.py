from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from aster_syssec.cli import main
from aster_syssec.config import load_registry
from aster_syssec.engine_results import evidence_id
from aster_syssec.runs import RunContext
from aster_syssec.runtime import PartialEfaultComparator, RuntimePipeline
from aster_syssec.runtime.targets import (
    load_runtime_profile_registry,
    load_runtime_target_registry,
)
from aster_syssec.safety import SafetyClass
from aster_syssec.schemas import validate_instance
from aster_syssec.source import atomic_write_json
from tests.helpers import init_git_repository, write_fixture

GUEST_RESULT = {
    "case_id": "pipe-partial-efault-read",
    "exit_kind": "normal",
    "return": -1,
    "errno": 14,
    "first_byte": 65,
    "remaining_return": 2,
    "remaining_errno": 0,
    "remaining_byte_0": 65,
    "remaining_byte_1": 66,
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_pipeline_source(root: Path) -> Path:
    write_fixture(root)
    files = {
        "Makefile": "all:\n\t@true\n",
        "test/initramfs/Makefile": "all:\n\t@true\n",
        "test/initramfs/src/regression/io/file_io/partial_efault_json.c": (
            "int main(void) { return 0; }\n"
        ),
    }
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    read_source = root / "kernel/core/src/syscall/read.rs"
    read_source.write_text(
        read_source.read_text(encoding="utf-8")
        + "\nconst SYS_READ: usize = 0;\nfn sys_read() {}\n",
        encoding="utf-8",
    )
    init_git_repository(root)
    return root


def write_oracle_metadata(root: Path) -> Path:
    metadata = {
        "schema_version": 1,
        "id": "linux-x86-64-6-18-45",
        "target_arch": "x86_64",
        "linux_revision": "1" * 40,
        "kernel_config": {"path": "linux.config", "sha256": "1" * 64},
        "kernel_image": {"path": "bzImage", "sha256": "2" * 64},
        "rootfs": {"path": "initramfs.cpio.gz", "sha256": "3" * 64},
        "qemu": {
            "executable": "/nix/store/qemu/bin/qemu-system-x86_64",
            "version": "10.1.0",
            "sha256": "4" * 64,
            "machine": "q35",
            "cpu": "max",
            "acceleration": "tcg",
            "memory_bytes": 2 * 1024 * 1024 * 1024,
            "smp": 1,
        },
        "packer": {
            "executable": "/nix/store/packer/bin/syssec-initramfs-packer",
            "version": "syssec-initramfs-packer 1.0.0",
            "sha256": "5" * 64,
        },
    }
    validate_instance(metadata, "oracle-image.schema.json")
    path = root / "oracle-image.json"
    atomic_write_json(path, metadata)
    return path


class FakeExporter:
    def __init__(
        self,
        *,
        tamper_binary: bool = False,
        detach_binary_descriptor: bool = False,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.tamper_binary = tamper_binary
        self.detach_binary_descriptor = detach_binary_descriptor

    def export(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request = dict(request)
        self.calls.append(request)
        root = Path(request["evidence_root"])
        artifacts = root / "artifacts"
        artifacts.mkdir(parents=True)
        request_path = atomic_write_json(root / "binary-export-request.json", request)
        binary = artifacts / "static-binary/partial_efault_json"
        binary.parent.mkdir()
        binary.write_bytes(b"\x7fELFpipeline-fixture\n")
        binary.chmod(0o755)
        case = (
            Path(request["source"]["path"])
            / "test/initramfs/src/regression"
            / (request["guest_case"] + ".c")
        )
        descriptor = {
            "path": str(binary),
            "sha256": sha256(binary),
            "source_sha256": sha256(case),
            "compiler": "fixture cc 1.0",
            "linker": "fixture ld 1.0",
            "build_command": {"argv": ["make", "initramfs"], "cwd": str(root)},
        }
        if self.detach_binary_descriptor:
            detached = root.parent / "unregistered-static-binary"
            detached.write_bytes(binary.read_bytes())
            detached.chmod(0o755)
            descriptor["path"] = str(detached)
        provenance = {
            "schema_version": 1,
            "provenance_id": evidence_id("BINARY-PROVENANCE", descriptor),
            "request_id": request["request_id"],
            "request_sha256": sha256(request_path),
            "created_at": datetime.now(UTC).isoformat(),
            "target": request["target"],
            "guest_case": request["guest_case"],
            "target_arch": request["target_arch"],
            "source": {
                **request["source"],
                "case_path": str(case.relative_to(request["source"]["path"])),
                "case_sha256": sha256(case),
            },
            "binary": descriptor,
            "nix": {
                "derivation": "/nix/store/fixture.drv",
                "output": "/nix/store/fixture",
                "compiler_executable": "/nix/store/cc/bin/cc",
                "linker_executable": "/nix/store/ld/bin/ld",
            },
            "verification": {
                "elf_class": "ELF64",
                "machine": "Advanced Micro Devices X86-64",
                "interpreter": None,
                "dynamic_dependencies": [],
                "statically_linked": True,
            },
            "artifacts": {
                "request": {
                    "path": str(request_path.relative_to(root)),
                    "sha256": sha256(request_path),
                },
                "binary": {
                    "path": str(binary.relative_to(root)),
                    "sha256": sha256(binary),
                },
            },
            "diagnostics": [],
        }
        validate_instance(provenance, "binary-provenance.schema.json")
        atomic_write_json(root / "binary-provenance.json", provenance)
        if self.tamper_binary:
            binary.write_bytes(b"changed after provenance\n")
        return provenance


class FakeRuntimeAdapter:
    def __init__(self, platform: str, *, stale_request: bool = False) -> None:
        self.platform = platform
        self.stale_request = stale_request
        self.calls: list[dict[str, Any]] = []

    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request = dict(request)
        self.calls.append(request)
        root = Path(request["evidence_root"])
        artifacts = root / "artifacts"
        artifacts.mkdir(parents=True)
        request_path = atomic_write_json(root / "runtime-request.json", request)
        log = artifacts / "qemu.log"
        log.write_text("fixture guest completed\n", encoding="utf-8")
        result = {
            "schema_version": 1,
            "result_id": evidence_id(
                "RUNTIME-RESULT",
                {"platform": self.platform, "request": request["request_id"]},
            ),
            "request_id": (
                evidence_id("RUNTIME-REQUEST", {"stale": self.platform})
                if self.stale_request
                else request["request_id"]
            ),
            "request_sha256": (
                "0" * 64 if self.stale_request else sha256(request_path)
            ),
            "target": request["target"],
            "platform": self.platform,
            "outcome": "normal",
            "started_at": "2026-08-27T00:00:00Z",
            "finished_at": "2026-08-27T00:00:01Z",
            "duration_ms": 1000,
            "process": {"exit_code": 0, "signal": None, "timed_out": False},
            "guest_result": dict(GUEST_RESULT),
            "protocol_error": None,
            "tool": {"qemu": "fixture", "binary_sha256": request["binary"]["sha256"]},
            "artifacts": {
                "request": {
                    "path": str(request_path.relative_to(root)),
                    "sha256": sha256(request_path),
                },
                "qemu_log": {
                    "path": str(log.relative_to(root)),
                    "sha256": sha256(log),
                },
            },
            "diagnostics": [],
        }
        validate_instance(result, "runtime-result.schema.json")
        atomic_write_json(root / "runtime-result.json", result)
        return result


class PackagedRuntimeRegistryTests(unittest.TestCase):
    def test_partial_efault_profile_resolves_one_core_target(self) -> None:
        targets = load_runtime_target_registry(load_registry())
        profiles = load_runtime_profile_registry()
        profile = profiles.require("partial-efault-baseline")
        target = targets.require(profile.target)

        self.assertEqual(target.id, "pipe-partial-efault-linux-diff")
        self.assertEqual(target.safety.safety_class, SafetyClass.CORE)
        self.assertEqual(profile.safety_class, SafetyClass.CORE)
        self.assertEqual(target.expected, "match")

    def test_runtime_targets_list_exposes_the_core_policy(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["runtime", "targets", "list", "--json"])

        values = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["id"], "pipe-partial-efault-linux-diff")
        self.assertEqual(values[0]["safety"]["class"], "core")

    def test_runtime_target_checkout_preflight_is_evidence_backed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = write_pipeline_source(root / "source")
            work = root / "work"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "runtime",
                        "targets",
                        "check",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--json",
                    ]
                )
            result = json.loads(output.getvalue())
            manifest = json.loads(next(work.rglob("run-manifest.json")).read_text())

        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["targets"], 1)
        self.assertIn(
            "runtime/targets/check.json",
            [item["path"] for item in manifest["outputs"]],
        )


class RuntimePipelineTests(unittest.TestCase):
    def test_pipeline_binds_each_stage_to_the_exact_previous_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = write_pipeline_source(root / "source")
            oracle = write_oracle_metadata(root / "oracle")
            registry = load_registry()
            targets = load_runtime_target_registry(registry)
            target = targets.require("pipe-partial-efault-linux-diff")
            run = RunContext.start(
                work_root=root / "work",
                command="runtime-pipeline",
                source_root=source,
                registry=registry,
                parameters={"target": target.id},
            )
            exporter = FakeExporter()
            asterinas = FakeRuntimeAdapter("asterinas")
            linux = FakeRuntimeAdapter("linux-oracle")
            pipeline = RuntimePipeline(
                exporter=exporter,
                asterinas_adapter=asterinas,
                linux_adapter=linux,
                comparator=PartialEfaultComparator(),
            )

            result = pipeline.execute(
                target=target,
                profile_id="partial-efault-baseline",
                runtime_registry_hash=targets.config_hash,
                source_root=source,
                oracle_metadata_path=oracle,
                run=run,
            )
            run.complete()
            manifest = json.loads(run.manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observed"], "match")
        self.assertEqual(result["disposition"], "baseline")
        self.assertEqual(len(exporter.calls), 1)
        self.assertEqual(len(asterinas.calls), 1)
        self.assertEqual(len(linux.calls), 1)
        self.assertEqual(
            asterinas.calls[0]["binary"],
            linux.calls[0]["binary"],
        )
        self.assertEqual(
            asterinas.calls[0]["binary"]["sha256"],
            result["binary_sha256"],
        )
        outputs = {item["path"]: item for item in manifest["outputs"]}
        for stage in result["stages"]:
            artifact = stage["artifact"]
            self.assertEqual(outputs[artifact["path"]]["sha256"], artifact["sha256"])
            self.assertEqual(outputs[artifact["path"]]["schema"], artifact["schema"])
        validate_instance(result, "runtime-pipeline-result.schema.json")

    def test_tampered_export_stops_before_either_vm_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = write_pipeline_source(root / "source")
            oracle = write_oracle_metadata(root / "oracle")
            registry = load_registry()
            targets = load_runtime_target_registry(registry)
            target = targets.require("pipe-partial-efault-linux-diff")
            run = RunContext.start(
                work_root=root / "work",
                command="runtime-pipeline",
                source_root=source,
                registry=registry,
                parameters={"target": target.id},
            )
            asterinas = FakeRuntimeAdapter("asterinas")
            linux = FakeRuntimeAdapter("linux-oracle")
            pipeline = RuntimePipeline(
                exporter=FakeExporter(tamper_binary=True),
                asterinas_adapter=asterinas,
                linux_adapter=linux,
                comparator=PartialEfaultComparator(),
            )

            with self.assertRaisesRegex(ValueError, "binary hash"):
                pipeline.execute(
                    target=target,
                    profile_id=None,
                    runtime_registry_hash=targets.config_hash,
                    source_root=source,
                    oracle_metadata_path=oracle,
                    run=run,
                )

        self.assertEqual(asterinas.calls, [])
        self.assertEqual(linux.calls, [])

    def test_unregistered_binary_descriptor_stops_before_vm_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = write_pipeline_source(root / "source")
            oracle = write_oracle_metadata(root / "oracle")
            registry = load_registry()
            targets = load_runtime_target_registry(registry)
            target = targets.require("pipe-partial-efault-linux-diff")
            run = RunContext.start(
                work_root=root / "work",
                command="runtime-pipeline",
                source_root=source,
                registry=registry,
                parameters={"target": target.id},
            )
            asterinas = FakeRuntimeAdapter("asterinas")
            linux = FakeRuntimeAdapter("linux-oracle")
            pipeline = RuntimePipeline(
                exporter=FakeExporter(detach_binary_descriptor=True),
                asterinas_adapter=asterinas,
                linux_adapter=linux,
                comparator=PartialEfaultComparator(),
            )

            with self.assertRaisesRegex(ValueError, "retained artifact"):
                pipeline.execute(
                    target=target,
                    profile_id=None,
                    runtime_registry_hash=targets.config_hash,
                    source_root=source,
                    oracle_metadata_path=oracle,
                    run=run,
                )

        self.assertEqual(asterinas.calls, [])
        self.assertEqual(linux.calls, [])

    def test_stale_adapter_result_stops_before_the_next_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = write_pipeline_source(root / "source")
            oracle = write_oracle_metadata(root / "oracle")
            registry = load_registry()
            targets = load_runtime_target_registry(registry)
            target = targets.require("pipe-partial-efault-linux-diff")
            run = RunContext.start(
                work_root=root / "work",
                command="runtime-pipeline",
                source_root=source,
                registry=registry,
                parameters={"target": target.id},
            )
            asterinas = FakeRuntimeAdapter("asterinas", stale_request=True)
            linux = FakeRuntimeAdapter("linux-oracle")
            pipeline = RuntimePipeline(
                exporter=FakeExporter(),
                asterinas_adapter=asterinas,
                linux_adapter=linux,
                comparator=PartialEfaultComparator(),
            )

            with self.assertRaisesRegex(ValueError, "pipeline request"):
                pipeline.execute(
                    target=target,
                    profile_id=None,
                    runtime_registry_hash=targets.config_hash,
                    source_root=source,
                    oracle_metadata_path=oracle,
                    run=run,
                )

        self.assertEqual(len(asterinas.calls), 1)
        self.assertEqual(linux.calls, [])

    def test_explicit_runtime_profile_executes_the_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = write_pipeline_source(root / "source")
            oracle = write_oracle_metadata(root / "oracle")
            work = root / "work"
            exporter = FakeExporter()
            asterinas = FakeRuntimeAdapter("asterinas")
            linux = FakeRuntimeAdapter("linux-oracle")
            output = io.StringIO()
            with (
                patch(
                    "aster_syssec.cli.AsterinasStaticBinaryExporter",
                    return_value=exporter,
                ),
                patch(
                    "aster_syssec.cli.AsterinasQemuAdapter",
                    return_value=asterinas,
                ),
                patch(
                    "aster_syssec.cli.LinuxOracleAdapter",
                    return_value=linux,
                ),
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "runtime",
                        "run",
                        "--profile",
                        "partial-efault-baseline",
                        "--asterinas",
                        str(source),
                        "--work-root",
                        str(work),
                        "--oracle-metadata",
                        str(oracle),
                        "--initramfs-packer",
                        "fixture-packer",
                        "--json",
                    ]
                )

        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["profile"], "partial-efault-baseline")
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["expectation_met"])


if __name__ == "__main__":
    unittest.main()
