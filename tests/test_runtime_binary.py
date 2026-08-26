from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aster_syssec.runtime import AsterinasStaticBinaryExporter
from aster_syssec.schemas import validate_instance
from aster_syssec.source import inspect_source
from tests.helpers import init_git_repository, write_fixture

TARGET_CONFIG_SHA256 = "a" * 64
BINARY_SHA256 = "432be00d283e2941fc4eb82661e9a977a3bef81e76cb0a5c2dc871a9a4bcee67"
SOURCE_SHA256 = "2ad75d95660563887d8d3f1d0ae1dcf18c2379cbd83a5c72f5ab276351ee6949"


def write_binary_source(root: Path) -> Path:
    write_fixture(root)
    files = {
        "Makefile": "initramfs:\n\t@true\n",
        "test/initramfs/Makefile": "initramfs:\n\t@true\n",
        "test/initramfs/src/regression/io/file_io/partial_efault_json.c": (
            "int main(void) { return 0; }\n"
        ),
    }
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    init_git_repository(root)
    return root


def export_request(source: Path, evidence_root: Path) -> dict[str, Any]:
    snapshot = inspect_source(source)
    return {
        "schema_version": 1,
        "request_id": "BINARY-EXPORT-REQUEST-0123456789ABCDEF",
        "created_at": "2026-08-26T00:00:00Z",
        "target": "pipe-partial-efault-linux-diff",
        "target_config_sha256": TARGET_CONFIG_SHA256,
        "guest_case": "io/file_io/partial_efault_json",
        "target_arch": "x86_64",
        "source": {
            "path": str(source),
            "revision": snapshot.revision,
            "dirty_hash": snapshot.dirty_hash,
        },
        "evidence_root": str(evidence_root),
        "limits": {
            "build_timeout_seconds": 10,
            "output_bytes": 64 * 1024,
        },
    }


def write_executable(destination: Path, body: str) -> Path:
    destination.write_text(f"#!/bin/sh\nset -eu\n{body}", encoding="utf-8")
    destination.chmod(0o755)
    return destination


def write_fake_toolchain(
    root: Path,
    *,
    binary_mode: int = 0o755,
    dynamic_binary: bool = False,
    mutate_source: bool = False,
    relative_compiler: bool = False,
    store_backed: bool = True,
    versioned_derivation: bool = False,
) -> dict[str, Path]:
    tools = root / "tools"
    tools.mkdir()
    fake_store = root / "nix/store/0123456789abcdef-io-test-0.1.0"
    binary = fake_store / "io/file_io/partial_efault_json"
    compiler_root = root / "nix/store/1111111111111111-gcc-wrapper-1.0"
    linker_root = root / "nix/store/2222222222222222-binutils-wrapper-2.0"
    compiler_root.joinpath("bin").mkdir(parents=True)
    linker_root.joinpath("bin").mkdir(parents=True)
    compiler = write_executable(
        compiler_root / "bin/cc",
        f"""case "${{1:-}}" in
    --version) printf '%s\n' 'fixture cc 1.0' ;;
    -print-prog-name=ld) printf '%s\n' '{linker_root / "bin/ld"}' ;;
    *) exit 64 ;;
esac
""",
    )
    linker = write_executable(
        linker_root / "bin/ld",
        "[ \"${1:-}\" = --version ] || exit 64\nprintf '%s\\n' 'fixture ld 2.0'\n",
    )
    source_mutation = (
        "printf 'int changed(void) { return 1; }\\n' > "
        "test/initramfs/src/regression/io/file_io/partial_efault_json.c"
        if mutate_source
        else ":"
    )
    if store_backed:
        write_binary = f"""mkdir -p '{binary.parent}' test/initramfs/build/initramfs/test/io/file_io
printf '\177ELFstatic-fixture\n' > '{binary}'
chmod {binary_mode:o} '{binary}'
ln -s '{binary}' test/initramfs/build/initramfs/test/io/file_io/partial_efault_json"""
    else:
        write_binary = f"""mkdir -p test/initramfs/build/initramfs/test/io/file_io
printf '\177ELFstatic-fixture\n' > test/initramfs/build/initramfs/test/io/file_io/partial_efault_json
chmod {binary_mode:o} test/initramfs/build/initramfs/test/io/file_io/partial_efault_json"""
    make = write_executable(
        tools / "make",
        f"""args=" $* "
for expected in -C test/initramfs ENABLE_REGRESSION_TEST=true REGRESSION_TEST_PLATFORM=asterinas TARGET_ARCH=x86_64; do
    case "$args" in
        *" $expected "*) ;;
        *) printf 'missing argument: %s\n' "$expected" >&2; exit 64 ;;
    esac
done
{source_mutation}
{write_binary}
printf 'build stdout\n'
printf 'build stderr\n' >&2
""",
    )
    derivation = root / "nix/store/abcdef0123456789-io-test-0.1.0.drv"
    stdenv = root / "nix/store/3333333333333333-stdenv-linux"
    stdenv.mkdir()
    nix_store = write_executable(
        tools / "nix-store",
        f"""case "$2" in
    --deriver) printf '%s\n' '{derivation}' ;;
    --references) printf '%s\n' '{compiler_root}' ;;
    *) exit 64 ;;
esac
""",
    )
    derivation_environment = {
        "CC": "cc" if relative_compiler or versioned_derivation else str(compiler),
        "buildCommand": "make regression package",
    }
    if versioned_derivation:
        derivation_environment["stdenv"] = str(stdenv)
    else:
        derivation_environment["PATH"] = str(compiler_root / "bin")
    derivation_entry = {
        "args": [],
        "builder": "/bin/sh",
        "env": derivation_environment,
        "inputDrvs": {},
        "inputSrcs": [],
        "name": "io-test-0.1.0",
        "outputs": {"out": {"path": str(fake_store)}},
        "system": "x86_64-linux",
    }
    derivation_payload = (
        {"derivations": {derivation.name: derivation_entry}, "version": 4}
        if versioned_derivation
        else {str(derivation): derivation_entry}
    )
    nix = write_executable(
        tools / "nix",
        f"printf '%s\\n' '{json.dumps(derivation_payload)}'\n",
    )
    program_headers = (
        "printf '%s\\n' 'Program Headers:' '  INTERP 0x0'"
        if dynamic_binary
        else "printf '%s\\n' 'Program Headers:' '  LOAD 0x0'"
    )
    dynamic_section = (
        "printf '%s\\n' ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]'"
        if dynamic_binary
        else "printf '%s\\n' 'There is no dynamic section in this file.'"
    )
    readelf = write_executable(
        tools / "readelf",
        f"""case "$1" in
    -hW) printf '%s\n' 'ELF Header:' '  Class:                             ELF64' '  Machine:                           Advanced Micro Devices X86-64' ;;
    -lW) {program_headers} ;;
    -dW) {dynamic_section} ;;
    *) exit 64 ;;
esac
""",
    )
    return {
        "make": make,
        "nix": nix,
        "nix_store": nix_store,
        "readelf": readelf,
        "store_binary": binary,
        "compiler": compiler,
        "linker": linker,
        "compiler_root": compiler_root,
    }


class AsterinasStaticBinaryExporterTests(unittest.TestCase):
    def test_exports_the_initramfs_binary_with_reproducible_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_binary_source(root / "source")
            evidence_root = root / "evidence"
            tools = write_fake_toolchain(root)
            exporter = AsterinasStaticBinaryExporter(
                make_executable=str(tools["make"]),
                nix_executable=str(tools["nix"]),
                nix_store_executable=str(tools["nix_store"]),
                readelf_executable=str(tools["readelf"]),
            )

            provenance = exporter.export(export_request(source, evidence_root))

            validate_instance(provenance, "binary-provenance.schema.json")
            self.assertEqual(
                json.loads((evidence_root / "binary-provenance.json").read_text()),
                provenance,
            )
            binary = provenance["binary"]
            exported = Path(binary["path"])
            self.assertEqual(exported.read_bytes(), b"\x7fELFstatic-fixture\n")
            self.assertTrue(exported.stat().st_mode & 0o111)
            self.assertNotEqual(
                exported.stat().st_ino, tools["store_binary"].stat().st_ino
            )
            self.assertEqual(binary["sha256"], BINARY_SHA256)
            self.assertEqual(binary["source_sha256"], SOURCE_SHA256)
            self.assertIn("fixture cc 1.0", binary["compiler"])
            self.assertIn(str(tools["compiler"]), binary["compiler"])
            self.assertIn("fixture ld 2.0", binary["linker"])
            self.assertIn(str(tools["linker"]), binary["linker"])
            self.assertEqual(binary["build_command"]["argv"][0], str(tools["make"]))
            self.assertIn(
                "ENABLE_REGRESSION_TEST=true", binary["build_command"]["argv"]
            )
            self.assertTrue(provenance["verification"]["statically_linked"])
            self.assertIsNone(provenance["verification"]["interpreter"])
            self.assertEqual(provenance["verification"]["elf_class"], "ELF64")
            for artifact in provenance["artifacts"].values():
                payload = (evidence_root / artifact["path"]).read_bytes()
                self.assertEqual(
                    artifact["sha256"], hashlib.sha256(payload).hexdigest()
                )
            self.assertEqual(
                subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=source,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )

    def test_rejects_a_non_executable_initramfs_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_binary_source(root / "source")
            evidence_root = root / "evidence"
            tools = write_fake_toolchain(root, binary_mode=0o644)
            exporter = AsterinasStaticBinaryExporter(
                make_executable=str(tools["make"]),
                nix_executable=str(tools["nix"]),
                nix_store_executable=str(tools["nix_store"]),
                readelf_executable=str(tools["readelf"]),
            )

            with self.assertRaisesRegex(ValueError, "not executable"):
                exporter.export(export_request(source, evidence_root))

            self.assertFalse((evidence_root / "binary-provenance.json").exists())

    def test_rejects_source_changed_by_the_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_binary_source(root / "source")
            evidence_root = root / "evidence"
            tools = write_fake_toolchain(root, mutate_source=True)
            exporter = AsterinasStaticBinaryExporter(
                make_executable=str(tools["make"]),
                nix_executable=str(tools["nix"]),
                nix_store_executable=str(tools["nix_store"]),
                readelf_executable=str(tools["readelf"]),
            )

            with self.assertRaisesRegex(ValueError, "source changed during build"):
                exporter.export(export_request(source, evidence_root))

            self.assertFalse((evidence_root / "binary-provenance.json").exists())

    def test_resolves_the_compiler_from_the_derivation_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_binary_source(root / "source")
            evidence_root = root / "evidence"
            tools = write_fake_toolchain(root, relative_compiler=True)
            exporter = AsterinasStaticBinaryExporter(
                make_executable=str(tools["make"]),
                nix_executable=str(tools["nix"]),
                nix_store_executable=str(tools["nix_store"]),
                readelf_executable=str(tools["readelf"]),
            )

            provenance = exporter.export(export_request(source, evidence_root))

            self.assertEqual(
                provenance["nix"]["compiler_executable"],
                str(tools["compiler"]),
            )
            self.assertIn("fixture cc 1.0", provenance["binary"]["compiler"])

    def test_rejects_a_dynamically_linked_guest_case(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_binary_source(root / "source")
            evidence_root = root / "evidence"
            tools = write_fake_toolchain(root, dynamic_binary=True)
            exporter = AsterinasStaticBinaryExporter(
                make_executable=str(tools["make"]),
                nix_executable=str(tools["nix"]),
                nix_store_executable=str(tools["nix_store"]),
                readelf_executable=str(tools["readelf"]),
            )

            with self.assertRaisesRegex(ValueError, "ELF interpreter"):
                exporter.export(export_request(source, evidence_root))

            self.assertFalse((evidence_root / "binary-provenance.json").exists())

    def test_rejects_a_binary_not_backed_by_the_nix_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_binary_source(root / "source")
            evidence_root = root / "evidence"
            tools = write_fake_toolchain(root, store_backed=False)
            exporter = AsterinasStaticBinaryExporter(
                make_executable=str(tools["make"]),
                nix_executable=str(tools["nix"]),
                nix_store_executable=str(tools["nix_store"]),
                readelf_executable=str(tools["readelf"]),
            )

            with self.assertRaisesRegex(ValueError, "not backed by a Nix store"):
                exporter.export(export_request(source, evidence_root))

            self.assertFalse((evidence_root / "binary-provenance.json").exists())

    def test_reads_versioned_nix_derivation_and_its_stdenv_compiler(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_binary_source(root / "source")
            evidence_root = root / "evidence"
            tools = write_fake_toolchain(root, versioned_derivation=True)
            exporter = AsterinasStaticBinaryExporter(
                make_executable=str(tools["make"]),
                nix_executable=str(tools["nix"]),
                nix_store_executable=str(tools["nix_store"]),
                readelf_executable=str(tools["readelf"]),
            )

            provenance = exporter.export(export_request(source, evidence_root))

            self.assertEqual(
                provenance["nix"]["compiler_executable"],
                str(tools["compiler"]),
            )
            self.assertIn("fixture cc 1.0", provenance["binary"]["compiler"])


if __name__ == "__main__":
    unittest.main()
