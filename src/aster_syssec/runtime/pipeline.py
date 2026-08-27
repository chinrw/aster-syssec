from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from ..engine_results import evidence_id
from ..runs import RunContext
from ..safety import require_core_execution
from ..schemas import validate_instance
from ..source import atomic_write_text, inspect_source
from .targets import RuntimeTarget


class BinaryExporter(Protocol):
    def export(self, request: Mapping[str, Any]) -> dict[str, Any]: ...


class RuntimeAdapter(Protocol):
    def execute(self, request: Mapping[str, Any]) -> dict[str, Any]: ...


class RuntimeComparator(Protocol):
    def compare(
        self,
        *,
        asterinas_result_path: str | Path,
        linux_result_path: str | Path,
        output_path: str | Path,
    ) -> dict[str, Any]: ...


class RuntimePipeline:
    def __init__(
        self,
        *,
        exporter: BinaryExporter,
        asterinas_adapter: RuntimeAdapter,
        linux_adapter: RuntimeAdapter,
        comparator: RuntimeComparator,
    ) -> None:
        self._exporter = exporter
        self._asterinas_adapter = asterinas_adapter
        self._linux_adapter = linux_adapter
        self._comparator = comparator

    def execute(
        self,
        *,
        target: RuntimeTarget,
        profile_id: str | None,
        runtime_registry_hash: str,
        source_root: Path,
        oracle_metadata_path: Path,
        run: RunContext,
    ) -> dict[str, Any]:
        require_core_execution(target.safety, operation="Runtime pipeline")
        source_root = source_root.resolve()
        snapshot = inspect_source(source_root)
        if snapshot.revision is None or snapshot.dirty_entries:
            raise ValueError("Runtime pipeline requires a clean Git checkout")
        metadata_path = oracle_metadata_path.resolve(strict=True)
        metadata_bytes = metadata_path.read_bytes()
        metadata = _json_object(metadata_bytes, label="oracle metadata")
        validate_instance(metadata, "oracle-image.schema.json")
        _require_oracle_configuration(target, metadata)
        metadata_sha256 = _sha256(metadata_bytes)

        target_root = run.root / "runtime" / target.id
        target_config_path = target_root / "target.json"
        target_config_bytes = Path(target.config_path).read_bytes()
        if _sha256(target_config_bytes) != target.config_sha256:
            raise ValueError("Runtime target configuration changed after registry load")
        atomic_write_text(
            target_config_path,
            target_config_bytes.decode("utf-8"),
        )
        run.register_json_artifact(
            target_config_path,
            schema="runtime-target.schema.json",
        )
        target_config_artifact = _schema_artifact(run, target_config_path)
        if target_config_artifact["sha256"] != target.config_sha256:
            raise ValueError("retained Runtime target differs from its registry hash")

        pipeline_seed = {
            "run_id": run.manifest["run_id"],
            "target": target.id,
            "target_config_sha256": target.config_sha256,
            "oracle_metadata_sha256": metadata_sha256,
        }
        pipeline_id = evidence_id("RUNTIME-PIPELINE", pipeline_seed)
        plan = {
            "schema_version": 1,
            "pipeline_id": pipeline_id,
            "created_at": datetime.now(UTC).isoformat(),
            "target": target.id,
            "profile": profile_id,
            "target_config": target_config_artifact,
            "target_config_sha256": target.config_sha256,
            "runtime_registry_hash": runtime_registry_hash,
            "safety_class": target.safety.safety_class.value,
            "source": {
                "path": str(source_root),
                "revision": snapshot.revision,
                "dirty_hash": snapshot.dirty_hash,
            },
            "oracle": {
                "id": target.oracle,
                "metadata_path": str(metadata_path),
                "metadata_sha256": metadata_sha256,
            },
            "stages": [
                "export-binary",
                "run-asterinas",
                "run-linux",
                "compare",
            ],
            "expected": target.expected,
        }
        run.write_json(
            f"runtime/{target.id}/pipeline-plan.json",
            plan,
            schema="runtime-pipeline-plan.schema.json",
        )

        export_root = target_root / "export-binary"
        export_request = _binary_export_request(
            pipeline_id=pipeline_id,
            target=target,
            source_root=source_root,
            source_revision=snapshot.revision,
            source_dirty_hash=snapshot.dirty_hash,
            evidence_root=export_root,
        )
        returned_provenance = self._exporter.export(export_request)
        provenance_path = export_root / "binary-provenance.json"
        provenance = _register_result(
            run,
            root=export_root,
            result_path=provenance_path,
            returned=returned_provenance,
            schema="binary-provenance.schema.json",
            declared_artifacts=returned_provenance["artifacts"],
            artifact_schemas={"request": "binary-export-request.schema.json"},
        )
        _require_request_binding(
            provenance,
            export_request,
            export_root / "binary-export-request.json",
            label="binary export",
        )
        stages = [
            _stage_result(
                run,
                name="export-binary",
                path=provenance_path,
            )
        ]
        binary = provenance["binary"]
        _require_exported_binary_binding(provenance, export_root)

        asterinas_root = target_root / "run-asterinas"
        asterinas_request = _runtime_request(
            pipeline_id=pipeline_id,
            platform="asterinas",
            target=target,
            source_root=source_root,
            source_revision=snapshot.revision,
            source_dirty_hash=snapshot.dirty_hash,
            binary=binary,
            oracle_metadata_sha256=metadata_sha256,
            evidence_root=asterinas_root,
        )
        returned_asterinas = self._asterinas_adapter.execute(asterinas_request)
        asterinas_result_path = asterinas_root / "runtime-result.json"
        asterinas_result = _register_result(
            run,
            root=asterinas_root,
            result_path=asterinas_result_path,
            returned=returned_asterinas,
            schema="runtime-result.schema.json",
            declared_artifacts=returned_asterinas["artifacts"],
            artifact_schemas={"request": "runtime-request.schema.json"},
        )
        _require_runtime_result_binding(
            asterinas_result,
            asterinas_request,
            asterinas_root / "runtime-request.json",
            binary,
            label="Asterinas",
        )
        stages.append(
            _stage_result(run, name="run-asterinas", path=asterinas_result_path)
        )
        _require_declared_file(binary["path"], binary["sha256"], "static binary")

        linux_root = target_root / "run-linux"
        linux_request = _runtime_request(
            pipeline_id=pipeline_id,
            platform="linux-oracle",
            target=target,
            source_root=source_root,
            source_revision=snapshot.revision,
            source_dirty_hash=snapshot.dirty_hash,
            binary=binary,
            oracle_metadata_sha256=metadata_sha256,
            evidence_root=linux_root,
        )
        returned_linux = self._linux_adapter.execute(linux_request)
        linux_result_path = linux_root / "runtime-result.json"
        linux_result = _register_result(
            run,
            root=linux_root,
            result_path=linux_result_path,
            returned=returned_linux,
            schema="runtime-result.schema.json",
            declared_artifacts=returned_linux["artifacts"],
            artifact_schemas={
                "request": "runtime-request.schema.json",
                "oracle_metadata": "oracle-image.schema.json",
                "execution": "linux-execution.schema.json",
            },
        )
        _require_runtime_result_binding(
            linux_result,
            linux_request,
            linux_root / "runtime-request.json",
            binary,
            label="Linux oracle",
        )
        stages.append(_stage_result(run, name="run-linux", path=linux_result_path))
        _require_declared_file(binary["path"], binary["sha256"], "static binary")

        comparison_path = target_root / "compare/oracle-comparison.json"
        returned_comparison = self._comparator.compare(
            asterinas_result_path=asterinas_result_path,
            linux_result_path=linux_result_path,
            output_path=comparison_path,
        )
        comparison = _register_result(
            run,
            root=comparison_path.parent,
            result_path=comparison_path,
            returned=returned_comparison,
            schema="oracle-comparison.schema.json",
            declared_artifacts={},
            artifact_schemas={},
        )
        _require_comparison_binding(
            comparison,
            target=target,
            binary=binary,
            asterinas_result=asterinas_result,
            asterinas_result_path=asterinas_result_path,
            linux_result=linux_result,
            linux_result_path=linux_result_path,
        )
        stages.append(_stage_result(run, name="compare", path=comparison_path))

        expectation_met = comparison["status"] == target.expected
        result = {
            "schema_version": 1,
            "pipeline_id": pipeline_id,
            "finished_at": datetime.now(UTC).isoformat(),
            "target": target.id,
            "profile": profile_id,
            "target_config_sha256": target.config_sha256,
            "safety_class": target.safety.safety_class.value,
            "status": "pass" if expectation_met else "fail",
            "expected": target.expected,
            "observed": comparison["status"],
            "expectation_met": expectation_met,
            "binary_sha256": binary["sha256"],
            "comparison_id": comparison["comparison_id"],
            "disposition": comparison["disposition"],
            "stages": stages,
        }
        run.write_json(
            f"runtime/{target.id}/pipeline-result.json",
            result,
            schema="runtime-pipeline-result.schema.json",
        )
        return result


def _binary_export_request(
    *,
    pipeline_id: str,
    target: RuntimeTarget,
    source_root: Path,
    source_revision: str,
    source_dirty_hash: str,
    evidence_root: Path,
) -> dict[str, Any]:
    seed = {"pipeline_id": pipeline_id, "stage": "export-binary"}
    return {
        "schema_version": 1,
        "request_id": evidence_id("BINARY-EXPORT-REQUEST", seed),
        "created_at": datetime.now(UTC).isoformat(),
        "target": target.id,
        "target_config_sha256": target.config_sha256,
        "guest_case": target.guest_case,
        "target_arch": target.target_arch,
        "source": {
            "path": str(source_root),
            "revision": source_revision,
            "dirty_hash": source_dirty_hash,
        },
        "evidence_root": str(evidence_root),
        "limits": {
            "build_timeout_seconds": target.limits.build_timeout_seconds,
            "output_bytes": target.limits.output_bytes,
        },
    }


def _runtime_request(
    *,
    pipeline_id: str,
    platform: str,
    target: RuntimeTarget,
    source_root: Path,
    source_revision: str,
    source_dirty_hash: str,
    binary: dict[str, Any],
    oracle_metadata_sha256: str,
    evidence_root: Path,
) -> dict[str, Any]:
    seed = {"pipeline_id": pipeline_id, "stage": platform}
    return {
        "schema_version": 1,
        "request_id": evidence_id("RUNTIME-REQUEST", seed),
        "created_at": datetime.now(UTC).isoformat(),
        "target": target.id,
        "target_config_sha256": target.config_sha256,
        "guest_case": target.guest_case,
        "target_arch": target.target_arch,
        "platform": platform,
        "source": {
            "path": str(source_root),
            "revision": source_revision,
            "dirty_hash": source_dirty_hash,
        },
        "binary": binary,
        "oracle": {
            "id": target.oracle,
            "metadata_sha256": oracle_metadata_sha256,
        },
        "evidence_root": str(evidence_root),
        "execution": {
            "acceleration": "tcg",
            "host_forwarding": False,
            "memory_bytes": target.limits.memory_bytes,
            "smp": target.limits.smp,
        },
        "limits": {
            "boot_timeout_seconds": target.limits.boot_timeout_seconds,
            "test_timeout_seconds": target.limits.test_timeout_seconds,
            "output_bytes": target.limits.output_bytes,
        },
    }


def _register_result(
    run: RunContext,
    *,
    root: Path,
    result_path: Path,
    returned: dict[str, Any],
    schema: str,
    declared_artifacts: Mapping[str, Any],
    artifact_schemas: Mapping[str, str],
) -> dict[str, Any]:
    value = _json_object(result_path.read_bytes(), label=result_path.name)
    if value != returned:
        raise ValueError(f"returned result does not match retained file: {result_path}")
    run.register_json_artifact(result_path, schema=schema)
    for name, artifact in declared_artifacts.items():
        path = _declared_artifact_path(root, artifact, label=name)
        declared_schema = artifact_schemas.get(name)
        if declared_schema is None:
            run.register_artifact(path)
        else:
            run.register_json_artifact(path, schema=declared_schema)
    return value


def _declared_artifact_path(root: Path, artifact: Any, *, label: str) -> Path:
    if not isinstance(artifact, dict):
        raise TypeError(f"declared artifact {label} must be an object")
    relative = Path(artifact.get("path", ""))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"declared artifact {label} has an unsafe path")
    candidate = root / relative
    if candidate.is_symlink():
        raise ValueError(f"declared artifact {label} must not be a symlink")
    path = candidate.resolve(strict=True)
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"declared artifact {label} escapes its stage root")
    _require_declared_file(path, artifact.get("sha256"), label)
    return path


def _require_declared_file(path: str | Path, sha256: object, label: str) -> None:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"{label} must be a regular file")
    value = candidate.resolve(strict=True)
    if not value.is_file():
        raise ValueError(f"{label} must be a regular file")
    if not isinstance(sha256, str) or _sha256(value.read_bytes()) != sha256:
        raise ValueError(f"{label} hash does not match its descriptor")


def _require_request_binding(
    result: Mapping[str, Any],
    request: Mapping[str, Any],
    request_path: Path,
    *,
    label: str,
) -> None:
    retained = _json_object(request_path.read_bytes(), label=f"{label} request")
    if retained != request:
        raise ValueError(f"{label} retained request differs from pipeline request")
    if result.get("request_id") != request.get("request_id"):
        raise ValueError(f"{label} result does not reference the pipeline request")
    if result.get("request_sha256") != _sha256(request_path.read_bytes()):
        raise ValueError(f"{label} result request hash does not match retained request")


def _require_exported_binary_binding(
    provenance: Mapping[str, Any],
    export_root: Path,
) -> None:
    binary = provenance["binary"]
    retained = _declared_artifact_path(
        export_root,
        provenance["artifacts"].get("binary"),
        label="static binary",
    )
    described = Path(binary["path"])
    if not described.is_absolute() or described.is_symlink():
        raise ValueError("static binary descriptor must name the retained artifact")
    if described.resolve(strict=True) != retained:
        raise ValueError("static binary descriptor does not name the retained artifact")
    if provenance["artifacts"]["binary"].get("sha256") != binary["sha256"]:
        raise ValueError("static binary artifact hash differs from its descriptor")
    _require_declared_file(retained, binary["sha256"], "static binary")


def _require_runtime_result_binding(
    result: Mapping[str, Any],
    request: Mapping[str, Any],
    request_path: Path,
    binary: Mapping[str, Any],
    *,
    label: str,
) -> None:
    _require_request_binding(result, request, request_path, label=label)
    if result.get("target") != request.get("target"):
        raise ValueError(f"{label} result target differs from its request")
    if result.get("platform") != request.get("platform"):
        raise ValueError(f"{label} result platform differs from its request")
    if result.get("outcome") == "normal" and result.get("tool", {}).get(
        "binary_sha256"
    ) != binary.get("sha256"):
        raise ValueError(f"{label} result does not identify the pipeline binary")


def _require_comparison_binding(
    comparison: Mapping[str, Any],
    *,
    target: RuntimeTarget,
    binary: Mapping[str, Any],
    asterinas_result: Mapping[str, Any],
    asterinas_result_path: Path,
    linux_result: Mapping[str, Any],
    linux_result_path: Path,
) -> None:
    expected_identity = {
        "target": target.id,
        "case_id": target.case_id,
        "comparator": target.comparator,
    }
    for name, expected in expected_identity.items():
        if comparison.get(name) != expected:
            raise ValueError(f"comparison {name} differs from the Runtime target")
    for label, retained, path in (
        ("Asterinas", asterinas_result, asterinas_result_path),
        ("Linux oracle", linux_result, linux_result_path),
    ):
        reference = comparison.get(
            "asterinas_result" if label == "Asterinas" else "linux_result"
        )
        if not isinstance(reference, dict):
            raise TypeError(f"comparison lacks the {label} result reference")
        if reference.get("result_id") != retained.get("result_id"):
            raise ValueError(f"comparison references a different {label} result")
        if reference.get("sha256") != _sha256(path.read_bytes()):
            raise ValueError(f"comparison {label} result hash does not match")
    comparison_binary = comparison.get("binary_sha256")
    if comparison_binary is not None and comparison_binary != binary.get("sha256"):
        raise ValueError("comparison does not reference the pipeline binary")


def _stage_result(run: RunContext, *, name: str, path: Path) -> dict[str, Any]:
    return {
        "name": name,
        "status": "pass",
        "artifact": _schema_artifact(run, path),
    }


def _schema_artifact(run: RunContext, path: Path) -> dict[str, str]:
    relative = path.resolve().relative_to(run.root.resolve()).as_posix()
    record = run.artifact_record(relative)
    schema = record.get("schema")
    schema_sha256 = record.get("schema_sha256")
    if not isinstance(schema, str) or not isinstance(schema_sha256, str):
        raise TypeError(f"pipeline stage artifact has no schema identity: {relative}")
    return {
        "path": relative,
        "sha256": record["sha256"],
        "schema": schema,
        "schema_sha256": schema_sha256,
    }


def _require_oracle_configuration(
    target: RuntimeTarget,
    metadata: dict[str, Any],
) -> None:
    if metadata["id"] != target.oracle:
        raise ValueError("Runtime target oracle does not match oracle metadata")
    if metadata["target_arch"] != target.target_arch:
        raise ValueError("Runtime target architecture does not match oracle metadata")
    qemu = metadata["qemu"]
    if qemu["acceleration"] != "tcg":
        raise ValueError("Runtime pipeline requires the pinned TCG oracle")
    if qemu["memory_bytes"] != target.limits.memory_bytes:
        raise ValueError("Runtime target memory does not match oracle metadata")
    if qemu["smp"] != target.limits.smp:
        raise ValueError("Runtime target SMP does not match oracle metadata")


def _json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a JSON object")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
