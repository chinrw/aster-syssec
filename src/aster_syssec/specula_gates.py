from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .handoff import verify_handoff
from .provenance import file_sha256
from .schemas import validate_instance
from .source import SourceSnapshot, inspect_source

STAGE_GATES = {
    "analysis": "analysis",
    "specgen": "spec",
    "harness": "trace",
    "validate": "counterexample-mapping",
}
STAGE_REQUIRED_APPROVALS = {
    "specgen": "analysis",
    "harness": "spec",
    "validate": "trace",
}
_GATE_PREDECESSORS = {
    "analysis": None,
    "spec": "analysis",
    "trace": "spec",
    "counterexample-mapping": "trace",
}
_GATE_PHASES = {
    "analysis": "analyze",
    "spec": "specgen",
    "trace": "harness",
    "counterexample-mapping": "validate",
}

_ANALYSIS_ARTIFACTS = {
    "modeling-brief.md": "modeling-brief",
    "analysis-report.md": "analysis-report",
}
_SPEC_ARTIFACTS = {
    "spec/base.tla": "base-spec",
    "spec/base.cfg": "base-config",
    "spec/MC.tla": "model-check-spec",
    "spec/MC.cfg": "model-check-config",
    "spec/brief-coverage.md": "brief-coverage",
    "spec/Trace.tla": "trace-spec",
    "spec/Trace.cfg": "trace-config",
    "spec/instrumentation-spec.md": "instrumentation-spec",
}
_HARNESS_ARTIFACTS = {
    "harness/apply.sh": "harness-apply",
    "harness/run.sh": "harness-run",
    "harness/INSTRUMENTATION.md": "instrumentation-guide",
}
_COUNTEREXAMPLE_ARTIFACTS = {
    "counterexample-bundle.json": "counterexample-bundle",
}
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_ARTIFACT_SET_BYTES = 128 * 1024 * 1024


def create_gate_request(
    *, handoff_path: Path, run_root: Path
) -> tuple[dict[str, Any], tuple[Path, ...]]:
    handoff_path = Path(handoff_path).resolve()
    handoff = _read_json(handoff_path, "Specula handoff")
    validate_instance(handoff, "specula-handoff.schema.json")
    verify_handoff(handoff_path, include_mutable=False)
    if handoff["gate_approval"] is not None:
        previous_gate = STAGE_REQUIRED_APPROVALS.get(handoff["stage"])
        if previous_gate is None:
            raise ValueError("unexpected approval on initial Specula phase")
        previous_verified = verify_gate_approval(
            Path(handoff["gate_approval"]["path"]),
            expected_gate=previous_gate,
        )
        if previous_verified["approval_sha256"] != handoff["gate_approval"]["sha256"]:
            raise ValueError("previous Specula gate approval changed")
    if not handoff["ready"]:
        raise ValueError("cannot gate a blocked Specula handoff")
    stage = handoff["stage"]
    if stage == "dry-run":
        raise ValueError("a Specula dry-run does not produce gate artifacts")
    gate = STAGE_GATES.get(stage)
    if gate is None or handoff["next_gate"] != gate:
        raise ValueError(f"unsupported Specula gate stage: {stage}")

    request_root = Path(run_root).resolve() / "specula-gate"
    input_root = request_root / "inputs"
    artifact_root = request_root / "artifacts"
    output_root = Path(handoff["workspace"]).resolve() / ".specula-output"
    if not output_root.is_dir():
        raise ValueError(f"Specula phase output does not exist: {output_root}")

    handoff_copy = input_root / "handoff.json"
    handoff_copy.parent.mkdir(parents=True, exist_ok=False)
    shutil.copy2(handoff_path, handoff_copy)
    selected = _select_artifacts(output_root, gate)
    records: list[dict[str, Any]] = []
    copied: list[Path] = [handoff_copy]
    total = 0
    for logical_path, role, source in selected:
        size = source.stat().st_size
        if size > _MAX_ARTIFACT_BYTES:
            raise ValueError(
                f"Specula gate artifact exceeds {_MAX_ARTIFACT_BYTES} bytes: {logical_path}"
            )
        total += size
        if total > _MAX_ARTIFACT_SET_BYTES:
            raise ValueError(
                f"Specula gate artifacts exceed {_MAX_ARTIFACT_SET_BYTES} bytes"
            )
        destination = artifact_root / logical_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied.append(destination)
        records.append(
            {
                "path": destination.relative_to(request_root).as_posix(),
                "logical_path": logical_path,
                "role": role,
                "sha256": file_sha256(destination),
                "size": size,
            }
        )

    artifact_set_sha256 = _artifact_set_sha256(records)
    source = handoff["source"]
    previous = handoff["gate_approval"]
    artifact_checkout = inspect_source(Path(handoff["artifact"])).to_dict()
    seed = {
        "gate": gate,
        "track": handoff["track"],
        "phase": handoff["phase"],
        "handoff_sha256": file_sha256(handoff_copy),
        "source_revision": source["revision"],
        "source_dirty_hash": source["dirty_hash"],
        "artifact_revision": artifact_checkout["revision"],
        "artifact_dirty_hash": artifact_checkout["dirty_hash"],
        "artifact_set_sha256": artifact_set_sha256,
        "previous_gate_id": previous["gate_id"] if previous else None,
        "previous_approval_sha256": previous["sha256"] if previous else None,
    }
    request = {
        "schema_version": 1,
        "kind": "specula-gate-request",
        "gate_id": _identity("SPECULA-GATE", seed),
        "gate": gate,
        "safety_class": "model",
        "created_at": datetime.now(UTC).isoformat(),
        "track": handoff["track"],
        "phase": handoff["phase"],
        "handoff": {
            "path": handoff_copy.relative_to(request_root).as_posix(),
            "sha256": file_sha256(handoff_copy),
        },
        "source": {
            "revision": source["revision"],
            "dirty_hash": source["dirty_hash"],
        },
        "artifact_checkout": artifact_checkout,
        "workspace": str(Path(handoff["workspace"]).resolve()),
        "artifacts": records,
        "artifact_set_sha256": artifact_set_sha256,
        "previous_approval": (
            {
                "path": previous["path"],
                "sha256": previous["sha256"],
                "gate": previous["gate"],
                "gate_id": previous["gate_id"],
            }
            if previous
            else None
        ),
    }
    validate_instance(request, "specula-gate-request.schema.json")
    return request, tuple(copied)


def verify_gate_approval(
    approval_path: Path,
    *,
    expected_gate: str | None = None,
    _seen: frozenset[Path] = frozenset(),
) -> dict[str, Any]:
    approval_path = Path(approval_path).resolve()
    if approval_path in _seen:
        raise ValueError("Specula gate approval chain contains a cycle")
    approval = _read_json(approval_path, "Specula gate approval")
    validate_instance(approval, "specula-gate-approval.schema.json")
    if approval["decision"] != "approved":
        raise ValueError(f"Specula {approval['gate']} gate was not approved")
    if expected_gate is not None and approval["gate"] != expected_gate:
        raise ValueError(
            f"expected Specula {expected_gate} approval, observed {approval['gate']}"
        )

    request_path = _resolve_external_file(
        approval_path.parent, approval["request_path"], "gate request"
    )
    request_sha256 = file_sha256(request_path)
    if request_sha256 != approval["request_sha256"]:
        raise ValueError("Specula gate request changed after approval")
    request = _read_json(request_path, "Specula gate request")
    validate_instance(request, "specula-gate-request.schema.json")
    if approval["gate"] != request["gate"]:
        raise ValueError("Specula approval gate does not match its request")
    if approval["gate_id"] != request["gate_id"]:
        raise ValueError("Specula approval gate ID does not match its request")
    if request["gate_id"] != _request_gate_id(request):
        raise ValueError("Specula gate request has a non-canonical gate ID")

    request_root = request_path.parent
    handoff_path = _safe_relative_file(
        request_root, request["handoff"]["path"], "handoff"
    )
    if file_sha256(handoff_path) != request["handoff"]["sha256"]:
        raise ValueError("Specula gate handoff changed after request creation")
    handoff = _read_json(handoff_path, "Specula gate handoff")
    validate_instance(handoff, "specula-handoff.schema.json")
    if handoff["track"] != request["track"] or handoff["phase"] != request["phase"]:
        raise ValueError("Specula gate request does not match its handoff")
    if handoff["next_gate"] != request["gate"]:
        raise ValueError("Specula gate request does not match the handoff's next gate")
    if request["phase"] != _GATE_PHASES[request["gate"]]:
        raise ValueError("Specula gate request has an invalid phase transition")

    observed_records: list[dict[str, Any]] = []
    logical_paths: set[str] = set()
    storage_paths: set[str] = set()
    for record in request["artifacts"]:
        if record["logical_path"] in logical_paths or record["path"] in storage_paths:
            raise ValueError("Specula gate request contains duplicate artifact paths")
        logical_paths.add(record["logical_path"])
        storage_paths.add(record["path"])
        artifact = _safe_relative_file(
            request_root, record["path"], f"artifact {record['logical_path']}"
        )
        if artifact.stat().st_size != record["size"]:
            raise ValueError(
                f"Specula gate artifact size changed: {record['logical_path']}"
            )
        if file_sha256(artifact) != record["sha256"]:
            raise ValueError(f"Specula gate artifact changed: {record['logical_path']}")
        observed_records.append(record)
    _validate_artifact_roles(request["gate"], observed_records)
    if _artifact_set_sha256(observed_records) != request["artifact_set_sha256"]:
        raise ValueError("Specula gate artifact-set hash does not match")

    previous = request["previous_approval"]
    expected_previous = _GATE_PREDECESSORS[request["gate"]]
    if expected_previous is None and previous is not None:
        raise ValueError("initial Specula analysis gate cannot have a predecessor")
    if expected_previous is not None and previous is None:
        raise ValueError(
            f"Specula {request['gate']} gate requires a {expected_previous} predecessor"
        )
    if previous is not None:
        if previous["gate"] != expected_previous:
            raise ValueError(
                f"Specula {request['gate']} gate has the wrong predecessor"
            )
        previous_path = _resolve_external_file(
            request_root, previous["path"], "previous gate approval"
        )
        if file_sha256(previous_path) != previous["sha256"]:
            raise ValueError("previous Specula gate approval changed")
        verified_previous = verify_gate_approval(
            previous_path,
            expected_gate=previous["gate"],
            _seen=_seen | {approval_path},
        )
        if verified_previous["request"]["gate_id"] != previous["gate_id"]:
            raise ValueError("previous Specula gate ID does not match")

    return {
        "verified": True,
        "approval_path": str(approval_path),
        "approval_sha256": file_sha256(approval_path),
        "approval": approval,
        "request_path": str(request_path),
        "request_sha256": request_sha256,
        "request": request,
        "handoff": handoff,
    }


def copy_gate_inputs(
    *,
    approval_path: Path,
    expected_gate: str,
    expected_track: str,
    source: SourceSnapshot,
    destination: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    verified = verify_gate_approval(approval_path, expected_gate=expected_gate)
    request = verified["request"]
    if request["track"] != expected_track:
        raise ValueError(
            f"Specula approval track mismatch: expected {expected_track}, observed {request['track']}"
        )
    if request["source"] != {
        "revision": source.revision,
        "dirty_hash": source.dirty_hash,
    }:
        raise ValueError("Specula approval targets a different Asterinas source")

    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError(
            f"Specula phase input destination already exists: {destination}"
        )
    destination.mkdir(parents=True)
    request_root = Path(verified["request_path"]).parent
    inputs: list[dict[str, Any]] = []
    for record in request["artifacts"]:
        source_path = _safe_relative_file(
            request_root, record["path"], f"artifact {record['logical_path']}"
        )
        destination_path = destination / record["logical_path"]
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)
        inputs.append(
            {
                "path": str(destination_path),
                "logical_path": record["logical_path"],
                "role": record["role"],
                "sha256": record["sha256"],
                "size": record["size"],
            }
        )
    summary = {
        "path": str(Path(approval_path).resolve()),
        "sha256": verified["approval_sha256"],
        "gate": request["gate"],
        "gate_id": request["gate_id"],
        "request_path": verified["request_path"],
        "request_sha256": verified["request_sha256"],
    }
    return summary, inputs


def import_counterexample(
    *, approval_path: Path, source_root: Path, expected_track: str
) -> dict[str, Any]:
    verified = verify_gate_approval(
        approval_path, expected_gate="counterexample-mapping"
    )
    request = verified["request"]
    source = inspect_source(Path(source_root))
    if request["track"] != expected_track:
        raise ValueError(
            f"Specula import track mismatch: expected {expected_track}, observed {request['track']}"
        )
    if request["source"] != {
        "revision": source.revision,
        "dirty_hash": source.dirty_hash,
    }:
        raise ValueError("Specula import targets a different Asterinas source")

    bundles = [
        item for item in request["artifacts"] if item["role"] == "counterexample-bundle"
    ]
    if len(bundles) != 1:
        raise ValueError("Specula import requires exactly one counterexample bundle")
    bundle_record = bundles[0]
    bundle_path = _safe_relative_file(
        Path(verified["request_path"]).parent,
        bundle_record["path"],
        "counterexample bundle",
    )
    bundle = _read_json(bundle_path, "Specula counterexample bundle")
    validate_instance(bundle, "specula-counterexample-source.schema.json")
    handoff = verified["handoff"]
    seed = {
        "gate_id": request["gate_id"],
        "request_sha256": verified["request_sha256"],
        "approval_sha256": verified["approval_sha256"],
        "bundle_sha256": bundle_record["sha256"],
    }
    result = {
        "schema_version": 1,
        "result_id": _identity("SPECULA-RESULT", seed),
        "engine": "specula",
        "status": "candidate",
        "safety_class": "model",
        "track": request["track"],
        "source": request["source"],
        "specula_run_id": handoff["execution_identity"]["run_id"],
        "gate": {
            "gate_id": request["gate_id"],
            "request_sha256": verified["request_sha256"],
            "approval_sha256": verified["approval_sha256"],
        },
        "model_bounds": bundle["model_bounds"],
        "tlc_result": bundle["tlc_result"],
        "counterexample_states": bundle["counterexample_states"],
        "source_anchors": bundle["source_anchors"],
        "trace_mapping": bundle["trace_mapping"],
        "diagnostics": [],
    }
    validate_instance(result, "specula-result.schema.json")
    return result


def _select_artifacts(output_root: Path, gate: str) -> list[tuple[str, str, Path]]:
    expected: dict[str, str] = dict(_ANALYSIS_ARTIFACTS)
    if gate in {"spec", "trace", "counterexample-mapping"}:
        expected.update(_SPEC_ARTIFACTS)
    if gate in {"trace", "counterexample-mapping"}:
        expected.update(_HARNESS_ARTIFACTS)
    if gate == "counterexample-mapping":
        expected.update(_COUNTEREXAMPLE_ARTIFACTS)

    selected: list[tuple[str, str, Path]] = []
    for logical_path, role in sorted(expected.items()):
        source = _safe_relative_file(output_root, logical_path, role)
        selected.append((logical_path, role, source))
    if gate in {"trace", "counterexample-mapping"}:
        trace_root = output_root / "traces"
        traces = [] if not trace_root.is_dir() else sorted(trace_root.rglob("*.ndjson"))
        if not traces:
            raise ValueError("Specula trace gate requires at least one NDJSON trace")
        for trace in traces:
            logical_path = trace.relative_to(output_root).as_posix()
            source = _safe_relative_file(output_root, logical_path, "trace")
            selected.append((logical_path, "trace", source))
    return sorted(selected, key=lambda item: item[0])


def _validate_artifact_roles(gate: str, records: list[dict[str, Any]]) -> None:
    expected: dict[str, str] = dict(_ANALYSIS_ARTIFACTS)
    if gate in {"spec", "trace", "counterexample-mapping"}:
        expected.update(_SPEC_ARTIFACTS)
    if gate in {"trace", "counterexample-mapping"}:
        expected.update(_HARNESS_ARTIFACTS)
    if gate == "counterexample-mapping":
        expected.update(_COUNTEREXAMPLE_ARTIFACTS)
    observed = {
        item["logical_path"]: item["role"]
        for item in records
        if item["role"] != "trace"
    }
    if observed != expected:
        raise ValueError(
            f"Specula {gate} gate artifact roles are incomplete or unknown"
        )
    traces = [item for item in records if item["role"] == "trace"]
    if gate in {"trace", "counterexample-mapping"}:
        if not traces:
            raise ValueError(f"Specula {gate} gate requires an NDJSON trace")
        if any(
            not item["logical_path"].startswith("traces/")
            or not item["logical_path"].endswith(".ndjson")
            for item in traces
        ):
            raise ValueError("Specula trace artifact has an invalid logical path")
    elif traces:
        raise ValueError(f"Specula {gate} gate cannot contain trace artifacts")


def _request_gate_id(request: dict[str, Any]) -> str:
    previous = request["previous_approval"]
    checkout = request["artifact_checkout"]
    seed = {
        "gate": request["gate"],
        "track": request["track"],
        "phase": request["phase"],
        "handoff_sha256": request["handoff"]["sha256"],
        "source_revision": request["source"]["revision"],
        "source_dirty_hash": request["source"]["dirty_hash"],
        "artifact_revision": checkout["revision"],
        "artifact_dirty_hash": checkout["dirty_hash"],
        "artifact_set_sha256": request["artifact_set_sha256"],
        "previous_gate_id": previous["gate_id"] if previous else None,
        "previous_approval_sha256": previous["sha256"] if previous else None,
    }
    return _identity("SPECULA-GATE", seed)


def _artifact_set_sha256(records: list[dict[str, Any]]) -> str:
    identity = [
        {
            "logical_path": item["logical_path"],
            "role": item["role"],
            "sha256": item["sha256"],
            "size": item["size"],
        }
        for item in sorted(records, key=lambda item: item["logical_path"])
    ]
    return hashlib.sha256(_canonical_json(identity)).hexdigest()


def _identity(prefix: str, value: dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(value)).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a JSON object")
    return value


def _resolve_external_file(base: Path, raw: str, label: str) -> Path:
    path = Path(raw).expanduser()
    unresolved = path if path.is_absolute() else Path(base) / path
    if unresolved.is_symlink():
        raise ValueError(f"symlink is not allowed for {label}: {unresolved}")
    candidate = unresolved.resolve()
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError(f"{label} is not a regular file: {candidate}")
    return candidate


def _safe_relative_file(base: Path, raw: str, label: str) -> Path:
    relative = Path(raw)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe relative path for {label}: {raw}")
    base = Path(base).resolve()
    candidate = base / relative
    current = candidate
    while current != base:
        if current.is_symlink():
            raise ValueError(f"symlink is not allowed for {label}: {candidate}")
        current = current.parent
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as error:
        raise ValueError(f"path escapes Specula evidence for {label}: {raw}") from error
    if not resolved.is_file():
        raise ValueError(f"required Specula artifact is missing: {raw}")
    return resolved
