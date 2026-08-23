from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Property:
    id: str
    description: str


@dataclass(frozen=True)
class Track:
    id: str
    description: str
    syscalls: tuple[str, ...]
    source_roots: tuple[str, ...]
    properties: tuple[str, ...]
    engines: tuple[str, ...]
    guidance: str
    specula_readiness: str
    target: str
    applies_to_all: bool = False


@dataclass(frozen=True)
class DispatchEntry:
    number: int
    arity: int
    constant: str
    path: str
    line: int


@dataclass(frozen=True)
class EvidenceCoverage:
    status: str
    files: tuple[str, ...] = ()
    reference_count: int = 0


@dataclass(frozen=True)
class SyscallEntry:
    name: str
    handler: str
    architectures: dict[str, DispatchEntry]
    handler_path: str | None
    handler_line: int | None
    raw_abi_argument_count: int
    converted_rust_types: tuple[str, ...]
    user_pointers: tuple[str, ...]
    copy_in_operations: tuple[str, ...]
    copy_out_operations: tuple[str, ...]
    kernel_objects_reached: tuple[str, ...]
    permission_checks: tuple[str, ...]
    locks_and_waits: tuple[str, ...]
    scml: EvidenceCoverage
    regression: EvidenceCoverage
    security_tracks: tuple[str, ...]


@dataclass(frozen=True)
class Drift:
    kind: str
    severity: str
    message: str
    syscall: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class Catalog:
    source: dict[str, Any]
    syscalls: tuple[SyscallEntry, ...]
    drift: tuple[Drift, ...]
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Candidate:
    finding_id: str
    rule_id: str
    title: str
    track: str
    source_commit: str | None
    path: str
    line: int
    symbol: str | None
    violated_property: str
    evidence: str
    rationale: str
    confidence: str
    expected_result: str | None = None
    observed_result: str | None = None
    reproducer_path: str | None = None
    linux_comparison: str | None = None
    scml_support_status: str | None = None
    security_impact: str | None = None
    raw_artifact_paths: tuple[str, ...] = ()
    engine: str = "static"
    status: str = "candidate"
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["source_anchor"] = {
            "path": result.pop("path"),
            "line": result.pop("line"),
            "symbol": result.pop("symbol"),
        }
        return result


@dataclass(frozen=True)
class ReviewResult:
    source: dict[str, Any]
    files_selected: tuple[str, ...]
    files_scanned: tuple[str, ...]
    functions_scanned: int
    candidates: tuple[Candidate, ...]
    rules_run: tuple[str, ...]
    limitations: tuple[str, ...]
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source": self.source,
            "files_selected": list(self.files_selected),
            "files_scanned": list(self.files_scanned),
            "functions_scanned": self.functions_scanned,
            "rules_run": list(self.rules_run),
            "limitations": list(self.limitations),
            "candidates": [item.to_dict() for item in self.candidates],
        }
