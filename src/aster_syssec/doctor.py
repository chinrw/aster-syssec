from __future__ import annotations

import hashlib
import shutil
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import Registry, validate_registry_against_checkout
from .handoff import validate_specula_agent_config
from .inventory import InventoryBuilder
from .source import inspect_source


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    detail: str
    required: bool


@dataclass(frozen=True)
class DoctorResult:
    status: str
    source: dict[str, Any]
    checks: tuple[Check, ...]
    capabilities: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_doctor(
    source_root: Path,
    registry: Registry,
    *,
    profile_root: Path | None = None,
    specula_repo: Path | None = None,
) -> DoctorResult:
    source_root = source_root.resolve()
    checks: list[Check] = []
    required_paths = (
        "kernel/core/src/syscall/mod.rs",
        "kernel/core/src/syscall/arch/x86.rs",
        "kernel/core/src/syscall/arch/generic.rs",
        "rust-toolchain.toml",
    )
    missing = [path for path in required_paths if not (source_root / path).is_file()]
    checks.append(
        Check(
            id="asterinas-layout",
            status="FAIL" if missing else "PASS",
            detail=f"missing: {', '.join(missing)}"
            if missing
            else "required syscall and toolchain files exist",
            required=True,
        )
    )
    snapshot = inspect_source(source_root)
    checks.append(
        Check(
            id="source-revision",
            status="PASS" if snapshot.revision else "WARN",
            detail=snapshot.revision
            or "source is not a Git checkout; provenance uses its content hash",
            required=False,
        )
    )

    toolchain_path = source_root / "rust-toolchain.toml"
    if toolchain_path.is_file():
        try:
            toolchain = tomllib.loads(toolchain_path.read_text(encoding="utf-8"))
            channel = toolchain["toolchain"]["channel"]
            checks.append(Check("rust-toolchain", "PASS", channel, True))
        except (KeyError, tomllib.TOMLDecodeError) as error:
            checks.append(Check("rust-toolchain", "FAIL", str(error), True))

    catalog = None
    if not missing:
        catalog = InventoryBuilder(source_root, registry).build()
        architecture_counts = {
            architecture: sum(
                architecture in item.architectures for item in catalog.syscalls
            )
            for architecture in ("x86_64", "riscv64", "loongarch64")
        }
        checks.append(
            Check(
                id="dispatch-inventory",
                status="PASS" if all(architecture_counts.values()) else "FAIL",
                detail=", ".join(
                    f"{key}={value}" for key, value in architecture_counts.items()
                ),
                required=True,
            )
        )
        structural_errors = [item for item in catalog.drift if item.severity == "error"]
        checks.append(
            Check(
                id="inventory-structural-drift",
                status="FAIL" if structural_errors else "PASS",
                detail=f"{len(structural_errors)} structural errors",
                required=True,
            )
        )
        checks.append(
            Check(
                id="coverage-debt",
                status="WARN"
                if any(item.severity == "warning" for item in catalog.drift)
                else "PASS",
                detail=(
                    f"{sum(item.severity == 'warning' for item in catalog.drift)} SCML/test coverage warnings"
                ),
                required=False,
            )
        )

    capabilities = {
        "static": "available",
        "inventory": "available",
        "aster-code-review": (
            "handoff-available"
            if (
                source_root / ".agents/skills/aster-code-review/aster_code_review.sh"
            ).is_file()
            else "not-present"
        ),
        "specula-handoff": "configured" if profile_root else "not-configured",
        "kani": "installed-unverified"
        if shutil.which("cargo-kani")
        else "not-installed",
        "miri": "installed-unverified"
        if shutil.which("cargo-miri")
        else "not-installed",
        "cargo-fuzz": "installed-unverified"
        if shutil.which("cargo-fuzz")
        else "not-installed",
        "loom": "adapter-not-implemented",
        "differential": "adapter-not-implemented",
        "kernel-fuzz": "adapter-not-implemented",
    }
    for tool in ("git", "uv", "tar"):
        path = shutil.which(tool)
        checks.append(
            Check(
                id=f"tool-{tool}",
                status="PASS" if path else "FAIL",
                detail=path or "not found on PATH",
                required=True,
            )
        )

    if profile_root is not None:
        profile_root = profile_root.resolve()
        config = profile_root / "specula-asterinas-hybrid.json"
        guidance = [profile_root / track.guidance for track in registry.tracks.values()]
        if config.is_file():
            try:
                validate_specula_agent_config(config)
                detail = f"sha256={_sha256(config)}"
                checks.append(Check("specula-agent-config", "PASS", detail, True))
            except (TypeError, ValueError, OSError) as error:
                checks.append(Check("specula-agent-config", "FAIL", str(error), True))
        else:
            checks.append(
                Check("specula-agent-config", "FAIL", f"missing {config}", True)
            )
        missing_guidance = [str(path) for path in guidance if not path.is_file()]
        checks.append(
            Check(
                id="specula-guidance",
                status="FAIL" if missing_guidance else "PASS",
                detail=(
                    f"missing: {', '.join(missing_guidance)}"
                    if missing_guidance
                    else f"{len(guidance)} configured track files"
                ),
                required=True,
            )
        )

    checks.extend(
        Check(issue.id, issue.status, issue.detail, issue.status == "FAIL")
        for issue in validate_registry_against_checkout(
            registry,
            source_root,
            catalog=catalog,
            profile_root=profile_root,
        )
    )

    if specula_repo is not None:
        specula_repo = specula_repo.resolve()
        marker = specula_repo / "pyproject.toml"
        checks.append(
            Check(
                id="specula-checkout",
                status="PASS" if marker.is_file() else "FAIL",
                detail=str(specula_repo),
                required=True,
            )
        )

    failed = any(check.required and check.status == "FAIL" for check in checks)
    warned = any(check.status == "WARN" for check in checks)
    status = "fail" if failed else "warn" if warned else "ok"
    return DoctorResult(
        status=status,
        source=snapshot.to_dict(),
        checks=tuple(checks),
        capabilities=capabilities,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
