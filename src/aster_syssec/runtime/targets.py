from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from ..config import Registry
from ..rust_source import mask_non_code
from ..safety import SafetyClass, SafetyPolicy
from ..schemas import validate_instance


@dataclass(frozen=True)
class RuntimeLimits:
    build_timeout_seconds: int
    boot_timeout_seconds: int
    test_timeout_seconds: int
    output_bytes: int
    memory_bytes: int
    smp: int


@dataclass(frozen=True)
class RuntimeTarget:
    id: str
    track: str
    case_id: str
    guest_case: str
    target_arch: str
    properties: tuple[str, ...]
    source_symbols: tuple[str, ...]
    safety: SafetyPolicy
    oracle: str
    comparator: str
    limits: RuntimeLimits
    expected: str
    configuration: dict[str, Any]
    config_path: str
    config_sha256: str

    def summary(self) -> dict[str, object]:
        return {
            "id": self.id,
            "track": self.track,
            "case_id": self.case_id,
            "target_arch": self.target_arch,
            "oracle": self.oracle,
            "comparator": self.comparator,
            "expected": self.expected,
            "safety": self.safety.summary(),
        }


@dataclass(frozen=True)
class RuntimeTargetRegistry:
    targets: dict[str, RuntimeTarget]
    config_hash: str

    def require(self, target_id: str) -> RuntimeTarget:
        try:
            return self.targets[target_id]
        except KeyError as error:
            choices = ", ".join(sorted(self.targets)) or "none configured"
            raise ValueError(
                f"unknown Runtime target {target_id!r}; choose one of: {choices}"
            ) from error


@dataclass(frozen=True)
class RuntimeProfile:
    id: str
    safety_class: SafetyClass
    target: str


@dataclass(frozen=True)
class RuntimeProfileRegistry:
    profiles: dict[str, RuntimeProfile]
    config_sha256: str

    def require(self, profile_id: str) -> RuntimeProfile:
        try:
            return self.profiles[profile_id]
        except KeyError as error:
            choices = ", ".join(sorted(self.profiles)) or "none configured"
            raise ValueError(
                f"unknown Runtime profile {profile_id!r}; choose one of: {choices}"
            ) from error


@dataclass(frozen=True)
class RuntimeTargetCheckIssue:
    id: str
    target: str
    status: str
    detail: str


def load_runtime_target_registry(
    registry: Registry,
    target_root: Path | None = None,
) -> RuntimeTargetRegistry:
    root = _runtime_target_root(target_root)
    if target_root is not None and not root.is_dir():
        raise ValueError(f"Runtime target root does not exist: {root}")

    targets: dict[str, RuntimeTarget] = {}
    digest = hashlib.sha256()
    for path in sorted(root.glob("*.json")) if root.is_dir() else ():
        payload = path.read_bytes()
        try:
            item = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid Runtime target {path}: {error}") from error
        validate_instance(item, "runtime-target.schema.json")
        target_id = item["id"]
        if path.stem != target_id:
            raise ValueError(
                f"Runtime target filename must match id {target_id!r}: {path.name}"
            )
        if target_id in targets:
            raise ValueError(f"duplicate Runtime target id: {target_id}")
        try:
            track = registry.tracks[item["track"]]
        except KeyError as error:
            raise ValueError(
                f"Runtime target {target_id} references unknown Track: {item['track']}"
            ) from error
        unknown_properties = sorted(set(item["properties"]) - set(registry.properties))
        if unknown_properties:
            raise ValueError(
                f"Runtime target {target_id} references unknown properties: {unknown_properties}"
            )
        limits = item["limits"]
        targets[target_id] = RuntimeTarget(
            id=target_id,
            track=track.id,
            case_id=item["case_id"],
            guest_case=item["guest_case"],
            target_arch=item["target_arch"],
            properties=tuple(item["properties"]),
            source_symbols=tuple(item["source_symbols"]),
            safety=SafetyPolicy.from_mapping(item["safety"]),
            oracle=item["oracle"],
            comparator=item["comparator"],
            limits=RuntimeLimits(
                build_timeout_seconds=limits["build_timeout_seconds"],
                boot_timeout_seconds=limits["boot_timeout_seconds"],
                test_timeout_seconds=limits["test_timeout_seconds"],
                output_bytes=limits["output_bytes"],
                memory_bytes=limits["memory_bytes"],
                smp=limits["smp"],
            ),
            expected=item["expected"],
            configuration=item,
            config_path=str(path.resolve()),
            config_sha256=hashlib.sha256(payload).hexdigest(),
        )
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return RuntimeTargetRegistry(targets=targets, config_hash=digest.hexdigest())


def load_runtime_profile_registry(
    path: Path | None = None,
) -> RuntimeProfileRegistry:
    config = (
        path.resolve()
        if path is not None
        else Path(
            str(resources.files("aster_syssec").joinpath("data/runtime-profiles.toml"))
        )
    )
    if not config.is_file():
        raise ValueError(f"Runtime profile config does not exist: {config}")
    payload = config.read_bytes()
    try:
        parsed = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"invalid Runtime profile config: {error}") from error
    if parsed.get("version") != 1 or not isinstance(parsed.get("profiles"), dict):
        raise ValueError("Runtime profile config must contain version 1 profiles")
    profiles: dict[str, RuntimeProfile] = {}
    for profile_id, value in parsed["profiles"].items():
        if not isinstance(value, dict):
            raise TypeError(f"Runtime profile must be an object: {profile_id}")
        unknown = sorted(set(value) - {"safety_class", "target"})
        if unknown:
            raise ValueError(
                f"Runtime profile {profile_id} has unknown keys: {unknown}"
            )
        safety_class = value.get("safety_class")
        target = value.get("target")
        if not isinstance(safety_class, str) or not isinstance(target, str):
            raise TypeError(
                f"Runtime profile {profile_id} must declare safety_class and target"
            )
        try:
            parsed_class = SafetyClass(safety_class)
        except ValueError as error:
            raise ValueError(
                f"Runtime profile {profile_id} has unknown safety_class: {safety_class}"
            ) from error
        profiles[profile_id] = RuntimeProfile(
            id=profile_id,
            safety_class=parsed_class,
            target=target,
        )
    return RuntimeProfileRegistry(
        profiles=profiles,
        config_sha256=hashlib.sha256(payload).hexdigest(),
    )


def validate_runtime_targets_against_checkout(
    target_registry: RuntimeTargetRegistry,
    registry: Registry,
    source_root: Path,
) -> tuple[RuntimeTargetCheckIssue, ...]:
    source_root = source_root.resolve()
    issues: list[RuntimeTargetCheckIssue] = []
    for target in target_registry.targets.values():
        case = (
            source_root / "test/initramfs/src/regression" / (target.guest_case + ".c")
        )
        if not case.is_file():
            issues.append(
                RuntimeTargetCheckIssue(
                    id="guest-case-missing",
                    target=target.id,
                    status="FAIL",
                    detail=f"guest case is not present: {target.guest_case}.c",
                )
            )
        track = registry.tracks[target.track]
        source_paths = [
            source_root / relative
            for relative in (
                *track.source_roots,
                "kernel/core/src/syscall/arch/x86.rs",
                "kernel/core/src/syscall/arch/generic.rs",
            )
        ]
        sources = tuple(
            mask_non_code(path.read_text(encoding="utf-8"))
            for path in source_paths
            if path.is_file() and path.suffix == ".rs"
        )
        for symbol in target.source_symbols:
            pattern = re.compile(rf"\b{re.escape(symbol)}\b")
            if not any(pattern.search(source) for source in sources):
                issues.append(
                    RuntimeTargetCheckIssue(
                        id="source-symbol-missing",
                        target=target.id,
                        status="FAIL",
                        detail=f"source symbol is not present in Track roots: {symbol}",
                    )
                )
    return tuple(issues)


def _runtime_target_root(value: Path | None) -> Path:
    if value is not None:
        return value.resolve()
    return Path(str(resources.files("aster_syssec").joinpath("data/runtime-targets")))
