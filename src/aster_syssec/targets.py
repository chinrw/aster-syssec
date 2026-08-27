from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from .config import Registry
from .rust_source import mask_non_code
from .safety import SafetyPolicy
from .schemas import validate_instance


@dataclass(frozen=True)
class TargetLimits:
    timeout_seconds: int
    memory_bytes: int
    unwind: int | None


@dataclass(frozen=True)
class TargetPolicy:
    expected: str
    pr_blocking: bool


@dataclass(frozen=True)
class VerificationTarget:
    id: str
    engine: str
    track: str
    properties: tuple[str, ...]
    source_symbols: tuple[str, ...]
    safety: SafetyPolicy
    limits: TargetLimits
    policy: TargetPolicy
    configuration: dict[str, Any]
    config_path: str
    config_sha256: str

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "engine": self.engine,
            "track": self.track,
            "properties": list(self.properties),
            "safety": self.safety.summary(),
            "expected": self.policy.expected,
            "pr_blocking": self.policy.pr_blocking,
        }


@dataclass(frozen=True)
class TargetRegistry:
    targets: dict[str, VerificationTarget]
    config_hash: str

    def require(self, target_id: str) -> VerificationTarget:
        try:
            return self.targets[target_id]
        except KeyError as error:
            choices = ", ".join(sorted(self.targets)) or "none configured"
            raise ValueError(
                f"unknown verification target {target_id!r}; choose one of: {choices}"
            ) from error


@dataclass(frozen=True)
class TargetCheckIssue:
    id: str
    target: str
    status: str
    detail: str


def load_target_registry(
    registry: Registry,
    target_root: Path | None = None,
) -> TargetRegistry:
    root = _target_root(target_root)
    if target_root is not None and not root.is_dir():
        raise ValueError(f"verification target root does not exist: {root}")

    targets: dict[str, VerificationTarget] = {}
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.toml")) if root.is_dir() else ():
        payload = path.read_bytes()
        try:
            item = tomllib.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise ValueError(f"invalid verification target {path}: {error}") from error
        validate_instance(item, "verification-target.schema.json")
        target_id = item["id"]
        if path.stem != target_id:
            raise ValueError(
                f"verification target filename must match id {target_id!r}: {path.name}"
            )
        relative = path.relative_to(root)
        if len(relative.parts) < 2 or relative.parts[0] != item["engine"]:
            raise ValueError(
                f"verification target {target_id} must be stored under {item['engine']}/"
            )
        if target_id in targets:
            raise ValueError(f"duplicate verification target id: {target_id}")
        try:
            track = registry.tracks[item["track"]]
        except KeyError as error:
            raise ValueError(
                f"verification target {target_id} references unknown Track: {item['track']}"
            ) from error
        if item["engine"] not in track.engines:
            raise ValueError(
                f"verification target {target_id} uses engine {item['engine']} not declared by Track {track.id}"
            )
        unknown_properties = sorted(set(item["properties"]) - set(registry.properties))
        if unknown_properties:
            raise ValueError(
                f"verification target {target_id} references unknown properties: {unknown_properties}"
            )
        limits = item["limits"]
        policy = item["policy"]
        targets[target_id] = VerificationTarget(
            id=target_id,
            engine=item["engine"],
            track=track.id,
            properties=tuple(item["properties"]),
            source_symbols=tuple(item["source_symbols"]),
            safety=SafetyPolicy.from_mapping(item["safety"]),
            limits=TargetLimits(
                timeout_seconds=limits["timeout_seconds"],
                memory_bytes=limits["memory_bytes"],
                unwind=limits.get("unwind"),
            ),
            policy=TargetPolicy(
                expected=policy["expected"],
                pr_blocking=policy["pr_blocking"],
            ),
            configuration=item,
            config_path=str(path.resolve()),
            config_sha256=hashlib.sha256(payload).hexdigest(),
        )
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return TargetRegistry(targets=targets, config_hash=digest.hexdigest())


def validate_targets_against_checkout(
    target_registry: TargetRegistry,
    source_root: Path,
) -> tuple[TargetCheckIssue, ...]:
    source_root = Path(source_root).resolve()
    packages = _package_index(source_root)
    issues: list[TargetCheckIssue] = []
    for target in target_registry.targets.values():
        package_name = target.configuration.get("package")
        if not isinstance(package_name, str):
            continue
        manifests: tuple[Path, ...] = packages.get(package_name, ())
        if not manifests:
            issues.append(
                TargetCheckIssue(
                    id="package-missing",
                    target=target.id,
                    status="FAIL",
                    detail=f"Cargo package is not present in the Asterinas checkout: {package_name}",
                )
            )
            continue
        if len(manifests) > 1:
            issues.append(
                TargetCheckIssue(
                    id="package-ambiguous",
                    target=target.id,
                    status="FAIL",
                    detail=f"Cargo package name is not unique: {package_name}",
                )
            )
            continue
        package_root = next(iter(manifests)).parent
        configured_manifest = target.configuration.get("manifest_path")
        if isinstance(configured_manifest, str):
            relative_manifest = Path(configured_manifest)
            expected_manifest = package_root / "Cargo.toml"
            candidate_manifest = (source_root / relative_manifest).resolve()
            if (
                relative_manifest.is_absolute()
                or ".." in relative_manifest.parts
                or candidate_manifest != expected_manifest.resolve()
            ):
                issues.append(
                    TargetCheckIssue(
                        id="manifest-mismatch",
                        target=target.id,
                        status="FAIL",
                        detail=(
                            f"manifest_path does not identify package {package_name}: "
                            f"{configured_manifest}"
                        ),
                    )
                )
        rust_sources = tuple(
            path
            for path in sorted(package_root.rglob("*.rs"))
            if not _is_generated_path(path.relative_to(package_root))
        )
        masked_sources = tuple(
            (path, mask_non_code(path.read_text(encoding="utf-8")))
            for path in rust_sources
        )
        for symbol in target.source_symbols:
            pattern = re.compile(rf"\b{re.escape(symbol)}\b")
            if not any(pattern.search(text) for _, text in masked_sources):
                issues.append(
                    TargetCheckIssue(
                        id="source-symbol-missing",
                        target=target.id,
                        status="FAIL",
                        detail=f"source symbol is not present in package {package_name}: {symbol}",
                    )
                )
        harness = target.configuration.get("harness")
        if isinstance(harness, str) and target.engine == "kani":
            proof = re.compile(
                rf"#\s*\[\s*kani::proof\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+{re.escape(harness)}\s*\("
            )
            if not any(proof.search(text) for _, text in masked_sources):
                issues.append(
                    TargetCheckIssue(
                        id="kani-harness-missing",
                        target=target.id,
                        status="FAIL",
                        detail=f"Kani proof harness is not present in package {package_name}: {harness}",
                    )
                )
        test = target.configuration.get("test")
        if isinstance(test, str) and target.engine in {"loom", "miri"}:
            function = test.rsplit("::", 1)[-1]
            test_pattern = re.compile(
                rf"#\s*\[\s*test\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+{re.escape(function)}\s*\("
            )
            if not any(test_pattern.search(text) for _, text in masked_sources):
                issues.append(
                    TargetCheckIssue(
                        id="test-missing",
                        target=target.id,
                        status="FAIL",
                        detail=f"verification test is not present in package {package_name}: {test}",
                    )
                )
        fuzz_target = target.configuration.get("fuzz_target")
        if isinstance(fuzz_target, str) and target.engine == "fuzz":
            fuzz_source = package_root / "fuzz_targets" / f"{fuzz_target}.rs"
            if not fuzz_source.is_file():
                issues.append(
                    TargetCheckIssue(
                        id="fuzz-target-missing",
                        target=target.id,
                        status="FAIL",
                        detail=(
                            f"cargo-fuzz target is not present in package {package_name}: "
                            f"{fuzz_target}"
                        ),
                    )
                )
    return tuple(issues)


def _target_root(target_root: Path | None) -> Path:
    if target_root is not None:
        return Path(target_root).resolve()
    traversable = resources.files("aster_syssec").joinpath("data/targets")
    return Path(str(traversable))


def _package_index(source_root: Path) -> dict[str, tuple[Path, ...]]:
    found: dict[str, list[Path]] = {}
    for manifest in sorted(source_root.rglob("Cargo.toml")):
        if _is_generated_path(manifest.relative_to(source_root)):
            continue
        try:
            item = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        name = item.get("package", {}).get("name")
        if isinstance(name, str):
            found.setdefault(name, []).append(manifest)
    return {name: tuple(paths) for name, paths in found.items()}


def _is_generated_path(relative: Path) -> bool:
    return any(part in {".git", "build", "target"} for part in relative.parts)
