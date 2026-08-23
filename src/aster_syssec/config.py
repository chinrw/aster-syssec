from __future__ import annotations

import hashlib
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .models import Catalog, Property, Track

KNOWN_ENGINES = frozenset(
    {
        "differential",
        "fault-injection",
        "fuzz",
        "kani",
        "kernel-fuzz",
        "kselftest",
        "layout",
        "loom",
        "ltp",
        "miri",
        "regression",
        "specula",
        "static",
        "stress",
        "xfstests",
    }
)
SPECULA_READINESS = frozenset(
    {
        "analysis-only",
        "analysis-only-narrow-before-specgen",
        "analysis-only-select-one-resource-family",
    }
)


@dataclass(frozen=True)
class Registry:
    properties: dict[str, Property]
    tracks: dict[str, Track]
    config_hash: str


@dataclass(frozen=True)
class ConfigIssue:
    id: str
    status: str
    detail: str


def _read_toml(path: Path) -> tuple[dict, bytes]:
    payload = path.read_bytes()
    return tomllib.loads(payload.decode("utf-8")), payload


def load_registry(config_root: Path | None = None) -> Registry:
    if config_root is None:
        traversable = resources.files("aster_syssec").joinpath("data")
        root = Path(str(traversable))
    else:
        root = Path(config_root).resolve()

    invariant_data, invariant_bytes = _read_toml(root / "invariants.toml")
    properties: dict[str, Property] = {}
    for item in invariant_data.get("properties", []):
        prop = Property(id=item["id"], description=item["description"])
        if prop.id in properties:
            raise ValueError(f"duplicate property id: {prop.id}")
        properties[prop.id] = prop

    tracks: dict[str, Track] = {}
    hashed_files: list[tuple[str, bytes]] = [("invariants.toml", invariant_bytes)]
    for path in sorted((root / "tracks").glob("*.toml")):
        item, payload = _read_toml(path)
        track = Track(
            id=item["id"],
            description=item["description"],
            syscalls=tuple(item.get("syscalls", [])),
            source_roots=tuple(item.get("source_roots", [])),
            properties=tuple(item.get("properties", [])),
            engines=tuple(item.get("engines", [])),
            guidance=item["guidance"],
            specula_readiness=item["specula_readiness"],
            target=item["target"],
            applies_to_all=bool(item.get("applies_to_all", False)),
        )
        if track.id in tracks:
            raise ValueError(f"duplicate track id: {track.id}")
        unknown = sorted(set(track.properties) - set(properties))
        if unknown:
            raise ValueError(
                f"track {track.id} references unknown properties: {unknown}"
            )
        unknown_engines = sorted(set(track.engines) - KNOWN_ENGINES)
        if unknown_engines:
            raise ValueError(
                f"track {track.id} references unknown engine names: {unknown_engines}"
            )
        if track.specula_readiness not in SPECULA_READINESS:
            raise ValueError(
                f"track {track.id} has unknown specula_readiness: {track.specula_readiness}"
            )
        target_parts = track.target.split("|")
        if len(target_parts) != 4 or any(not part.strip() for part in target_parts):
            raise ValueError(
                f"track {track.id} target must contain four non-empty pipe-separated fields"
            )
        for source_root in track.source_roots:
            _validate_relative_config_path(track.id, "source_root", source_root)
        _validate_relative_config_path(track.id, "guidance", track.guidance)
        tracks[track.id] = track
        hashed_files.append((f"tracks/{path.name}", payload))

    digest = hashlib.sha256()
    for name, payload in hashed_files:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return Registry(
        properties=properties, tracks=tracks, config_hash=digest.hexdigest()
    )


def require_tracks(registry: Registry, track_ids: Iterable[str]) -> tuple[Track, ...]:
    selected: list[Track] = []
    for track_id in track_ids:
        try:
            selected.append(registry.tracks[track_id])
        except KeyError as error:
            choices = ", ".join(sorted(registry.tracks))
            raise ValueError(
                f"unknown track {track_id!r}; choose one of: {choices}"
            ) from error
    return tuple(selected)


def validate_registry_against_checkout(
    registry: Registry,
    source_root: Path,
    *,
    catalog: Catalog | None = None,
    profile_root: Path | None = None,
) -> tuple[ConfigIssue, ...]:
    source_root = Path(source_root).resolve()
    profile_root = Path(profile_root).resolve() if profile_root is not None else None
    implemented = (
        {item.name for item in catalog.syscalls} if catalog is not None else set()
    )
    issues: list[ConfigIssue] = []
    for track in registry.tracks.values():
        selectable = bool(track.applies_to_all and implemented)
        for raw in track.source_roots:
            candidate = source_root / raw
            try:
                candidate.resolve().relative_to(source_root)
            except ValueError:
                issues.append(
                    ConfigIssue(
                        id=f"config-source-root:{track.id}",
                        status="FAIL",
                        detail=f"Track source root escapes Asterinas checkout: {raw}",
                    )
                )
                continue
            if not candidate.exists():
                issues.append(
                    ConfigIssue(
                        id=f"config-source-root:{track.id}",
                        status="FAIL",
                        detail=f"missing Track source root: {raw}",
                    )
                )
                continue
            if (
                candidate.is_file()
                and candidate.suffix == ".rs"
                or candidate.is_dir()
                and any(candidate.rglob("*.rs"))
            ):
                selectable = True
        for syscall in track.syscalls:
            if catalog is None:
                continue
            if syscall in implemented:
                selectable = True
            else:
                issues.append(
                    ConfigIssue(
                        id=f"config-syscall:{track.id}:{syscall}",
                        status="WARN",
                        detail=f"configured syscall is not dispatched: {syscall}",
                    )
                )
        if profile_root is not None:
            guidance = profile_root / track.guidance
            if not guidance.is_file():
                issues.append(
                    ConfigIssue(
                        id=f"config-guidance:{track.id}",
                        status="FAIL",
                        detail=f"missing Track guidance: {guidance}",
                    )
                )
        if catalog is not None and not selectable:
            issues.append(
                ConfigIssue(
                    id=f"config-empty-track:{track.id}",
                    status="FAIL",
                    detail="Track selects no implemented syscall or existing Rust source",
                )
            )
    return tuple(issues)


def _validate_relative_config_path(track_id: str, field: str, raw: str) -> None:
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(
            f"track {track_id} {field} must be a non-empty relative path: {raw!r}"
        )
