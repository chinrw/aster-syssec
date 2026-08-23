from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterable

from .models import Property, Track


@dataclass(frozen=True)
class Registry:
    properties: dict[str, Property]
    tracks: dict[str, Track]
    config_hash: str

    def tracks_for_syscall(
        self,
        syscall: str,
        handler_path: str | None = None,
    ) -> tuple[str, ...]:
        selected: list[str] = []
        for track in self.tracks.values():
            if track.applies_to_all or syscall in track.syscalls:
                selected.append(track.id)
        return tuple(selected)

    def tracks_for_path(self, path: str) -> tuple[str, ...]:
        matches: list[tuple[int, str]] = []
        for track in self.tracks.values():
            matching_roots = [
                root
                for root in track.source_roots
                if path == root or path.startswith(f"{root.rstrip('/')}/")
            ]
            if matching_roots:
                matches.append((max(len(root) for root in matching_roots), track.id))
        return tuple(track_id for _, track_id in sorted(matches, key=lambda item: (-item[0], item[1])))


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
            raise ValueError(f"track {track.id} references unknown properties: {unknown}")
        tracks[track.id] = track
        hashed_files.append((f"tracks/{path.name}", payload))

    digest = hashlib.sha256()
    for name, payload in hashed_files:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return Registry(properties=properties, tracks=tracks, config_hash=digest.hexdigest())


def require_tracks(registry: Registry, track_ids: Iterable[str]) -> tuple[Track, ...]:
    selected: list[Track] = []
    for track_id in track_ids:
        try:
            selected.append(registry.tracks[track_id])
        except KeyError as error:
            choices = ", ".join(sorted(registry.tracks))
            raise ValueError(f"unknown track {track_id!r}; choose one of: {choices}") from error
    return tuple(selected)
