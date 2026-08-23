from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .config import Registry, require_tracks
from .models import Catalog, Track

_CONTEXT_DOMINANT_RULES = frozenset(
    {
        "COPYOUT-AFTER-SIDE-EFFECT",
        "DOUBLE-FETCH-USER-METADATA",
        "LOCK-GUARD-ACROSS-BLOCKING",
        "TYPED-STRUCT-COPYOUT",
    }
)


@dataclass(frozen=True)
class TrackSelection:
    tracks: tuple[Track, ...]
    syscalls: tuple[str, ...]
    source_roots: tuple[str, ...]


@dataclass(frozen=True)
class CandidateRoute:
    primary: str
    related: tuple[str, ...]


class TrackRouter:
    """Owns Security Track membership, selection, and candidate precedence."""

    def __init__(self, registry: Registry, catalog: Catalog | None = None):
        self.registry = registry
        self._symbol_tracks: dict[str, list[str]] = {}
        self._catalog_path_tracks: dict[str, list[str]] = {}
        if catalog is None:
            return
        for syscall in catalog.syscalls:
            self._extend(self._symbol_tracks, syscall.handler, syscall.security_tracks)
            if syscall.handler_path:
                self._extend(
                    self._catalog_path_tracks,
                    syscall.handler_path,
                    syscall.security_tracks,
                )

    def syscall_tracks(
        self, syscall: str, handler_path: str | None = None
    ) -> tuple[str, ...]:
        matches = [
            track.id
            for track in self.registry.tracks.values()
            if track.applies_to_all or syscall in track.syscalls
        ]
        if handler_path is not None:
            self._append_unique(matches, self.path_tracks(handler_path))
        return tuple(matches)

    def path_tracks(self, path: str) -> tuple[str, ...]:
        matches: list[tuple[int, str]] = []
        for track in self.registry.tracks.values():
            matching_roots = [
                root
                for root in track.source_roots
                if path == root or path.startswith(f"{root.rstrip('/')}/")
            ]
            if matching_roots:
                matches.append((max(len(root) for root in matching_roots), track.id))
        return tuple(
            track_id
            for _, track_id in sorted(matches, key=lambda item: (-item[0], item[1]))
        )

    def selection(self, track_ids: Iterable[str]) -> TrackSelection:
        tracks = require_tracks(self.registry, track_ids)
        syscalls: list[str] = []
        source_roots: list[str] = []
        for track in tracks:
            self._append_unique(syscalls, track.syscalls)
            self._append_unique(source_roots, track.source_roots)
        return TrackSelection(
            tracks=tracks,
            syscalls=tuple(syscalls),
            source_roots=tuple(source_roots),
        )

    def candidate_route(
        self,
        *,
        rule_id: str,
        preferred_track: str,
        symbol: str | None,
        path: str,
    ) -> CandidateRoute:
        contextual: list[str] = []
        if symbol is not None:
            self._append_unique(contextual, self._symbol_tracks.get(symbol, ()))
        self._append_unique(contextual, self._catalog_path_tracks.get(path, ()))
        self._append_unique(contextual, self.path_tracks(path))
        non_abi = [track for track in contextual if track != "abi-integer-layout"]

        if rule_id in _CONTEXT_DOMINANT_RULES and non_abi:
            primary = preferred_track if preferred_track in non_abi else non_abi[0]
        elif preferred_track in self.registry.tracks:
            primary = preferred_track
        elif non_abi:
            primary = non_abi[0]
        else:
            primary = "abi-integer-layout"

        related = [track for track in contextual if track != primary]
        if preferred_track in self.registry.tracks and preferred_track != primary:
            self._append_unique(related, (preferred_track,))
        return CandidateRoute(primary=primary, related=tuple(related))

    @staticmethod
    def _append_unique(target: list[str], values: Iterable[str]) -> None:
        for value in values:
            if value not in target:
                target.append(value)

    @classmethod
    def _extend(
        cls,
        index: dict[str, list[str]],
        key: str,
        values: Iterable[str],
    ) -> None:
        cls._append_unique(index.setdefault(key, []), values)
