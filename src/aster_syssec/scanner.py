from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import Registry
from .models import Candidate, Catalog, ReviewResult
from .source import inspect_source, relative_paths


RULE_IDS = (
    "RAW-DISPATCH-INFERRED-CAST",
    "LOSSY-ABI-CAST",
    "FLAGS-TRUNCATE-UNKNOWN",
    "UNCHECKED-RANGE-ARITHMETIC",
    "REACHABLE-PANIC",
    "DOUBLE-FETCH-USER-METADATA",
    "COPYOUT-AFTER-SIDE-EFFECT",
    "LOCK-GUARD-ACROSS-BLOCKING",
    "TYPED-STRUCT-COPYOUT",
)


@dataclass(frozen=True)
class _Function:
    symbol: str
    start: int
    end: int
    start_line: int
    parameter_names: tuple[str, ...]


@dataclass(frozen=True)
class _RawCandidate:
    rule_id: str
    title: str
    property_id: str
    line: int
    symbol: str | None
    evidence: str
    rationale: str
    confidence: str
    preferred_track: str


class StaticReviewer:
    def __init__(self, source_root: Path, registry: Registry, catalog: Catalog):
        self.source_root = Path(source_root).resolve()
        self.registry = registry
        self.catalog = catalog
        self._handler_entries: dict[str, list] = {}
        self._path_tracks: dict[str, list[str]] = {}
        for syscall in catalog.syscalls:
            self._handler_entries.setdefault(syscall.handler, []).append(syscall)
            if syscall.handler_path:
                tracks = self._path_tracks.setdefault(syscall.handler_path, [])
                for track in syscall.security_tracks:
                    if track not in tracks:
                        tracks.append(track)

    def review(
        self,
        paths: Iterable[Path],
        *,
        scope: str = "handlers",
        rule_ids: Iterable[str] | None = None,
    ) -> ReviewResult:
        if scope not in {"handlers", "selected"}:
            raise ValueError("static review scope must be handlers or selected")
        selected_rules = set(rule_ids or RULE_IDS)
        unknown_rules = selected_rules - set(RULE_IDS)
        if unknown_rules:
            raise ValueError(f"unknown static rule ids: {sorted(unknown_rules)}")
        relative = relative_paths(self.source_root, paths)
        snapshot = inspect_source(self.source_root)
        candidates: list[Candidate] = []
        scanned_files: list[str] = []
        function_count = 0
        for relative_path in sorted(set(relative)):
            path = self.source_root / relative_path
            if path.suffix != ".rs" or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            masked = mask_non_code(text)
            functions = _extract_functions(masked, handlers_only=scope == "handlers")
            raw_candidates = _scan_file_level(text, masked, relative_path)
            raw_candidates.extend(_scan_file(text, masked, functions))
            if scope == "selected" or functions or raw_candidates:
                scanned_files.append(relative_path)
            function_count += len(functions)
            for raw in raw_candidates:
                if raw.rule_id not in selected_rules:
                    continue
                track = self._route(raw, relative_path)
                candidate_id = _candidate_id(
                    snapshot.revision,
                    raw.rule_id,
                    relative_path,
                    raw.line,
                    raw.evidence,
                )
                candidates.append(
                    Candidate(
                        finding_id=candidate_id,
                        rule_id=raw.rule_id,
                        title=(
                            "Track-selected code contains a panic-shaped path"
                            if scope == "selected" and raw.rule_id == "REACHABLE-PANIC"
                            else raw.title
                        ),
                        track=track,
                        source_commit=snapshot.revision,
                        path=relative_path,
                        line=raw.line,
                        symbol=raw.symbol,
                        violated_property=raw.property_id,
                        evidence=raw.evidence,
                        rationale=(
                            "Determine whether a supported syscall reaches this path and whether attacker-controlled input satisfies its precondition."
                            if scope == "selected" and raw.rule_id == "REACHABLE-PANIC"
                            else raw.rationale
                        ),
                        confidence=raw.confidence,
                        scml_support_status=self._scml_status(raw.symbol),
                    )
                )
        deduplicated = {item.finding_id: item for item in candidates}
        ordered = tuple(
            sorted(
                deduplicated.values(),
                key=lambda item: (item.path, item.line, item.rule_id),
            )
        )
        return ReviewResult(
            source=snapshot.to_dict(),
            files_selected=tuple(sorted(set(relative))),
            files_scanned=tuple(sorted(set(scanned_files))),
            functions_scanned=function_count,
            candidates=ordered,
            rules_run=tuple(rule_id for rule_id in RULE_IDS if rule_id in selected_rules),
            limitations=(
                (
                    "Handler scope follows syscall handlers and same-file function calls only; method and cross-file reachability require selected scope, manual review, or a MIR backend."
                    if scope == "handlers"
                    else "Selected scope scans every function in selected paths; path membership does not prove syscall reachability."
                ),
                "A candidate identifies a review premise, not a violated runtime contract or security impact.",
                "Regression coverage is an identifier-reference heuristic, not executed test coverage.",
            ),
        )

    def _route(self, raw: _RawCandidate, path: str) -> str:
        contextual_tracks = list(self._symbol_tracks(raw.symbol))
        contextual_tracks.extend(
            track for track in self._path_tracks.get(path, ()) if track not in contextual_tracks
        )
        contextual_tracks.extend(
            track for track in self.registry.tracks_for_path(path) if track not in contextual_tracks
        )
        if raw.preferred_track in self.registry.tracks:
            if raw.preferred_track in {"abi-integer-layout", "user-memory-partial-io"}:
                if "socket-cmsg-iovec" in contextual_tracks and raw.rule_id in {
                    "DOUBLE-FETCH-USER-METADATA",
                    "COPYOUT-AFTER-SIDE-EFFECT",
                    "TYPED-STRUCT-COPYOUT",
                }:
                    return "socket-cmsg-iovec"
            return raw.preferred_track
        non_abi = [track for track in contextual_tracks if track != "abi-integer-layout"]
        return non_abi[0] if non_abi else "abi-integer-layout"

    def _symbol_tracks(self, symbol: str | None) -> tuple[str, ...]:
        if symbol is None:
            return ()
        tracks: list[str] = []
        for entry in self._handler_entries.get(symbol, []):
            for track in entry.security_tracks:
                if track not in tracks:
                    tracks.append(track)
        return tuple(tracks)

    def _scml_status(self, symbol: str | None) -> str | None:
        if symbol is None:
            return None
        statuses = {entry.scml.status for entry in self._handler_entries.get(symbol, [])}
        if "described" in statuses:
            return "described"
        if statuses:
            return "missing"
        return None


def _scan_file(text: str, masked: str, functions: tuple[_Function, ...]) -> list[_RawCandidate]:
    result: list[_RawCandidate] = []
    for function in functions:
        code = masked[function.start:function.end]
        original = text[function.start:function.end]
        result.extend(_scan_line_rules(original, code, function))
        result.extend(_scan_double_fetch(original, code, function))
        result.extend(_scan_copyout_after_effect(original, code, function))
        result.extend(_scan_guard_across_blocking(original, code, function))
        result.extend(_scan_typed_copyout(original, code, function))
    return result


def _scan_file_level(text: str, masked: str, path: str) -> list[_RawCandidate]:
    if path != "kernel/core/src/syscall/mod.rs":
        return []
    match = re.search(r"\$args\s*\[\s*\d+\s*\]\s+as\s+_", masked)
    if match is None:
        return []
    line = masked.count("\n", 0, match.start()) + 1
    return [
        _RawCandidate(
            rule_id="RAW-DISPATCH-INFERRED-CAST",
            title="Raw syscall registers use inferred `as _` conversion",
            property_id="LINUX-ABI-CONTRACT",
            line=line,
            symbol="syscall_handler",
            evidence=_line_at(text, line),
            rationale=(
                "Audit each handler's inferred signedness and width; safety depends on the typed parameter and later validation."
            ),
            confidence="high",
            preferred_track="abi-integer-layout",
        )
    ]


def _scan_line_rules(original: str, code: str, function: _Function) -> list[_RawCandidate]:
    result: list[_RawCandidate] = []
    original_lines = original.splitlines()
    code_lines = code.splitlines()
    parameters = set(function.parameter_names)
    for offset, code_line in enumerate(code_lines):
        line = function.start_line + offset
        evidence = original_lines[offset].strip() if offset < len(original_lines) else ""
        if re.search(r"::from_bits_truncate\s*\(", code_line):
            result.append(
                _RawCandidate(
                    rule_id="FLAGS-TRUNCATE-UNKNOWN",
                    title="Unknown flag bits are silently discarded",
                    property_id="BOUNDARY-VALIDATION",
                    line=line,
                    symbol=function.symbol,
                    evidence=evidence,
                    rationale="Confirm that the syscall contract permits unknown bits to be ignored before any state change.",
                    confidence="high",
                    preferred_track="abi-integer-layout",
                )
            )
        if re.search(r"\b(?:unwrap|expect)\s*\(|\b(?:panic|todo|unimplemented)!\s*\(", code_line):
            result.append(
                _RawCandidate(
                    rule_id="REACHABLE-PANIC",
                    title="Syscall-reachable code may panic",
                    property_id="BOUNDED-UNPRIVILEGED-WORK",
                    line=line,
                    symbol=function.symbol,
                    evidence=evidence,
                    rationale="Prove the panic precondition is unreachable for attacker-controlled syscall inputs or return an errno.",
                    confidence="high",
                    preferred_track="resource-rollback-dos",
                )
            )
        for match in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s+as\s+(usize|isize|u8|u16|u32|i8|i16|i32|_)",
            code_line,
        ):
            if match.group(1) not in parameters:
                continue
            result.append(
                _RawCandidate(
                    rule_id="LOSSY-ABI-CAST",
                    title="Typed syscall parameter is narrowed with `as`",
                    property_id="LINUX-ABI-CONTRACT",
                    line=line,
                    symbol=function.symbol,
                    evidence=evidence,
                    rationale="Check signedness, width, and rejected values against the architecture ABI.",
                    confidence="medium",
                    preferred_track="abi-integer-layout",
                )
            )
        if "checked_" not in code_line and "saturating_" not in code_line and "wrapping_" not in code_line:
            for parameter in parameters:
                if not any(token in parameter.lower() for token in ("addr", "len", "count", "size", "offset")):
                    continue
                if re.search(rf"\b{re.escape(parameter)}\b\s*[+*]|[+*]\s*\b{re.escape(parameter)}\b", code_line):
                    result.append(
                        _RawCandidate(
                            rule_id="UNCHECKED-RANGE-ARITHMETIC",
                            title="Syscall range arithmetic is not visibly checked",
                            property_id="BOUNDARY-VALIDATION",
                            line=line,
                            symbol=function.symbol,
                            evidence=evidence,
                            rationale="Trace the expression to a checked range helper or prove overflow cannot alter the validated range.",
                            confidence="medium",
                            preferred_track="abi-integer-layout",
                        )
                    )
                    break
    return result


def _scan_double_fetch(original: str, code: str, function: _Function) -> list[_RawCandidate]:
    pattern = re.compile(r"\b(?:read_val|read_slice|read_bytes)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)")
    seen: dict[str, int] = {}
    for match in pattern.finditer(code):
        argument = match.group(1)
        if argument in seen:
            line = function.start_line + code.count("\n", 0, match.start())
            return [
                _RawCandidate(
                    rule_id="DOUBLE-FETCH-USER-METADATA",
                    title="User metadata is fetched more than once",
                    property_id="BOUNDARY-VALIDATION",
                    line=line,
                    symbol=function.symbol,
                    evidence=_line_at(original, code.count("\n", 0, match.start()) + 1),
                    rationale="Check whether concurrent userspace mutation can combine pointer, length, or flag generations.",
                    confidence="medium",
                    preferred_track="user-memory-partial-io",
                )
            ]
        seen[argument] = match.start()
    return []


def _scan_copyout_after_effect(original: str, code: str, function: _Function) -> list[_RawCandidate]:
    effect = re.compile(
        r"(?:\.(?:recvmsg|sendmsg|sendmmsg|recvfrom|accept|truncate|remove|insert|install|consume|dequeue|pop_front)\s*\("
        r"|\b(?:add_file|insert_entry|remove_entry|install_fd|consume_message|send_one_message)\s*\()"
    )
    copyout = re.compile(
        r"\b(?:write_val|write_slice|write_bytes|copy_[a-z_]*to_user|"
        r"write_socket_addr_to_user|write_control_messages_to_user)\s*\("
    )
    effect_match = effect.search(code)
    if effect_match is None:
        return []
    copyout_match = copyout.search(code, effect_match.end())
    if copyout_match is None:
        return []
    effect_line_number = code.count("\n", 0, effect_match.start()) + 1
    copy_line_number = code.count("\n", 0, copyout_match.start()) + 1
    evidence = f"effect: {_line_at(original, effect_line_number)}; copy-out: {_line_at(original, copy_line_number)}"
    return [
        _RawCandidate(
            rule_id="COPYOUT-AFTER-SIDE-EFFECT",
            title="Fallible copy-out follows a possible external side effect",
            property_id="FAILURE-ATOMICITY",
            line=function.start_line + copy_line_number - 1,
            symbol=function.symbol,
            evidence=evidence,
            rationale="Identify the syscall-specific commit point and verify copy-out failure cannot leak, duplicate, strand, or misreport state.",
            confidence="medium",
            preferred_track="user-memory-partial-io",
        )
    ]


def _scan_guard_across_blocking(original: str, code: str, function: _Function) -> list[_RawCandidate]:
    guard_pattern = re.compile(
        r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*(?:guard|table|lock)[A-Za-z0-9_]*)\s*=.*"
        r"(?:\.lock\s*\(|borrow_[A-Za-z0-9_]*\s*\()"
    )
    blocking_pattern = re.compile(r"\.(?:wait|poll|recvmsg|sendmsg|accept|allocate)\s*\(")
    for guard in guard_pattern.finditer(code):
        name = guard.group(1)
        drop = re.search(rf"\bdrop\s*\(\s*{re.escape(name)}\s*\)", code[guard.end():])
        region_end = guard.end() + drop.start() if drop else len(code)
        blocking = blocking_pattern.search(code, guard.end(), region_end)
        if blocking is None:
            continue
        local_line = code.count("\n", 0, blocking.start()) + 1
        return [
            _RawCandidate(
                rule_id="LOCK-GUARD-ACROSS-BLOCKING",
                title="A guard may remain held across blocking work",
                property_id="NO-BLOCK-IN-ATOMIC-CONTEXT",
                line=function.start_line + local_line - 1,
                symbol=function.symbol,
                evidence=_line_at(original, local_line),
                rationale=f"Determine whether `{name}` is an atomic or borrow guard and whether the call can sleep, poll, or allocate.",
                confidence="low",
                preferred_track="fd-object-lifetime",
            )
        ]
    return []


def _scan_typed_copyout(original: str, code: str, function: _Function) -> list[_RawCandidate]:
    declarations = {
        match.group(1): match.group(2)
        for match in re.finditer(
            r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Z][A-Za-z0-9_:<>]*)",
            code,
        )
    }
    declarations.update(
        {
            match.group(1): match.group(2)
            for match in re.finditer(
                r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]*"
                r"read_val\s*::\s*<\s*([A-Z][A-Za-z0-9_:<>]*)\s*>",
                code,
            )
        }
    )
    for match in re.finditer(
        r"\bwrite_val\s*\([^,]+,\s*&\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        code,
    ):
        variable = match.group(1)
        rust_type = declarations.get(variable)
        if rust_type is None:
            continue
        local_line = code.count("\n", 0, match.start()) + 1
        return [
            _RawCandidate(
                rule_id="TYPED-STRUCT-COPYOUT",
                title="Typed structure is copied to userspace",
                property_id="NO-UNINITIALIZED-COPYOUT",
                line=function.start_line + local_line - 1,
                symbol=function.symbol,
                evidence=_line_at(original, local_line),
                rationale=f"Verify `{rust_type}` layout, initialized fields, padding, and reserved-byte zeroing on every path.",
                confidence="medium",
                preferred_track="abi-integer-layout",
            )
        ]
    return []


def _extract_functions(masked: str, *, handlers_only: bool) -> tuple[_Function, ...]:
    result: list[_Function] = []
    pattern = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(masked):
        open_paren = masked.find("(", match.start())
        close_paren = _matching_delimiter(masked, open_paren, "(", ")")
        if close_paren is None:
            continue
        open_brace = masked.find("{", close_paren)
        if open_brace < 0:
            continue
        close_brace = _matching_delimiter(masked, open_brace, "{", "}")
        if close_brace is None:
            continue
        parameter_text = masked[open_paren + 1:close_paren]
        parameter_names = tuple(
            name
            for name in re.findall(r"(?:^|,)\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", parameter_text)
        )
        start_line = masked.count("\n", 0, match.start()) + 1
        result.append(
            _Function(
                symbol=match.group(1),
                start=match.start(),
                end=close_brace + 1,
                start_line=start_line,
                parameter_names=parameter_names,
            )
        )
    if not handlers_only:
        return tuple(result)
    by_symbol = {function.symbol: function for function in result}
    reachable = {function.symbol for function in result if function.symbol.startswith("sys_")}
    pending = list(reachable)
    while pending:
        symbol = pending.pop()
        function = by_symbol[symbol]
        body = masked[function.start:function.end]
        for callee in re.findall(r"\b([a-z_][A-Za-z0-9_]*)\s*\(", body):
            if callee in by_symbol and callee not in reachable:
                reachable.add(callee)
                pending.append(callee)
    return tuple(function for function in result if function.symbol in reachable)


def _matching_delimiter(text: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def mask_non_code(text: str) -> str:
    result = list(text)
    index = 0
    block_depth = 0
    state = "code"
    raw_hashes = 0
    while index < len(text):
        if state == "line-comment":
            if text[index] == "\n":
                state = "code"
            else:
                result[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if text.startswith("/*", index):
                result[index:index + 2] = [" ", " "]
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                result[index:index + 2] = [" ", " "]
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                if text[index] != "\n":
                    result[index] = " "
                index += 1
            continue
        if state == "string":
            if text[index] == "\\":
                result[index] = " "
                if index + 1 < len(text):
                    if text[index + 1] != "\n":
                        result[index + 1] = " "
                    index += 2
                else:
                    index += 1
            else:
                char = text[index]
                if char != "\n":
                    result[index] = " "
                index += 1
                if char == '"':
                    state = "code"
            continue
        if state == "raw-string":
            terminator = '"' + ("#" * raw_hashes)
            if text.startswith(terminator, index):
                for offset in range(len(terminator)):
                    result[index + offset] = " "
                index += len(terminator)
                state = "code"
            else:
                if text[index] != "\n":
                    result[index] = " "
                index += 1
            continue

        if text.startswith("//", index):
            result[index:index + 2] = [" ", " "]
            state = "line-comment"
            index += 2
        elif text.startswith("/*", index):
            result[index:index + 2] = [" ", " "]
            state = "block-comment"
            block_depth = 1
            index += 2
        elif text[index] == '"':
            result[index] = " "
            state = "string"
            index += 1
        elif text[index] == "r":
            raw = re.match(r'r(#{0,16})"', text[index:])
            if raw:
                raw_hashes = len(raw.group(1))
                length = 2 + raw_hashes
                for offset in range(length):
                    result[index + offset] = " "
                index += length
                state = "raw-string"
            else:
                index += 1
        else:
            index += 1
    return "".join(result)


def _line_at(text: str, one_based: int) -> str:
    lines = text.splitlines()
    if 1 <= one_based <= len(lines):
        return lines[one_based - 1].strip()
    return ""


def _candidate_id(
    revision: str | None,
    rule_id: str,
    path: str,
    line: int,
    evidence: str,
) -> str:
    payload = "\0".join((revision or "working-tree", rule_id, path, str(line), evidence))
    return f"CAND-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16].upper()}"
