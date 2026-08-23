from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class RustParameter:
    name: str
    type_name: str


@dataclass(frozen=True)
class RustFunction:
    symbol: str
    start: int
    end: int
    start_line: int
    parameters: tuple[RustParameter, ...]
    is_public: bool

    @property
    def parameter_names(self) -> tuple[str, ...]:
        return tuple(parameter.name for parameter in self.parameters)


class RustSourceIndex:
    def __init__(self, text: str):
        self.text = text
        self.masked = mask_non_code(text)
        self.functions = _extract_functions(self.masked)
        self._by_symbol = {function.symbol: function for function in self.functions}

    def syscall_handlers(self) -> tuple[RustFunction, ...]:
        return tuple(
            function
            for function in self.functions
            if function.is_public and function.symbol.startswith("sys_")
        )

    def reachable_from(self, symbols: Iterable[str]) -> tuple[RustFunction, ...]:
        reachable: set[str] = set()
        pending = [symbol for symbol in symbols if symbol in self._by_symbol]
        while pending:
            symbol = pending.pop()
            if symbol in reachable:
                continue
            reachable.add(symbol)
            function = self._by_symbol[symbol]
            body = self.masked[function.start : function.end]
            for callee in re.findall(r"\b([a-z_][A-Za-z0-9_]*)\s*\(", body):
                if callee in self._by_symbol and callee not in reachable:
                    pending.append(callee)
        return tuple(
            function for function in self.functions if function.symbol in reachable
        )

    def code_for(self, functions: Iterable[RustFunction]) -> str:
        return "\n".join(self.masked[item.start : item.end] for item in functions)


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
                result[index : index + 2] = [" ", " "]
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                result[index : index + 2] = [" ", " "]
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
                _mask_range(result, text, index, index + len(terminator))
                index += len(terminator)
                state = "code"
            else:
                if text[index] != "\n":
                    result[index] = " "
                index += 1
            continue

        if text.startswith("//", index):
            result[index : index + 2] = [" ", " "]
            state = "line-comment"
            index += 2
        elif text.startswith("/*", index):
            result[index : index + 2] = [" ", " "]
            state = "block-comment"
            block_depth = 1
            index += 2
        elif text[index] == '"':
            result[index] = " "
            state = "string"
            index += 1
        elif text[index] == "'":
            end = _char_literal_end(text, index)
            if end is None:
                index += 1
            else:
                _mask_range(result, text, index, end)
                index = end
        elif text[index] == "r":
            raw = re.match(r'r(#{0,16})"', text[index:])
            if raw:
                raw_hashes = len(raw.group(1))
                length = 2 + raw_hashes
                _mask_range(result, text, index, index + length)
                index += length
                state = "raw-string"
            else:
                index += 1
        else:
            index += 1
    return "".join(result)


def _extract_functions(masked: str) -> tuple[RustFunction, ...]:
    functions: list[RustFunction] = []
    pattern = re.compile(
        r"\b(?:(?P<public>pub(?:\([^)]*\))?)\s+)?(?:async\s+)?fn\s+"
        r"(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s*\("
    )
    for match in pattern.finditer(masked):
        # The regex ends at the parameter-list opener. Searching from the
        # declaration start would mistake `pub(super)` for the parameters.
        open_paren = match.end() - 1
        close_paren = _matching_delimiter(masked, open_paren, "(", ")")
        if close_paren is None:
            continue
        open_brace = _body_open(masked, close_paren + 1)
        if open_brace is None:
            continue
        close_brace = _matching_delimiter(masked, open_brace, "{", "}")
        if close_brace is None:
            continue
        parameters = tuple(_split_parameters(masked[open_paren + 1 : close_paren]))
        functions.append(
            RustFunction(
                symbol=match.group("symbol"),
                start=match.start(),
                end=close_brace + 1,
                start_line=masked.count("\n", 0, match.start()) + 1,
                parameters=parameters,
                is_public=match.group("public") is not None,
            )
        )
    return tuple(functions)


def _body_open(text: str, start: int) -> int | None:
    for index in range(start, len(text)):
        if text[index] == ";":
            return None
        if text[index] == "{":
            return index
    return None


def _matching_delimiter(
    text: str, start: int, opening: str, closing: str
) -> int | None:
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


def _split_parameters(raw: str) -> list[RustParameter]:
    result: list[RustParameter] = []
    current: list[str] = []
    depth = 0
    for char in raw:
        if char in "(<[{":
            depth += 1
        elif char in ")>]}":
            depth = max(depth - 1, 0)
        if char == "," and depth == 0:
            _append_parameter(result, "".join(current))
            current = []
        else:
            current.append(char)
    _append_parameter(result, "".join(current))
    return result


def _append_parameter(result: list[RustParameter], raw: str) -> None:
    raw = raw.strip()
    if not raw or ":" not in raw:
        return
    name, type_name = raw.split(":", 1)
    result.append(
        RustParameter(
            name=name.strip().removeprefix("mut "),
            type_name=" ".join(type_name.split()),
        )
    )


def _char_literal_end(text: str, start: int) -> int | None:
    index = start + 1
    if index >= len(text) or text[index] in {"'", "\n"}:
        return None
    if text[index] != "\\":
        index += 1
    elif index + 1 >= len(text):
        return None
    elif text[index + 1] == "x":
        index += 4
    elif text[index + 1] == "u" and text.startswith("\\u{", index):
        closing = text.find("}", index + 3, index + 10)
        if closing < 0:
            return None
        index = closing + 1
    else:
        index += 2
    return index + 1 if index < len(text) and text[index] == "'" else None


def _mask_range(result: list[str], text: str, start: int, end: int) -> None:
    for index in range(start, min(end, len(text))):
        if text[index] != "\n":
            result[index] = " "
