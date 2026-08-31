"""A small, dependency-free JSON5-tolerant loader.

OpenClaw's `openclaw.json` is JSON5: `//` and `/* */` comments, trailing commas,
unquoted keys, single-quoted strings, hex numbers, `+` signs, `.5` / `5.` floats,
`\\` line continuations. The wizard writes strict JSON, humans do not.

Strict JSON is tried first; this normaliser only runs on failure. It converts JSON5
syntax to JSON and hands the result to the stdlib parser. It is not a full JSON5
implementation (no `\\x` escapes beyond ASCII, no identifier keys outside ASCII), but
it must never *repair* broken input into something that parses: an unterminated
string or block comment raises ValueError, because a truncated config that "parses"
as a prefix is a false pass waiting to happen (AGENTS.md §4).
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

_UNQUOTED_KEY = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)(\s*:)")
_HEX = re.compile(r"(?<![\w.])([+-]?)0[xX]([0-9a-fA-F]+)(?![\w.])")
_PLUS = re.compile(r"(?<![\w.])\+(?=\d|\.\d|Infinity|NaN)")
_LEADING_DOT = re.compile(r"(?<![\w.])(-?)\.(\d)")
_TRAILING_DOT = re.compile(r"(?<![\w.])(-?\d+)\.(?![\d\w])")
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _strip_comments_and_quotes(src: str) -> str:
    """Drop comments, turn single-quoted strings into double-quoted ones, normalise escapes.
    Raises ValueError on an unterminated string or block comment."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in ("'", '"'):
            quote = c
            j = i + 1
            buf = ['"']
            while j < n and src[j] != quote:
                if src[j] == "\\" and j + 1 < n:
                    nxt = src[j + 1]
                    if nxt == "\n":  # line continuation
                        j += 2
                        continue
                    if nxt == "\r":  # CRLF line continuation
                        j += 3 if src[j + 2 : j + 3] == "\n" else 2
                        continue
                    if nxt == "'":  # \' is JSON5, not JSON
                        buf.append("'")
                        j += 2
                        continue
                    buf.append(src[j : j + 2])
                    j += 2
                    continue
                if src[j] == "\n":
                    raise ValueError(f"unterminated string at offset {i}")
                buf.append('\\"' if src[j] == '"' and quote == "'" else src[j])
                j += 1
            if j >= n:
                raise ValueError(f"unterminated string at offset {i}")
            buf.append('"')
            out.append(_HEX_ESCAPE.sub(lambda m: "\\u00" + m.group(1), "".join(buf)))
            i = j + 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j < 0:
                raise ValueError(f"unterminated block comment at offset {i}")
            i = j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _outside_strings(s: str, fn: Callable[[str], str]) -> str:
    """Apply `fn` to every run of text that is not inside a (double-quoted) string."""
    out: list[str] = []
    i, n = 0, len(s)
    start = 0
    while i < n:
        if s[i] == '"':
            out.append(fn(s[start:i]))
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            out.append(s[i : j + 1])
            i = j + 1
            start = i
            continue
        i += 1
    out.append(fn(s[start:]))
    return "".join(out)


def _quote_keys_chunk(s: str) -> str:
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        m = _UNQUOTED_KEY.match(s, i)
        if m and (i == 0 or s[i - 1] in " \t\r\n{,"):
            out.append(f'"{m.group(1)}"{m.group(2)}')
            i = m.end()
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _strip_trailing_commas_chunk(s: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", s)


def _numbers_chunk(s: str) -> str:
    s = _HEX.sub(lambda m: f"{m.group(1)}{int(m.group(2), 16)}", s)
    s = _PLUS.sub("", s)
    s = _LEADING_DOT.sub(r"\g<1>0.\2", s)
    s = _TRAILING_DOT.sub(r"\1.0", s)
    return s


def loads(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        pass
    norm = _strip_comments_and_quotes(text)
    norm = _outside_strings(norm, lambda c: _strip_trailing_commas_chunk(_numbers_chunk(_quote_keys_chunk(c))))
    return json.loads(norm)  # raises ValueError for the caller to note
