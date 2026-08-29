"""A small, dependency-free JSON5-tolerant loader.

OpenClaw's `openclaw.json` is JSON5: `//` and `/* */` comments, trailing commas,
unquoted keys, single-quoted strings. The wizard writes strict JSON, humans do not.
Strict JSON is tried first; this normaliser only runs on failure. It converts
JSON5 syntax to JSON and hands the result to the stdlib parser — it is not a
full JSON5 implementation (no hex numbers, no multi-line string continuations).
"""

from __future__ import annotations

import json
import re
from typing import Any

_UNQUOTED_KEY = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)(\s*:)")


def _strip_comments_and_quotes(src: str) -> str:
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
                    if nxt == "'" and quote == "'":  # \' is not a JSON escape
                        buf.append("'")
                        j += 2
                        continue
                    buf.append(src[j : j + 2])
                    j += 2
                    continue
                buf.append('\\"' if src[j] == '"' and quote == "'" else src[j])
                j += 1
            buf.append('"')
            out.append("".join(buf))
            i = j + 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _quote_keys(s: str) -> str:
    """Quote bare identifiers that sit before a colon, outside strings."""
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            out.append(s[i : j + 1])
            i = j + 1
            continue
        m = _UNQUOTED_KEY.match(s, i)
        if m and (i == 0 or s[i - 1] in " \t\r\n{,"):
            out.append(f'"{m.group(1)}"{m.group(2)}')
            i = m.end()
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _strip_trailing_commas(s: str) -> str:
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            out.append(s[i : j + 1])
            i = j + 1
            continue
        if c == ",":
            j = i + 1
            while j < n and s[j] in " \t\r\n":
                j += 1
            if j < n and s[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        pass
    norm = _strip_trailing_commas(_quote_keys(_strip_comments_and_quotes(text)))
    return json.loads(norm)  # raises ValueError for the caller to note
