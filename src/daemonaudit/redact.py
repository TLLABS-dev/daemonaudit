"""Secret detection and redaction.

Two jobs with different risk tolerances (Codex C2 #4):
1. find_hits() / find_secrets(): classify credential-shaped strings for *findings*.
   Provider-aware, conservative about false positives.
2. scrub(): last line of defence over any text the tool emits. Broader than detection —
   it also blanks anything that merely looks like a high-entropy blob, and the *encoded
   carrier* of anything found through a decoding stream.

Detection runs over several bounded "streams" derived from the input (C2 #1):
  direct · shell (line-continuation joined + backslash-unescaped) · nfkc (Unicode
  compatibility normalisation) · yaml-fold (folded block scalars joined) · nulls
  (UTF-16-style null interleaving removed) · base64 / hex (decoded tokens).
Only *provider/structural* kinds are accepted from derived streams; the context-only
generic-credential kind must match the text as written. Every hit records `via`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass

from daemonaudit.model import RedactedSecret

MAX_SCAN_BYTES = 64 * 1024 * 1024  # a file bigger than this is reported as not inspected
MAX_NORMALIZE_CHARS = 16 * 1024 * 1024  # derived streams are skipped above this
MAX_BLOB_CHARS = 8 * 1024  # a single base64/hex token bigger than this is not decoded


@dataclass(frozen=True)
class Pattern:
    kind: str
    regex: re.Pattern[str]
    group: int = 0  # which group holds the secret value
    structural: bool = True  # fixed provider shape → no randomness test needed


@dataclass(frozen=True)
class Hit:
    kind: str
    raw: str
    via: str = "direct"  # which stream found it
    carrier: str | None = None  # literal substring of the original text that carries it


# Ordered most-specific first. Overlaps are de-duplicated by span within a stream.
# Fixtures in tests/ use these shapes with obviously fake bodies.
PATTERNS: list[Pattern] = [
    Pattern("anthropic-api-key", re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}"), structural=False),
    Pattern("openrouter-api-key", re.compile(r"(?<![A-Za-z0-9])sk-or-v1-[a-f0-9]{40,}")),
    Pattern("openai-api-key", re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}"), structural=False),
    Pattern("github-token", re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}"), structural=False),
    Pattern("github-fine-grained-pat", re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,}"), structural=False),
    Pattern("slack-app-token", re.compile(r"(?<![A-Za-z0-9])xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{40,}")),
    Pattern("slack-token", re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9\-]{10,}"), structural=False),
    Pattern("telegram-bot-token", re.compile(r"(?<![A-Za-z0-9])[0-9]{8,10}:[A-Za-z0-9_\-]{35}(?![A-Za-z0-9_\-])")),
    Pattern("discord-webhook-url", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,}")),
    Pattern("discord-bot-token", re.compile(r"(?<![A-Za-z0-9])[MN][A-Za-z0-9_\-]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}"), structural=False),
    Pattern("aws-access-key-id", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    Pattern("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    Pattern("google-oauth-client-secret", re.compile(r"(?<![A-Za-z0-9])GOCSPX-[A-Za-z0-9_\-]{20,}")),
    Pattern(
        "google-oauth-client-secret",
        re.compile(r"(?i)\bGOOGLE[A-Z0-9_]*CLIENT_?SECRET\s*[=:]\s*[\"']?(?P<val>[A-Za-z0-9_.\-]{20,})"),
        group=1,
    ),
    Pattern(
        "azure-openai-api-key",
        re.compile(r"(?i)\bAZURE[A-Z0-9_]*(?:API_?KEY|_KEY|SECRET)\s*[=:]\s*[\"']?(?P<val>[A-Za-z0-9]{32,})"),
        group=1,
    ),
    Pattern("jwt", re.compile(r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    Pattern("url-embedded-credential", re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:(?P<val>[^@\s/]{8,})@"), group=1),
    Pattern("bearer-token", re.compile(r"(?i)\bbearer\s+(?P<val>[A-Za-z0-9_\-.=]{20,})"), group=1, structural=False),
    Pattern("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    Pattern(
        "generic-credential",
        re.compile(
            r"(?i)\b(?P<name>[A-Z0-9_]*(?:API_KEY|APIKEY|SECRET|TOKEN|PASSWORD|PASSWD|CLIENT_SECRET))\b"
            r"\s*[=:]\s*[\"']?(?P<val>[^\s\"',;]{12,})"
        ),
        group=2,
        structural=False,
    ),
]
GENERIC = "generic-credential"

# Variable names that end in TOKEN/KEY/SECRET but are not credentials (C1 #6).
_NON_SECRET_NAME = re.compile(
    r"(?i)(SESSION_KEY|SESSION_ID|CACHE_KEY|CSRF|CHECKSUM|PUBLIC_KEY|KEY_NAME|KEY_PATH|KEY_FILE|_FILE$|_PATH$|_URL$|_ID$|MAX_TOKENS?|NUM_TOKENS?|TOKEN_LIMIT|TOKENS?_PER)"
)

# Values that look like credentials but are references/placeholders, not secrets.
_PLACEHOLDER_PREFIXES = ("$", "{", "<", "op://", "bws://", "cmd://", "secret-tool", "keyring:", "env:", "file:")
_PLACEHOLDER_WORDS = {"changeme", "redacted", "masked", "none", "null", "true", "false", "missing", "unset"}
_PLACEHOLDER_SUBSTRINGS = ("your", "here", "example", "placeholder", "dummy", "sample", "replace", "insert", "todo", "xxxx", "redact", "missing")


def _is_placeholder(value: str) -> bool:
    v = value.strip().rstrip(":")
    low = v.lower()
    if low in _PLACEHOLDER_WORDS or v.startswith(_PLACEHOLDER_PREFIXES):
        return True
    if re.fullmatch(r"[xX*.\-_]+", v):
        return True
    return any(w in low for w in _PLACEHOLDER_SUBSTRINGS)


_PREFIX = re.compile(r"^(sk-ant-|sk-or-v1-|sk-proj-|sk-svcacct-|sk-|gh[pousr]_|github_pat_|xox[abprs]-)")


def _looks_random_prefixed(value: str) -> bool:
    """For bare provider prefixes (`sk-`, `ghp_`…) that English text can mimic:
    real keys have digits and mixed case; 'sk-consensus-diagnosis' does not."""
    body = _PREFIX.sub("", value)
    digits = sum(c.isdigit() for c in body)
    upper = sum(c.isupper() for c in body)
    return digits >= 2 and (upper >= 1 or digits >= 4)


def _looks_random_generic(value: str) -> bool:
    """For values already anchored by an assignment context (`FOO_TOKEN=`): the name
    carries the evidence, so accept lowercase opaque tokens too (C2 #2). Reject
    short, low-diversity or repetitive values."""
    if len(value) < 12:
        return False
    digits = sum(c.isdigit() for c in value)
    distinct = len(set(value))
    if re.search(r"(.)\1{3,}", value):
        return False
    if len(value) >= 20:
        return digits >= 2 and distinct >= 10
    return digits >= 2 and distinct >= 8 and any(c.isupper() for c in value)


def fingerprint(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:10]


def display(raw: str) -> str:
    """'sk-ant-…4f2a' — enough to recognise, useless to use."""
    if len(raw) >= 14:
        return f"{raw[:6]}…{raw[-4:]}"
    return f"{raw[:2]}…"


def redact(kind: str, raw: str) -> RedactedSecret:
    return RedactedSecret(kind=kind, display=display(raw), fingerprint=fingerprint(raw))


# --- core matcher over one stream ---------------------------------------------------

def _match_stream(text: str, via: str, allow_generic: bool) -> list[Hit]:
    taken: list[tuple[int, int]] = []
    out: list[Hit] = []
    for pat in PATTERNS:
        if pat.kind == GENERIC and not allow_generic:
            continue
        for m in text_finditer(pat, text):
            span = m.span(pat.group)
            if any(s <= span[0] < e or s < span[1] <= e for s, e in taken):
                continue
            raw = m.group(pat.group)
            if pat.kind == GENERIC:
                raw = raw.rstrip(":")
                if _NON_SECRET_NAME.search(m.group("name")) or _is_placeholder(raw) or not _looks_random_generic(raw):
                    continue
            elif not pat.structural and not _looks_random_prefixed(raw):
                continue
            taken.append(span)
            out.append(Hit(pat.kind, raw, via, carrier=raw))
    return out


def text_finditer(pat: Pattern, text: str):
    return pat.regex.finditer(text)


# --- derived streams ------------------------------------------------------------------

_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){20,}(?![0-9A-Fa-f])")
_YAML_FOLD = re.compile(r"^(?P<ind>[ \t]*)(?P<key>[^\s#][^:\n]*):[ \t]*[>|]-?[ \t]*\n(?P<body>(?:(?P=ind)[ \t]+\S.*\n?)+)", re.M)


def _printable(s: str) -> bool:
    return bool(s) and all(0x20 <= ord(c) < 0x7F for c in s)


def _decoded_hits(text: str, token_re: re.Pattern[str], decode, via: str) -> list[Hit]:
    out: list[Hit] = []
    for m in token_re.finditer(text):
        tok = m.group(0)
        if len(tok) > MAX_BLOB_CHARS:
            continue
        try:
            dec = decode(tok)
        except (binascii.Error, ValueError):
            continue
        try:
            s = dec.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not _printable(s):
            continue
        for h in _match_stream(s, via, allow_generic=False):
            out.append(Hit(h.kind, h.raw, via, carrier=tok))
    return out


def _b64decode(tok: str) -> bytes:
    pad = "=" * (-len(tok) % 4)
    return base64.b64decode(tok + pad, validate=True)


def _shell_stream(text: str) -> str | None:
    if "\\" not in text:
        return None
    joined = re.sub(r"\\\r?\n[ \t]*", "", text)  # line continuation
    return re.sub(r"\\(.)", r"\1", joined)  # backslash escapes


def _nfkc_stream(text: str) -> str | None:
    if text.isascii():
        return None
    norm = unicodedata.normalize("NFKC", text)
    return norm if norm != text else None


def _yaml_fold_stream(text: str) -> str | None:
    if ": >" not in text and ": |" not in text and ":>" not in text:
        return None

    def join(m: re.Match) -> str:
        # Folded YAML turns the newlines into spaces; a credential split that way was
        # never a valid token, so for *evasion* purposes we join tightly and also
        # keep the spaced form on a second line.
        lines = [ln.strip() for ln in m.group("body").splitlines() if ln.strip()]
        return f"{m.group('ind')}{m.group('key')}: {''.join(lines)}\n{m.group('ind')}{m.group('key')}: {' '.join(lines)}\n"

    folded = _YAML_FOLD.sub(join, text)
    return folded if folded != text else None


def _null_stream(data: bytes) -> bytes | None:
    n = data.count(b"\x00")
    if n == 0 or n * 20 < len(data):  # only when nulls are dense (UTF-16 / sqlite pages)
        return None
    collapsed = re.sub(rb"\x00{2,}", b" ", data)  # runs of nulls separate strings
    return collapsed.replace(b"\x00", b"")  # single nulls interleave UTF-16 text


def find_hits(data: str | bytes) -> list[Hit]:
    """All credential-shaped matches across every stream, de-duplicated by (kind, raw)."""
    if isinstance(data, bytes):
        text = data.decode("latin-1")
        null_stream = _null_stream(data)
    else:
        text = data
        null_stream = None

    hits: list[Hit] = list(_match_stream(text, "direct", allow_generic=True))
    if len(text) <= MAX_NORMALIZE_CHARS:
        for via, s in (("shell", _shell_stream(text)), ("nfkc", _nfkc_stream(text)), ("yaml-fold", _yaml_fold_stream(text))):
            if s is not None:
                hits += _match_stream(s, via, allow_generic=False)
        if null_stream is not None:
            hits += _match_stream(null_stream.decode("latin-1"), "nulls", allow_generic=False)
        hits += _decoded_hits(text, _B64_TOKEN, _b64decode, "base64")
        hits += _decoded_hits(text, _HEX_TOKEN, bytes.fromhex, "hex")

    seen: set[tuple[str, str]] = set()
    out: list[Hit] = []
    for h in hits:
        key = (h.kind, h.raw)
        if key in seen:
            continue
        # A derived-stream hit is redundant if a direct hit already has the same raw value.
        if h.via != "direct" and any(o.raw == h.raw for o in out):
            continue
        seen.add(key)
        out.append(h)
    return out


def find_secrets(data: str | bytes) -> list[tuple[str, str]]:
    """Compatibility view: [(kind, raw_value)]. Callers must redact before storing."""
    return [(h.kind, h.raw) for h in find_hits(data)]


# --- output scrubbing (broader than detection) -----------------------------------------

# Anything that looks like an opaque blob: 40+ base64/url-safe chars with both digits and
# letters. No '/' in the class so file paths with digits are left alone; base64 carriers
# containing '/' are still scrubbed via Hit.carrier above.
_BLOB = re.compile(r"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+=]{40,}(?![A-Za-z0-9_\-+/=])")


def scrub(text: str) -> str:
    """Replace every credential-shaped string — and its encoded carrier — with a
    redacted display form. Applied to all report output as a safety net."""
    for h in find_hits(text):
        for literal in (h.carrier, h.raw):
            if literal and len(literal) >= 8 and literal in text:
                text = text.replace(literal, display(literal))
    for m in list(_BLOB.finditer(text))[::-1]:
        tok = m.group(0)
        if sum(c.isdigit() for c in tok) >= 4 and sum(c.isalpha() for c in tok) >= 4:
            text = text[: m.start()] + display(tok) + text[m.end():]
    return text
