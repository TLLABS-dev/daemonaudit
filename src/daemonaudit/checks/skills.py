"""SKILL-001: static heuristics over installed skills and agent context files.

Deterministic and dependency-free (regex + stdlib `ast` + PyYAML, which we already
have). One finding per category, listing the skills involved — 82 vendor skills must
not produce 82 panels.

Normalisation before matching (Codex C3):
  scripts: shell line-continuations joined, simple `VAR=value` substituted, quote
           splitting (`"$HOME/.""env"`) and `"a"+"b"` concatenation collapsed
  docs:    NFKC, homoglyphs → Latin, default-ignorable chars removed, markdown link
           text kept / destination dropped, bounded base64 runs decoded in place
  python:  a small taint pass — network-call results reaching exec/eval/os.system/subprocess
"""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import posixpath
import re
import unicodedata
from collections import defaultdict
from pathlib import Path

import yaml

from daemonaudit.checks._walk import rel, walk_files
from daemonaudit.discover.hermes_config import SECRET_NAME
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import NotSupported, Platform, q
from daemonaudit.registry import check

SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".ts", ".rb", ".pl", ".ps1"}
BINARY_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".zip", ".gz", ".tar", ".whl", ".pyc",
              ".woff", ".woff2", ".ttf", ".mp3", ".mp4", ".wav", ".bin", ".so", ".dylib", ".dll", ".exe", ".db", ".sqlite"}
DOC_NAMES = {"SKILL.md", "SOUL.md", "AGENTS.md", "CLAUDE.md", ".cursorrules", "README.md"}
CONTEXT_FILES = ["SOUL.md", "AGENTS.md", ".cursorrules"]
VAULT_BASENAMES = {".env", "auth.json", ".anthropic_oauth.json", "mcp-tokens", "pairing"}

# Credentials Hermes itself holds: provider + platform + its own. Everything else is "scoped".
MASTER_ENV = re.compile(
    r"^(ANTHROPIC|OPENAI|OPENROUTER|GITHUB|GH|COPILOT|AWS|AZURE|GOOGLE|GCP|GEMINI|SLACK|TELEGRAM|DISCORD|WHATSAPP|TEAMS|HERMES|API_SERVER|GATEWAY|NOUS)_[A-Z0-9_]*$"
)

# --- shell / script vocab -------------------------------------------------------------
DOWNLOADER = r"(curl|wget|fetch|aria2c)"
SHELL = r"(sudo\s+(-E\s+)?)?(ba|z|da|k)?sh\b"
PIPE_TO_SHELL = re.compile(
    rf"\b{DOWNLOADER}\b[^\n|]*\|\s*{SHELL}"  # curl … | sh
    rf"|\b{SHELL}\s+-c\s+[\"']?\$\({DOWNLOADER}"  # sh -c "$(curl …)"
    rf"|\b(eval|source|\.)\s+[\"']?\$\({DOWNLOADER}"  # eval "$(curl …)"
    rf"|\b{SHELL}\s+<\({DOWNLOADER}"  # bash <(curl …)
    rf"|\b(eval|source|\.)\s+<\({DOWNLOADER}",
    re.I,
)
SUBST_ASSIGN = re.compile(rf"^\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)=[\"']?\$\({DOWNLOADER}\b|^\s*(?P<var2>[A-Za-z_][A-Za-z0-9_]*)=[\"']?`{DOWNLOADER}\b", re.I)
SIMPLE_ASSIGN = re.compile(r"^\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)=(?P<val>[A-Za-z0-9_./-]+)\s*$")
NETWORK = re.compile(
    r"\b(curl|wget|fetch|aria2c|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|dig|nslookup|host|openssl\s+s_client"
    r"|requests\.(get|post|put|patch|delete|request|Session)|urllib|urlopen|httpx|aiohttp|http\.client|websocket"
    r"|fetch\(|socket\.|net/http|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient)\b|/dev/(tcp|udp)/",
    re.I,
)
MASTER_SECRET_READ = re.compile(
    r"(\.env\b(?![A-Za-z0-9_.])|auth\.json|\.anthropic_oauth|mcp-tokens|\.ssh/id_[a-z0-9]+\b(?!\.pub)|\.aws/credentials"
    r"|\b(printenv|env)\s*(\||$|[A-Z_]*(API_?KEY|TOKEN|SECRET)\b)|\benv\s*\|\s*grep|\bfind\b[^\n]{0,80}\.env\b"
    r"|(os\.environ|process\.env|getenv|ENV)[\s\[\(.]*(get\()?[\s\"']*(?P<m1>[A-Z0-9_]+)"
    r"|\$\{?(?P<m2>[A-Z][A-Z0-9_]*)\b)"
)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
DECODE = re.compile(r"base64\s+(-d|--decode)|b64decode|atob\(|FromBase64String", re.I)

# --- doc vocab --------------------------------------------------------------------------
INVISIBLE = re.compile("[­​-‏⁠-⁤﻿‪-‮⁦-⁩᠎]")
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|guidance)"
    r"|do not (tell|inform|mention|reveal|alert)[^\n.]{0,40}\buser\b"
    r"|with-?out (telling|informing|notifying) the user"
    r"|(send|post|upload|forward|transmit)\b[^\n.]{0,40}\b(api[_ ]?keys?|tokens?|passwords?|credentials?|\.env|auth\.json)\b[^\n.]{0,40}\b(to|at|there|away)\b"
    r"|(cat|read|print|echo|curl)[^\n]{0,30}(~|\$HOME|/root)[^\n]{0,20}(\.env\b|auth\.json|\.ssh/id_[a-z0-9]+\b(?!\.pub)|\.aws/credentials)",
    re.I,
)
# A line that *talks about* attack phrases rather than issuing them.
DEFENSIVE = re.compile(
    r"\b(whether|determine|detect|identify|flag|look for|watch for|report|reject|such as|e\.g\.|example|rubric|audit|review|check for|scan|phrases? like|attempts? to)\b",
    re.I,
)
HIDDEN_COMMENT = re.compile(r"<!--(?P<body>(?:(?!-->).){0,400})-->", re.S)
COMMENT_IMPERATIVE = re.compile(
    r"ignore (all |any )?(previous|prior|above)|you (must|should|are|will)|\b(assistant|agent|model|system prompt)\b"
    r"|\b(curl|wget|bash|sh)\s|\$\(|\b(api[_ ]?key|token|password|secret)\b", re.I)
MD_LINK = re.compile(r"\[([^\]]{1,200})\]\((?:[^)\s]{1,500})\)")
B64_RUN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])")
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ɩ": "i",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y",
    "ο": "o", "α": "a", "ε": "e", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "χ": "x", "υ": "u",
})

# --- python taint vocab -----------------------------------------------------------------
PY_NET_CALLS = {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.request", "urlopen",
                "urllib.request.urlopen", "httpx.get", "httpx.post", "httpx.request", "http.client.HTTPConnection",
                "http.client.HTTPSConnection", "aiohttp.request", "urllib.urlopen"}
PY_EXEC_SINKS = {"exec", "eval", "compile", "os.system", "os.popen", "subprocess.run", "subprocess.call",
                 "subprocess.Popen", "subprocess.check_output", "subprocess.check_call", "os.execv", "os.execvp"}


def _read(plat: Platform, p: Path) -> str | None:
    """Text content, or None for unreadable/binary files (binary is skipped, not a note)."""
    if p.suffix.lower() in BINARY_EXT:
        return None
    try:
        raw = plat.read_nofollow(p, 2 * 1024 * 1024)
    except NotSupported:
        try:
            raw = p.read_bytes()
        except OSError:
            return None
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", "replace")


def _skill_of(skills_root: Path, p: Path) -> str:
    try:
        parts = p.relative_to(skills_root).parts
        return "/".join(parts[:2]) if len(parts) >= 2 else parts[0]
    except ValueError:
        return p.name


def _is_bundled(home: Path, lay, skills_root: Path, p: Path) -> bool:
    if not lay.bundled_skills_dir:
        return False
    try:
        vendor = home / lay.bundled_skills_dir / p.relative_to(skills_root)
    except ValueError:
        return False
    try:
        if vendor.is_symlink() or not vendor.is_file():
            return False
        return hashlib.sha256(vendor.read_bytes()).digest() == hashlib.sha256(p.read_bytes()).digest()
    except OSError:
        return False


NO_DOWNGRADE = {"invisible", "wants_vault", "pipe_script"}
SKILL_TAGS = {
    "pipe_script": ["skill:remote-exec"], "pipe_doc": ["skill:remote-exec"],
    "injection": ["skill:injection"], "hidden_comment": ["skill:injection"], "invisible": ["skill:injection"],
    "wants_keys": ["skill:wants-secrets"], "wants_vault": ["skill:wants-secrets"],
    "net_and_secrets": ["skill:exfil-shape"], "encoded_payload": ["skill:remote-exec"],
}
DOWNGRADE = {Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW, Severity.LOW: Severity.INFO}


# --- normalisers --------------------------------------------------------------------------

def normalize_script(text: str) -> str:
    """Join continuations, collapse quote-splitting and string concatenation, substitute
    simple shell variables. Line count is preserved where possible (joined lines keep
    their first line number)."""
    text = re.sub(r"\\\r?\n[ \t]*", " ", text)
    text = re.sub(r"[\"']\s*[\"']", "", text)  # "$HOME/.""env" → $HOME/.env
    text = re.sub(r"[\"']\s*\+\s*[\"']", "", text)  # "ur"+"llib" → urllib
    text = re.sub(r"(?<=[A-Za-z0-9_./])[\"'](?=[A-Za-z0-9_./])", "", text)  # ur"llib"
    simple: dict[str, str] = {}
    for line in text.splitlines():
        m = SIMPLE_ASSIGN.match(line)
        if m:
            simple[m.group("var")] = m.group("val")
    if simple:
        def sub(m: re.Match) -> str:
            name = m.group(1) or m.group(2)
            return simple.get(name, m.group(0))
        text = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", sub, text)
    return text


def _b64_inline(m: re.Match) -> str:
    tok = m.group(0)
    try:
        dec = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return tok
    if dec and all(0x20 <= ord(c) < 0x7F for c in dec):
        return f"{tok} [decoded: {dec}]"
    return tok


def normalize_doc(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(HOMOGLYPHS)
    text = INVISIBLE.sub("", text)
    text = MD_LINK.sub(r"\1", text)
    return B64_RUN.sub(_b64_inline, text)


def _lines(text: str, rx: re.Pattern[str]) -> list[int]:
    return [i for i, line in enumerate(text.splitlines(), 1) if rx.search(line)]


def _injection_lines(text: str) -> list[int]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = INJECTION.search(line)
        if not m:
            continue
        if DEFENSIVE.search(line):
            continue
        before = line[: m.start()]
        if before.count("`") % 2 == 1 or before.count('"') % 2 == 1:  # phrase is quoted
            continue
        out.append(i)
    return out


def _shell_remote_exec_lines(text: str) -> list[int]:
    """PIPE_TO_SHELL plus download-to-variable-to-eval."""
    hits = _lines(text, PIPE_TO_SHELL)
    tainted: set[str] = set()
    for i, line in enumerate(text.splitlines(), 1):
        m = SUBST_ASSIGN.match(line)
        if m:
            tainted.add(m.group("var") or m.group("var2"))
            continue
        if tainted and re.search(r"\b(eval|source|\.)\s|\bsh\s+-c\s|\bbash\s+-c\s", line):
            if any(re.search(rf"\$\{{?{re.escape(v)}\b", line) for v in tainted):
                hits.append(i)
    return sorted(set(hits))


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _python_remote_exec_lines(text: str) -> list[int]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return _lines(text, re.compile(r"\b(exec|eval|os\.system|subprocess\.\w+)\(.*\b(requests\.|urlopen|httpx\.)"))
    tainted: set[str] = set()

    def has_net(node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                name = _dotted(n.func)
                if name in PY_NET_CALLS or name.split(".")[-1] in {"urlopen"} or name.startswith(("requests.", "httpx.")):
                    return True
            if isinstance(n, ast.Name) and n.id in tainted:
                return True
        return False

    hits: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None and has_net(node.value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        tainted.add(n.id)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func) in PY_EXEC_SINKS:
            if any(has_net(a) for a in node.args) or any(has_net(k.value) for k in node.keywords):
                hits.append(node.lineno)
    return sorted(set(hits))


def _master_secret_read(line: str) -> bool:
    m = MASTER_SECRET_READ.search(line)
    if not m:
        return False
    name = m.group("m1") or m.group("m2")
    if name is None:
        return True  # vault file / env dump / ssh / aws
    return bool(MASTER_ENV.match(name) and SECRET_NAME.search(name))


def _frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    head = text[3:].split("\n---", 1)[0][:65536]
    try:
        fm = yaml.safe_load(head)
    except yaml.YAMLError:
        return {}
    return fm if isinstance(fm, dict) else {}


def _env_names(value) -> list[str]:
    if isinstance(value, dict):
        value = [value]
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        if isinstance(item, str):
            out.append(item.strip())
        elif isinstance(item, dict):
            n = item.get("name") or item.get("env_var")
            if isinstance(n, str):
                out.append(n.strip())
    return [n for n in out if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n)]


def _cred_files(value) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def _is_vault_path(path: str) -> bool:
    norm = posixpath.normpath(path.replace("\\", "/"))
    if norm.startswith("/") or norm.startswith("..") or path.startswith("~"):
        return True  # absolute / traversal / home-relative: never a scoped token file
    return posixpath.basename(norm) in VAULT_BASENAMES or any(part in VAULT_BASENAMES for part in norm.split("/"))


def _declarations(fm: dict) -> list[tuple[str, list[str], list[str]]]:
    """[(location, env_names, cred_files)] for top level and metadata subtrees."""
    out = [("frontmatter", _env_names(fm.get("required_environment_variables")), _cred_files(fm.get("required_credential_files")))]
    meta = fm.get("metadata")
    if isinstance(meta, dict):
        for loc, sub in (("metadata", meta), ("metadata.hermes", meta.get("hermes") if isinstance(meta.get("hermes"), dict) else {})):
            if sub:
                out.append((loc, _env_names(sub.get("required_environment_variables")), _cred_files(sub.get("required_credential_files"))))
    return out


@check("SKILL-001", "Risky patterns in installed skills and context files", Position.SUPPLY_CHAIN)
def skills(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    home, lay = target.home, target.layout
    skills_root = home / "skills"
    cats: dict[str, list[str]] = defaultdict(list)
    n_skills = n_scripts = 0
    net_skills: set[str] = set()
    scoped: list[str] = []

    files: list[Path] = list(walk_files(skills_root, lay.exclude_dirs, max_depth=6))
    files += [home / c for c in CONTEXT_FILES if (home / c).is_file() and not (home / c).is_symlink()]
    if not files:
        out.note("no skills directory or context files found")
        return out

    for p in files:
        raw = _read(plat, p)
        if raw is None:
            if p.suffix.lower() not in BINARY_EXT and not p.is_file():
                out.note(f"unreadable: {rel(home, p)}")
            continue
        in_skills = p.is_relative_to(skills_root)
        skill = _skill_of(skills_root, p) if in_skills else rel(home, p)
        r = rel(home, p) + (" (bundled)" if in_skills and _is_bundled(home, lay, skills_root, p) else "")
        is_doc = p.name in DOC_NAMES or p.suffix.lower() in (".md", ".txt")
        is_script = p.suffix.lower() in SCRIPT_EXT
        n_skills += p.name == "SKILL.md"
        n_scripts += is_script

        if INVISIBLE.search(raw):
            cats["invisible"].append(f"{skill}: {r} lines {_lines(raw, INVISIBLE)[:5]}")

        if is_doc:
            doc = normalize_doc(raw)
            for ln in _lines(doc, PIPE_TO_SHELL):
                cats["pipe_doc"].append(f"{skill}: {r}:{ln}")
            for ln in _injection_lines(doc):
                cats["injection"].append(f"{skill}: {r}:{ln}")
            for m in HIDDEN_COMMENT.finditer(doc):
                if COMMENT_IMPERATIVE.search(m.group("body")):
                    cats["hidden_comment"].append(f"{skill}: {r}:{doc.count(chr(10), 0, m.start()) + 1}")

        if p.name == "SKILL.md":
            for loc, envs, creds in _declarations(_frontmatter(raw)):
                tag = "" if loc == "frontmatter" else f" [{loc}: not read by Hermes at runtime]"
                for n in envs:
                    if MASTER_ENV.match(n) and SECRET_NAME.search(n):
                        cats["wants_keys"].append(f"{skill}: {n}{tag}")
                    elif SECRET_NAME.search(n):
                        scoped.append(f"{skill}: {n}")
                for c in creds:
                    if _is_vault_path(c):
                        cats["wants_vault"].append(f"{skill}: {c}{tag}")

        if is_script:
            script = normalize_script(raw)
            exec_lines = _shell_remote_exec_lines(script)
            if p.suffix.lower() == ".py":
                exec_lines = sorted(set(exec_lines) | set(_python_remote_exec_lines(raw)))
            for ln in exec_lines:
                cats["pipe_script"].append(f"{skill}: {r}:{ln}")
            has_net = bool(NETWORK.search(script))
            if has_net:
                net_skills.add(skill)
                if any(_master_secret_read(line) for line in script.splitlines()):
                    cats["net_and_secrets"].append(f"{skill}: {r}")
            if BASE64_BLOB.search(script) and DECODE.search(script):
                cats["encoded_payload"].append(f"{skill}: {r}")

    spec = {
        "invisible": ("Invisible Unicode (zero-width / bidi / soft hyphen) inside skill or context text", Severity.HIGH,
                      "Zero-width, soft-hyphen and bidirectional-override characters hide instructions from a human reading the file while the model still sees them. There is no benign reason for them in a SKILL.md.",
                      "Open each file in an editor that shows invisible characters, read what is hidden, and remove the skill if it is not yours."),
        "pipe_script": ("Skill script pipes a remote download into a shell or eval", Severity.HIGH,
                        "Downloading and executing in one motion — `curl | sh`, `eval \"$(curl …)\"`, a variable holding the download, or a Python fetch handed to subprocess — runs whatever the server returns, with no review and no pin.",
                        "Download to a file, verify a checksum or signature, then run. Or vendor the installer into the skill."),
        "pipe_doc": ("Skill instructions tell the agent to pipe a remote installer into a shell", Severity.MEDIUM,
                     "The agent follows SKILL.md literally. `curl … | bash` in the instructions means the first time the skill is used, the agent runs unreviewed remote code.",
                     "Prefer package managers or pinned releases in skill instructions; treat these skills as 'runs remote code' when deciding to keep them."),
        "injection": ("Prompt-injection phrasing in skill or context text", Severity.MEDIUM,
                      "Phrases like 'ignore previous instructions', 'without telling the user' or 'send the API key to' have no place in a tool description — including when hidden with look-alike letters, soft hyphens, link text or base64. Lines that merely discuss such phrases (rubrics, reviews) are not counted.",
                      "Read the flagged lines in context. Remove the skill if the intent is what it looks like."),
        "hidden_comment": ("Hidden HTML comments containing instructions to the agent", Severity.MEDIUM,
                           "Markdown renderers hide `<!-- … -->`; the model does not.",
                           "Inspect the comment bodies; remove anything that reads as an instruction to the agent."),
        "wants_keys": ("Skill frontmatter requests provider credentials as environment variables", Severity.MEDIUM,
                       "Hermes auto-passes `required_environment_variables` into the skill's shell. A skill asking for ANTHROPIC_API_KEY or GITHUB_TOKEN gets your master key, not a scoped one. Scoped keys (a weather API key) are listed under Inventory instead.",
                       "Decide per skill whether it truly needs that key; use a scoped/secondary token where the provider supports it."),
        "wants_vault": ("Skill requests the vault itself as a credential file", Severity.HIGH,
                        "`required_credential_files` mounts files into the tool environment. Asking for .env / auth.json, an absolute path, or `../` traversal is asking for everything. Current Hermes refuses these at mount time — the request is still the signature of a hostile skill.",
                        "Remove the skill. A legitimate skill names one specific token file relative to the Hermes home."),
        "net_and_secrets": ("Skill script both reads credentials and talks to the network", Severity.LOW,
                            "Reading the vault, ~/.ssh, ~/.aws, dumping the environment, or a provider key by name in the same script that makes network calls (curl, nc, openssl, DNS, python http…) is the exfiltration shape. Sometimes legitimate — which is why it needs a human look. Scripts that only read their own scoped key are not listed.",
                            "Read the script. Confirm every network destination is the service the skill claims to use."),
        "encoded_payload": ("Skill script decodes a large embedded base64 blob", Severity.MEDIUM,
                            "Large encoded payloads plus a decode call is how a script hides a second script from review.",
                            "Decode the blob yourself and read it before trusting the skill."),
    }
    for key, items in cats.items():
        title, sev, why, fix = spec[key]
        n = len({i.split(":")[0] for i in items})
        if all("(bundled)" in i for i in items) and key not in NO_DOWNGRADE:
            sev = DOWNGRADE[sev]
            why += " All flagged files are byte-identical to the copies Hermes ships, so this is the vendor's content, not something planted on your machine."
        elif key in ("wants_keys", "wants_vault") and all("not read by Hermes" in i for i in items):
            sev = DOWNGRADE[sev]
            why += " These declarations sit under `metadata:`, which Hermes does not read for credentials — inert today, but not what an honest skill writes."
        out.findings.append(Finding("SKILL-001", f"{title} — {n} skill(s)", sev, Position.SUPPLY_CHAIN, str(skills_root), why, fix,
                                    f"daemonaudit scan --home {q(home)}  # SKILL-001 category: {key}", sorted(items)[:15],
                                    tags=SKILL_TAGS.get(key, [])))
    out.findings.append(Finding(
        "SKILL-001",
        f"Inventory: {n_skills} skills, {n_scripts} scripts, {len(net_skills)} skill(s) with network calls, {len(scoped)} scoped credential declaration(s)",
        Severity.INFO, Position.SUPPLY_CHAIN, str(skills_root),
        "Every skill is code and instructions you did not write, running with your agent's privileges. This is the size of that surface. Scoped credential declarations are normal and listed for awareness.",
        "Remove skills you do not use: fewer skills, smaller blast radius.",
        f"ls {q(skills_root)}",
        sorted(net_skills)[:10] + [f"declares scoped credential: {s}" for s in sorted(scoped)[:5]],
    ))
    return out
