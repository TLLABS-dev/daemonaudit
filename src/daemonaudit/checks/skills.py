"""SKILL-001: static heuristics over installed skills and agent context files.

Deliberately regex-only in v0.1 (deterministic, reproducible). One finding per
category, listing the skills involved — 82 built-in skills must not produce 82 panels.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from daemonaudit.checks._walk import rel, walk_files
from daemonaudit.discover.hermes_config import SECRET_NAME
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import NotSupported, Platform, q
from daemonaudit.registry import check

SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".ts", ".rb", ".pl", ".ps1"}
DOC_NAMES = {"SKILL.md", "SOUL.md", "AGENTS.md", "CLAUDE.md", ".cursorrules", "README.md"}
CONTEXT_FILES = ["SOUL.md", "AGENTS.md", ".cursorrules"]  # at the daemon home root

PIPE_TO_SHELL = re.compile(r"\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+(-E\s+)?)?(ba|z|da)?sh\b|\b(ba)?sh\s+-c\s+[\"']?\$\((curl|wget)", re.I)
INVISIBLE = re.compile("[\u200b-\u200d\u2060-\u2064\ufeff\u202a-\u202e\u2066-\u2069]")
INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|guidance)"
    r"|do not (tell|inform|mention|reveal|alert)[^\n.]{0,40}\buser\b"
    r"|without (telling|informing|notifying) the user"
    r"|(send|post|upload|forward|transmit)\b[^\n.]{0,40}\b(api[_ ]?keys?|tokens?|passwords?|credentials?|\.env|auth\.json)\b[^\n.]{0,40}\b(to|at)\b"
    r"|(cat|read|print|echo|curl)[^\n]{0,30}(~|\$HOME|/root)[^\n]{0,20}(\.env\b|auth\.json|\.ssh/id_[a-z0-9]+\b(?!\.pub)|\.aws/credentials)",
    re.I,
)
HIDDEN_COMMENT = re.compile(r"<!--(?P<body>(?:(?!-->).){0,400})-->", re.S)
COMMENT_IMPERATIVE = re.compile(
    r"ignore (all |any )?(previous|prior|above)|you (must|should|are|will)|\b(assistant|agent|model|system prompt)\b"
    r"|\b(curl|wget|bash|sh)\s|\$\(|\b(api[_ ]?key|token|password|secret)\b", re.I)
NETWORK = re.compile(r"\b(curl|wget|requests\.(get|post|put)|urllib|httpx|fetch\(|socket\.|http\.client|Invoke-WebRequest|net/http)", re.I)
SECRET_READ = re.compile(
    r"(\.env\b(?!\w)|auth\.json|\.anthropic_oauth|\.ssh/id_[a-z0-9]+\b(?!\.pub)|\.aws/credentials"
    r"|(os\.environ|process\.env|getenv)[\s\[\(.]*[\"']?[A-Z0-9_]*(API_?KEY|TOKEN|SECRET|PASSWORD)\b"
    r"|\$\{?[A-Z_]*(API_?KEY|TOKEN|SECRET|PASSWORD)\b)")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
DECODE = re.compile(r"base64\s+(-d|--decode)|b64decode|atob\(|FromBase64String", re.I)
FRONTMATTER_LIST = re.compile(r"^(?P<key>required_environment_variables|required_credential_files)\s*:\s*(?P<val>.+?)$", re.M)


def _read(plat: Platform, p: Path) -> str | None:
    try:
        return plat.read_nofollow(p, 2 * 1024 * 1024).decode("utf-8", "replace")
    except NotSupported:
        try:
            return p.read_text(errors="replace")
        except OSError:
            return None
    except OSError:
        return None


def _skill_of(skills_root: Path, p: Path) -> str:
    try:
        parts = p.relative_to(skills_root).parts
        return "/".join(parts[:2]) if len(parts) >= 2 else parts[0]
    except ValueError:
        return p.name


def _is_bundled(home: Path, lay, skills_root: Path, p: Path) -> bool:
    """True if this file is byte-identical to the vendor's shipped copy."""
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


# Categories that stay at full severity even for vendor-shipped skills.
NO_DOWNGRADE = {"invisible", "wants_vault", "pipe_script"}
DOWNGRADE = {Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW, Severity.LOW: Severity.INFO}


def _lines(text: str, rx: re.Pattern[str]) -> list[int]:
    return [i for i, line in enumerate(text.splitlines(), 1) if rx.search(line)]


@check("SKILL-001", "Risky patterns in installed skills and context files", Position.SUPPLY_CHAIN)
def skills(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    home, lay = target.home, target.layout
    skills_root = home / "skills"
    cats: dict[str, list[str]] = defaultdict(list)
    n_skills = 0
    n_scripts = 0
    net_skills: set[str] = set()

    files: list[Path] = [p for p in walk_files(skills_root, lay.exclude_dirs, max_depth=6)]
    files += [home / c for c in CONTEXT_FILES if (home / c).is_file() and not (home / c).is_symlink()]
    if not files:
        out.note("no skills directory or context files found")
        return out

    for p in files:
        text = _read(plat, p)
        if text is None:
            out.note(f"unreadable: {rel(home, p)}")
            continue
        skill = _skill_of(skills_root, p) if p.is_relative_to(skills_root) else rel(home, p)
        r = rel(home, p)
        if p.is_relative_to(skills_root) and _is_bundled(home, lay, skills_root, p):
            r += " (bundled)"
        is_doc = p.name in DOC_NAMES or p.suffix.lower() in (".md", ".txt")
        is_script = p.suffix.lower() in SCRIPT_EXT
        if p.name == "SKILL.md":
            n_skills += 1
        if is_script:
            n_scripts += 1

        if INVISIBLE.search(text):
            cats["invisible"].append(f"{skill}: {r} lines {_lines(text, INVISIBLE)[:5]}")
        for ln in _lines(text, PIPE_TO_SHELL):
            cats["pipe_script" if is_script else "pipe_doc"].append(f"{skill}: {r}:{ln}")
        if is_doc:
            for ln in _lines(text, INJECTION):
                cats["injection"].append(f"{skill}: {r}:{ln}")
            for m in HIDDEN_COMMENT.finditer(text):
                if COMMENT_IMPERATIVE.search(m.group("body")):
                    ln = text.count("\n", 0, m.start()) + 1
                    cats["hidden_comment"].append(f"{skill}: {r}:{ln}")
        if p.name == "SKILL.md":
            head = text[3:].split("\n---", 1)[0] if text.startswith("---") else ""
            for m in FRONTMATTER_LIST.finditer(head):
                val = m.group("val")
                if m.group("key") == "required_environment_variables" and SECRET_NAME.search(val):
                    cats["wants_keys"].append(f"{skill}: {val.strip()[:80]}")
                if m.group("key") == "required_credential_files" and re.search(r"(^|[\s,\[\"'])(\.env|auth\.json|\.anthropic_oauth\.json)\b", val):
                    cats["wants_vault"].append(f"{skill}: {val.strip()[:80]}")
        if is_script:
            has_net = bool(NETWORK.search(text))
            if has_net:
                net_skills.add(skill)
            if has_net and SECRET_READ.search(text):
                cats["net_and_secrets"].append(f"{skill}: {r}")
            if BASE64_BLOB.search(text) and DECODE.search(text):
                cats["encoded_payload"].append(f"{skill}: {r}")

    spec = {
        "invisible": ("Invisible Unicode (zero-width / bidi) inside skill or context text", Severity.HIGH,
                      "Zero-width and bidirectional-override characters hide instructions from a human reading the file while the model still sees them. There is no benign reason for them in a SKILL.md.",
                      "Open each file in an editor that shows invisible characters (or `grep -P '[\\x{200b}-\\x{200d}\\x{202a}-\\x{202e}]'`), read what is hidden, and remove the skill if it is not yours."),
        "pipe_script": ("Skill script pipes a remote download straight into a shell", Severity.HIGH,
                        "`curl … | sh` in a script executes whatever the server returns, with no review and no pin. A hijacked domain or CDN becomes code execution on your host.",
                        "Download to a file, verify a checksum or signature, then run. Or vendor the installer into the skill."),
        "pipe_doc": ("Skill instructions tell the agent to pipe a remote installer into a shell", Severity.MEDIUM,
                     "The agent follows SKILL.md literally. An instruction like `curl … | bash` means the first time the skill is used, the agent runs unreviewed remote code — the same as a script doing it, one step removed.",
                     "Prefer package managers (pip/brew/apt) or pinned releases in skill instructions; treat these skills as 'runs remote code' when deciding to keep them."),
        "injection": ("Prompt-injection phrasing in skill or context text", Severity.MEDIUM,
                      "Phrases like 'ignore previous instructions', 'without telling the user' or 'send the API key to' have no place in a tool description. They are how a skill turns the agent against you.",
                      "Read the flagged lines in context. Remove the skill if the intent is what it looks like."),
        "hidden_comment": ("Hidden HTML comments containing imperative instructions", Severity.MEDIUM,
                           "Markdown renderers hide `<!-- … -->`; the model does not. Instructions in comments are instructions you never saw.",
                           "Inspect the comment bodies; remove anything that reads as an instruction to the agent."),
        "wants_keys": ("Skill frontmatter requests provider credentials as environment variables", Severity.MEDIUM,
                       "Hermes auto-passes `required_environment_variables` into the skill's shell when they are set. A skill asking for ANTHROPIC_API_KEY or GITHUB_TOKEN gets your master key, not a scoped one.",
                       "Decide per skill whether it truly needs that key; use a scoped/secondary token where the provider supports it."),
        "wants_vault": ("Skill requests the vault itself as a credential file", Severity.HIGH,
                        "`required_credential_files` mounts files into the tool environment. Asking for .env / auth.json is asking for everything.",
                        "Remove the skill or the request; a legitimate skill names one specific token file."),
        "net_and_secrets": ("Skill script both reads credentials and talks to the network", Severity.LOW,
                            "Reading .env / os.environ / auth files in the same script that makes HTTP calls is the exfiltration shape. Often legitimate (an API client reading its own key) — which is exactly why it needs a human look.",
                            "Read the script. Confirm every network destination is the service the skill claims to use."),
        "encoded_payload": ("Skill script decodes a large embedded base64 blob", Severity.MEDIUM,
                            "Large encoded payloads plus a decode call is how a script hides a second script from review.",
                            "Decode the blob yourself and read it before trusting the skill."),
    }
    for key, items in cats.items():
        title, sev, why, fix = spec[key]
        n = len({i.split(":")[0] for i in items})
        all_bundled = all("(bundled)" in i for i in items)
        if all_bundled and key not in NO_DOWNGRADE:
            sev = DOWNGRADE[sev]
            why += " All flagged files are byte-identical to the copies Hermes ships, so this is the vendor's content, not something planted on your machine — still worth a look, but not a supply-chain alarm."
        out.findings.append(
            Finding(
                check_id="SKILL-001",
                title=f"{title} — {n} skill(s)",
                severity=sev,
                position=Position.SUPPLY_CHAIN,
                asset=str(skills_root),
                why=why,
                fix=fix,
                verify_cmd=f"daemonaudit scan --home {q(home)}  # SKILL-001 category: {key}",
                evidence=sorted(items)[:15],
            )
        )
    out.findings.append(
        Finding(
            check_id="SKILL-001",
            title=f"Inventory: {n_skills} skills, {n_scripts} scripts, {len(net_skills)} skill(s) with network calls",
            severity=Severity.INFO,
            position=Position.SUPPLY_CHAIN,
            asset=str(skills_root),
            why="Every skill is code and instructions you did not write, running with your agent's privileges. This is the size of that surface.",
            fix="Remove skills you do not use: fewer skills, smaller blast radius.",
            verify_cmd=f"ls {q(skills_root)}",
            evidence=sorted(net_skills)[:15],
        )
    )
    return out
