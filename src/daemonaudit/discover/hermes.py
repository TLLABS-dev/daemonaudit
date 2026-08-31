"""Hermes Agent (Nous Research) adapter.

Layout knowledge lives here and only here. Checks read `target.layout`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# A real Hermes process: a python interpreter running the hermes_cli module.
# Guards against substring self-matches (a shell, grep, or editor that merely
# mentions 'hermes_cli' on its command line).
GATEWAY_RE = re.compile(r'(^|[/\\])(python[0-9.]*|py)\b.*\bhermes_cli(\.main)?\b', re.I)

from daemonaudit.model import Layout, Target
from daemonaudit.platform import Platform

HERMES_LAYOUT = Layout(
    vault_files=[".env", "auth.json", ".anthropic_oauth.json"],
    vault_dirs=["pairing", "mcp-tokens"],
    private_files=["config.yaml", "state.db", ".hermes_history", ".skills_prompt_snapshot.json"],
    private_dirs=["sessions", "logs", "memories", "cron"],
    sprawl_paths=[
        "config.yaml", "state.db", "kanban.db", ".hermes_history", ".skills_prompt_snapshot.json",
        "sessions", "logs", "memories", "cron", "cache",
    ],
    exclude_dirs={"venv", ".venv", "node_modules", "__pycache__", ".git"},
    exclude_root_dirs={"hermes-agent", "bin"},
    data_extensions={".pid", ".lock", ".log", ".json", ".db", ".yaml", ".yml", ".md", ".txt", ".bak", ".etag", ".db-shm", ".db-wal"},
    transcript_hints=("sessions", "logs", "state.db", ".hermes_history", "memories"),
    preferred_vault=".env",
    bundled_skills_dir="hermes-agent/skills",
    skills_dirs=["skills"],
    context_files=["SOUL.md", "AGENTS.md", ".cursorrules"],
    vault_basenames={".env", "auth.json", ".anthropic_oauth.json", "mcp-tokens", "pairing"},
    default_ports={"api_server": 8642, "bluebubbles_webhook": 8645, "desktop_cdp": 9222},
    http_probe_paths=("/", "/v1/models", "/health"),
    http_ui_paths=(),
    process_needle="hermes_cli",
    display_name="Hermes",
)

DEFAULT_PORTS = HERMES_LAYOUT.default_ports


def hermes_home(override: str | os.PathLike | None = None) -> Path:
    if override:
        return Path(override).expanduser()
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".hermes"


def looks_like_hermes(home: Path) -> bool:
    return any((home / n).exists() for n in ("config.yaml", ".env", "hermes-agent", "auth.json", "state.db", "sessions"))


def _version(home: Path) -> str | None:
    pyproject = home / "hermes-agent" / "pyproject.toml"
    try:
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(errors="replace"), re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def _is_hermes_proc(proc: dict) -> bool:
    return bool(GATEWAY_RE.search(proc.get("cmdline") or ""))


def _belongs_to(proc: dict, home: Path, plat: Platform) -> bool | None:
    """Attribute a hermes_cli process to *this* home only: True / False / None = cannot tell.

    The gateway runs from `<home>/hermes-agent/venv/bin/python`, so the interpreter
    path in the cmdline names the home. Fall back to the process's HERMES_HOME if we
    may read its environment. A process we cannot attribute is not ours — scanning
    a demo or backup home must never probe the real daemon — but the caller records
    the None so the report says "attribution failed", not "not running".
    """
    cmd = proc.get("cmdline") or ""
    if str(home) in cmd:
        return True
    try:
        env = plat.process_env(proc["pid"])
    except Exception:  # noqa: BLE001 - NotSupported / permission / gone
        return None
    ph = env.get("HERMES_HOME")
    if ph:
        return Path(os.path.realpath(os.path.expanduser(ph))) == home
    # No HERMES_HOME and no path hint: only the default home may claim it.
    return home == Path(os.path.realpath(Path.home() / ".hermes")) and str(Path.home()) in cmd


def discover_hermes(plat: Platform, home_override=None) -> Target | None:
    given = hermes_home(home_override)
    if not given.is_dir():
        return None
    if home_override and not looks_like_hermes(given):
        return None
    # Resolve the root exactly once. Everything below it is walked with no-follow
    # semantics; a symlink *as* the root is a user choice, a symlink *inside* is not.
    home = Path(os.path.realpath(given))
    procs: list[dict] = []
    unattributed: list[int] = []
    for p in plat.find_processes("hermes_cli"):
        if not _is_hermes_proc(p):
            continue
        owned = _belongs_to(p, home, plat)
        if owned:
            procs.append(p)
        elif owned is None:
            unattributed.append(p["pid"])
    gateway_pids = [p["pid"] for p in procs if "gateway" in p["cmdline"]]
    notes: list[str] = []
    if unattributed and not procs:
        notes.append(f"hermes pid(s) {', '.join(map(str, unattributed))} could not be attributed to this home (process environment unreadable); "
                     "treated as not this install's, so listener and process probes see no running daemon")
    t = Target(
        framework="hermes",
        home=home,
        version=_version(home),
        pids=[p["pid"] for p in procs],
        layout=HERMES_LAYOUT,
        meta={
            "home_as_given": str(given) if given != home else None,
            "gateway_pids": gateway_pids,
            "unattributed_pids": unattributed,
            "gateway_socket": str(home / "gateway.sock") if (home / "gateway.sock").exists() else None,
        },
    )
    from daemonaudit.discover.settings import load_settings

    s = load_settings(t, plat)
    t.meta["config_error"] = s.parse_error
    t.meta["notes"] = notes + ([s.parse_error] if s.parse_error else [])
    return t
