"""Hermes Agent (Nous Research) adapter.

Layout knowledge lives here and only here. Checks read `target.layout`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

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
    exclude_dirs={"hermes-agent", "venv", ".venv", "node_modules", "bin", "__pycache__"},
    data_extensions={".pid", ".lock", ".log", ".json", ".db", ".yaml", ".yml", ".md", ".txt", ".bak", ".etag", ".db-shm", ".db-wal"},
    transcript_hints=("sessions", "logs", "state.db", ".hermes_history", "memories"),
    preferred_vault=".env",
)

DEFAULT_PORTS = {"api_server": 8642, "bluebubbles_webhook": 8645, "desktop_cdp": 9222}


def hermes_home(override: str | os.PathLike | None = None) -> Path:
    if override:
        return Path(override).expanduser()
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".hermes"


def _version(home: Path) -> str | None:
    pyproject = home / "hermes-agent" / "pyproject.toml"
    try:
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(errors="replace"), re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def discover_hermes(plat: Platform, home_override=None) -> Target | None:
    given = hermes_home(home_override)
    if not given.is_dir():
        return None
    # Resolve the root exactly once. Everything below it is walked with no-follow
    # semantics; a symlink *as* the root is a user choice, a symlink *inside* is not.
    home = Path(os.path.realpath(given))
    procs = plat.find_processes("hermes_cli")
    gateway_pids = [p["pid"] for p in procs if "gateway" in p["cmdline"]]
    return Target(
        framework="hermes",
        home=home,
        version=_version(home),
        pids=[p["pid"] for p in procs],
        layout=HERMES_LAYOUT,
        meta={
            "home_as_given": str(given) if given != home else None,
            "gateway_pids": gateway_pids,
            "gateway_socket": str(home / "gateway.sock") if (home / "gateway.sock").exists() else None,
        },
    )
