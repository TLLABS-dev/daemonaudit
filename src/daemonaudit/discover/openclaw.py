"""OpenClaw adapter.

Layout knowledge lives here and only here. Checks read `target.layout`.

State dir: `--home` › `$OPENCLAW_STATE_DIR` › `$OPENCLAW_HOME/.openclaw` › `~/.openclaw`
(`--profile <name>` / `$OPENCLAW_PROFILE` isolate under `~/.openclaw-<name>`; `--dev` uses
`~/.openclaw-dev` and port 19001). Config: `$OPENCLAW_CONFIG_PATH` › `<home>/openclaw.json`.

On disk (2026.7.x, per the bundled docs — the release is mid-migration from JSON files to
`state/openclaw.sqlite`, so both the legacy files and the DB are covered):
  openclaw.json (+ $include files)    config — and, unless SecretRefs are used, the gateway token,
                                      channel bot tokens and provider keys → vault
  .env                                loaded by the gateway at start → vault
  credentials/                        channel creds (WhatsApp), pairing state, DM allowlists → vault
  devices/, nodes/                    device/node pairing tokens (`paired.json`) → vault
  secrets.json, secrets/, gateway.token, gateway.password, googlechat-service-account.json → vault
  agents/<id>/agent/auth-profiles.json, auth.json, openclaw-agent.sqlite  per-agent provider auth → vault
  agents/<id>/agent/models.json       generated catalog that can carry plaintext keys → sprawl target
  agents/<id>/sessions/, sessions/, transcripts/, state/, logs/, tui/, cron/, memory/, media/, audit/ → private
  exec-approvals.json                 host exec allowlist/policy → private, policy input
  /tmp/openclaw/openclaw-*.log        the gateway's own log file lives OUTSIDE the home by default → private
  workspace*/                         AGENTS.md / SOUL.md / … context files + <workspace>/skills, hooks
  skills/, hooks/, ~/.agents/skills   managed skills and hook handlers (code); plugin-skills/ are symlinks
  extensions/, browser/, sandboxes/, npm/, tools/  plugin code, Chrome profiles, sandbox copies — excluded
The framework itself lives in the npm package (`node_modules/openclaw`), never under the home;
its `skills/` directory is the bundled-skill reference for SKILL-001.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from daemonaudit.model import Layout, Target
from daemonaudit.platform import Platform

# A real OpenClaw gateway: node/bun running the openclaw entry (openclaw.mjs / dist/index.js / the
# `openclaw` bin shim / `openclaw-gateway` wrapper) with the `gateway` command on its line.
GATEWAY_RE = re.compile(
    r"(^|[/\\])(node[0-9.]*|bun)(\.exe)?\b[^\n]*\bopenclaw(\.mjs|-gateway)?\b[^\n]*\bgateway\b"
    r"|(^|[/\\])openclaw-gateway\b",
    re.I,
)
DEFAULT_PORT = 18789
DEV_PORT = 19001
WORKSPACE_CONTEXT = ["AGENTS.md", "SOUL.md", "TOOLS.md", "IDENTITY.md", "USER.md", "HEARTBEAT.md", "BOOTSTRAP.md", "MEMORY.md", ".cursorrules"]


def openclaw_home(override: str | os.PathLike | None = None) -> Path:
    if override:
        return Path(override).expanduser()
    env = os.environ.get("OPENCLAW_STATE_DIR")
    if env:
        return Path(env).expanduser()
    base = Path(os.environ.get("OPENCLAW_HOME") or "").expanduser() if os.environ.get("OPENCLAW_HOME") else Path.home()
    profile = os.environ.get("OPENCLAW_PROFILE")
    if profile and profile != "default":
        return base / f".openclaw-{profile}"
    return base / ".openclaw"


def config_path(home: Path, env_selected: bool = False) -> Path:
    """`$OPENCLAW_CONFIG_PATH` names the config of the install *this environment* selects. It is
    honoured for that home (`env_selected`, i.e. no `--home`) or when it lives inside the home being
    scanned. A `--home` pointed at a copy or backup never reads the live config (Codex C5 #2)."""
    env = os.environ.get("OPENCLAW_CONFIG_PATH")
    if env:
        p = Path(env).expanduser()
        if env_selected or Path(os.path.realpath(p.parent)) == home:
            return p
    return home / "openclaw.json"


def looks_like_openclaw(home: Path) -> bool:
    return (home / "openclaw.json").is_file() or ((home / "agents").is_dir() and (home / "credentials").is_dir())


def package_root(procs: list[dict]) -> Path | None:
    """The installed npm package (`.../node_modules/openclaw`) — from a running gateway's
    command line, `$OPENCLAW_PACKAGE_ROOT`, or the `openclaw` executable on PATH."""
    env = os.environ.get("OPENCLAW_PACKAGE_ROOT")
    if env and (Path(env) / "package.json").is_file():
        return Path(env)
    for p in procs:
        m = re.search(r"(\S*[/\\]node_modules[/\\]openclaw)[/\\]", p.get("cmdline") or "")
        if m and (Path(m.group(1)) / "package.json").is_file():
            return Path(m.group(1))
    exe = shutil.which("openclaw")
    if exe:
        try:
            real = Path(os.path.realpath(exe))
        except OSError:
            return None
        for cand in (real.parent, *real.parents):
            if (cand / "package.json").is_file() and cand.name == "openclaw":
                return cand
    return None


def _package_version(root: Path | None) -> str | None:
    if root is None:
        return None
    try:
        return json.loads((root / "package.json").read_text(encoding="utf-8", errors="replace")).get("version")
    except (OSError, ValueError, AttributeError):
        return None


def _is_openclaw_proc(proc: dict) -> bool:
    return bool(GATEWAY_RE.search(proc.get("cmdline") or ""))


def _belongs_to(proc: dict, home: Path, plat: Platform) -> bool | None:
    """Attribute a gateway process to *this* home: True / False / None = cannot tell (the process
    environment is unreadable). Same rule as Hermes: a process we cannot attribute is not ours —
    scanning a backup must never probe the live daemon — but the caller records the None so the
    report can say "attribution failed" rather than "not running"."""
    cmd = proc.get("cmdline") or ""
    if str(home) in cmd:
        return True
    try:
        env = plat.process_env(proc["pid"])
    except Exception:  # noqa: BLE001 - NotSupported / permission / gone
        return None
    sd = env.get("OPENCLAW_STATE_DIR")
    if sd:
        return Path(os.path.realpath(os.path.expanduser(sd))) == home
    profile = env.get("OPENCLAW_PROFILE")
    base = Path(os.path.realpath(env.get("OPENCLAW_HOME") or Path.home()))
    expected = base / (f".openclaw-{profile}" if profile and profile != "default" else ".openclaw")
    if "--dev" in cmd.split():
        expected = base / ".openclaw-dev"
    return home == Path(os.path.realpath(expected))


def _agent_dirs(home: Path) -> list[Path]:
    root = home / "agents"
    try:
        return sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return []


def _gateway_logs(cfg: dict) -> list[str]:
    """The gateway log file defaults to /tmp/openclaw/openclaw-YYYY-MM-DD.log — outside the home."""
    logging = cfg.get("logging") if isinstance(cfg.get("logging"), dict) else {}
    explicit = logging.get("file") if isinstance(logging, dict) else None
    out: list[str] = []
    if isinstance(explicit, str) and explicit.strip():
        p = Path(os.path.expanduser(explicit.strip()))
        if p.is_file() and not p.is_symlink():
            out.append(str(p))
    for d in (Path("/tmp/openclaw"), Path(os.environ.get("TMPDIR") or "/tmp") / f"openclaw-{os.getuid() if hasattr(os, 'getuid') else 'user'}"):
        try:
            if d.is_dir() and not d.is_symlink():
                out += [str(p) for p in sorted(d.glob("openclaw-*.log")) if p.is_file() and not p.is_symlink()][-7:]
        except OSError:
            continue
    return out


def _too_broad(ws: Path, home: Path) -> str | None:
    """A workspace that is the user's home, an ancestor of it, an ancestor of (or) the daemon home,
    or the filesystem root is not a workspace, it is the machine. Walking it for secret sprawl would
    take minutes and attribute every other project's secrets to this daemon."""
    ws = Path(os.path.realpath(ws))
    user_home = Path(os.path.realpath(Path.home()))
    if ws == Path(ws.anchor):
        return "the filesystem root"
    if ws == user_home:
        return "your home directory"
    if ws in user_home.parents:
        return "an ancestor of your home directory"
    if ws == home or ws in home.parents:
        return "the daemon home or an ancestor of it"
    return None


def build_layout(home: Path, cfg: dict, pkg_root: Path | None, included: list[Path] = (), cfg_path: Path | None = None) -> Layout:
    """Per-home layout: agent ids and workspaces come from the directory and the config."""
    agents = _agent_dirs(home)
    cp = cfg_path or (home / "openclaw.json")
    notes: list[str] = []
    vault_files = [str(cp) if cp.parent != home else cp.name, ".env", "hooks.json", "secrets.json", "gateway.token", "gateway.password",
                   "googlechat-service-account.json", "credentials/oauth.json"]
    vault_files += [str(p) for p in included]
    for a in agents:
        vault_files += [f"agents/{a.name}/agent/auth-profiles.json", f"agents/{a.name}/agent/auth.json", f"agents/{a.name}/agent/openclaw-agent.sqlite"]
    workspaces: list[Path] = []

    def add_ws(v) -> None:
        if isinstance(v, str) and v.strip():
            p = Path(os.path.expanduser(v.strip()))
            if not p.is_absolute():
                p = home / p
            if p not in workspaces:
                workspaces.append(p)

    defaults = cfg.get("agents", {}).get("defaults", {}) if isinstance(cfg.get("agents"), dict) else {}
    if isinstance(defaults, dict):
        add_ws(defaults.get("workspace"))
    lst = cfg.get("agents", {}).get("list") if isinstance(cfg.get("agents"), dict) else None
    if isinstance(lst, list):
        for a in lst:
            if isinstance(a, dict):
                add_ws(a.get("workspace"))
    add_ws("workspace")
    for a in agents:
        add_ws(str(a / "workspace"))
    workspaces = [w for w in workspaces if w.is_dir() and not w.is_symlink()]
    sprawl_ws: list[Path] = []
    for w in workspaces:
        why = _too_broad(w, home)
        if why:
            notes.append(f"workspace {w} is {why}; not walked for secret sprawl — point agents.defaults.workspace at a dedicated directory")
        else:
            sprawl_ws.append(w)

    skills_dirs = ["skills", "hooks", str(Path.home() / ".agents" / "skills")]
    for w in workspaces:
        skills_dirs += [str(w / "skills"), str(w / ".agents" / "skills"), str(w / "hooks")]
    load = cfg.get("skills", {}).get("load", {}) if isinstance(cfg.get("skills"), dict) else {}
    extra = load.get("extraDirs") if isinstance(load, dict) else None
    if isinstance(extra, list):
        skills_dirs += [os.path.expanduser(d) for d in extra if isinstance(d, str)]
    context = [str(w / c) for w in workspaces for c in WORKSPACE_CONTEXT]
    private_files = ["exec-approvals.json", "update-check.json"] + [f"agents/{a.name}/agent/models.json" for a in agents] + _gateway_logs(cfg)

    return Layout(
        vault_files=vault_files,
        vault_dirs=["credentials", "devices", "nodes", "secrets"],
        private_files=private_files,
        private_dirs=["agents", "sessions", "transcripts", "logs", "state", "tui", "cron", "memory", "media", "audit", "backups"],
        sprawl_paths=["agents", "sessions", "transcripts", "logs", "state", "tui", "cron", "memory", "audit", "hooks.json", "exec-approvals.json",
                      "openclaw.json.bak"] + [str(w) for w in sprawl_ws],
        exclude_dirs={"node_modules", ".git", "__pycache__", "venv", ".venv", "codex-home"},
        exclude_root_dirs={"extensions", "plugins", "browser", "sandboxes", "sandbox", "plugin-skills", "tmp", "npm", "npm-runtime", "tools", "git", "completions", "dns", "wiki"},
        data_extensions={".json", ".jsonl", ".sqlite", ".sqlite-wal", ".sqlite-shm", ".db", ".db-wal", ".db-shm", ".log", ".md", ".txt",
                         ".lock", ".pid", ".attested", ".yaml", ".yml"},
        backup_markers=(".bak", "~", ".orig", ".old", ".backup"),
        transcript_hints=("sessions", "logs", "state", "tui", "memory", ".sqlite", ".jsonl", "workspace"),
        preferred_vault=".env",
        bundled_skills_dir=str(pkg_root / "skills") if pkg_root and (pkg_root / "skills").is_dir() else None,
        skills_dirs=skills_dirs,
        context_files=context,
        vault_basenames={"openclaw.json", "auth-profiles.json", "auth.json", "openclaw-agent.sqlite", "credentials", ".env", "devices", "nodes",
                         "secrets.json", "secrets", "gateway.token", "gateway.password", "exec-approvals.json", "hooks.json"},
        default_ports={"gateway": DEFAULT_PORT},
        http_probe_paths=("/v1/models", "/v1/chat/completions", "/tools/invoke", "/metrics"),
        http_ui_paths=("/", "/health", "/healthz", "/readyz"),
        process_needle="openclaw",
        display_name="OpenClaw",
        coverage_notes=notes,
    )


def discover_openclaw(plat: Platform, home_override=None) -> Target | None:
    given = openclaw_home(home_override)
    if not given.is_dir():
        return None
    if home_override and not looks_like_openclaw(given):
        return None
    home = Path(os.path.realpath(given))
    procs: list[dict] = []
    unattributed: list[int] = []
    for p in plat.find_processes("openclaw"):
        if not _is_openclaw_proc(p):
            continue
        owned = _belongs_to(p, home, plat)
        if owned:
            procs.append(p)
        elif owned is None:
            unattributed.append(p["pid"])
    pkg = package_root(procs)
    cp = config_path(home, env_selected=home_override is None)
    notes: list[str] = []
    if unattributed and not procs:
        notes.append(f"gateway pid(s) {', '.join(map(str, unattributed))} could not be attributed to this home (process environment unreadable); "
                     "treated as not this install's, so listener and process probes see no running daemon")
    t = Target(
        framework="openclaw",
        home=home,
        version=_package_version(pkg),
        pids=[p["pid"] for p in procs],
        meta={
            "home_as_given": str(given) if given != home else None,
            "gateway_pids": [p["pid"] for p in procs],
            "unattributed_pids": unattributed,
            "config_path": str(cp),
            "package_root": str(pkg) if pkg else None,
        },
    )
    from daemonaudit.discover.settings import load_settings

    s = load_settings(t, plat)
    if t.version is None:
        t.version = s.get("meta.lastTouchedVersion") or None
    t.layout = build_layout(home, s.cfg, pkg, s.included, cp)
    t.meta["config_error"] = s.parse_error
    t.meta["notes"] = notes + list(s.notes) + list(t.layout.coverage_notes)
    return t
