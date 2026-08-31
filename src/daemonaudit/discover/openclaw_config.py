"""OpenClaw settings view: openclaw.json (JSON5) + `$include` files + .env + the shell.

Values are held in memory for policy evaluation only. Checks must never put a
value from the config into a Finding — names only, or redacted displays.

`$include` follows OpenClaw's own rules (docs/gateway/configuration-reference.md, 2026.7):
resolved relative to the including file; must resolve inside the directory holding
`openclaw.json` or one of `OPENCLAW_INCLUDE_ROOTS` (path-list, read from the target's
`.env` — never from the audit shell, which may belong to a different install); 10
nested levels; 2 MB per file; circular includes are an error. A file OpenClaw would
refuse is not part of the effective config, so it is not part of ours either — and every
refusal is a coverage note, so a check that saw a partial config says so.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from daemonaudit.discover import _json5
from daemonaudit.discover.settings import Settings, parse_dotenv, read_text_nofollow
from daemonaudit.model import Target
from daemonaudit.platform import Platform

MAX_INCLUDE_DEPTH = 10
MAX_INCLUDE_BYTES = 2 * 1024 * 1024
MAX_INCLUDE_PATH = 4096
MAX_CONFIG_BYTES = 8 * 1024 * 1024

# channel → (config key holding the bot credential, env var fallback) — names only, never values
CHANNEL_CREDENTIAL = {
    "telegram": ("channels.telegram.botToken", "TELEGRAM_BOT_TOKEN"),
    "discord": ("channels.discord.token", "DISCORD_BOT_TOKEN"),
    "slack": ("channels.slack.botToken", "SLACK_BOT_TOKEN"),
    "whatsapp": ("channels.whatsapp", None),
    "signal": ("channels.signal", None),
    "imessage": ("channels.imessage", None),
    "msteams": ("channels.msteams.appPassword", None),
    "matrix": ("channels.matrix.accessToken", None),
    "googlechat": ("channels.googlechat", None),
}
# channels whose DMs are gated by dmPolicy / allowFrom
DM_CHANNELS = ("telegram", "discord", "slack", "whatsapp", "signal", "imessage", "msteams", "matrix", "googlechat", "line", "zalo", "nostr", "twitch", "mattermost", "irc", "bluebubbles")

SECRET_REF = re.compile(r"^\s*(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|(env|file|exec|op|keychain|secret|secretref)://.*)\s*$")


def is_secret_ref(v: Any) -> bool:
    """`${VAR}`, `env://…`, `file://…`, `exec://…` and SecretRef objects are references, not literals."""
    if isinstance(v, dict):
        return "source" in v or "ref" in v or "$ref" in v or "secretRef" in v
    return isinstance(v, str) and bool(SECRET_REF.match(v))


def _merge(base: dict, extra: dict) -> dict:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def _real(p: Path) -> Path:
    return Path(os.path.realpath(p))


def _inside(p: Path, roots: list[Path]) -> bool:
    return any(p == r or p.is_relative_to(r) for r in roots)


@dataclass
class _IncludeContext:
    plat: Platform
    roots: list[Path]  # canonical directories an include may resolve into
    notes: list[str]
    included: list[Path]  # files actually read, in order
    active: list[Path] = field(default_factory=list)  # canonical include chain being resolved (cycle check)


def _load_include(spec: Any, base_dir: Path, ctx: _IncludeContext, depth: int) -> dict | None:
    if not isinstance(spec, str):
        ctx.notes.append(f"$include spec is a {type(spec).__name__}, not a path; not followed")
        return None
    label = f"$include {spec[:80]}"
    if "\0" in spec or len(spec) >= MAX_INCLUDE_PATH:
        ctx.notes.append(f"{label} has an invalid path (NUL or ≥ {MAX_INCLUDE_PATH} chars); OpenClaw rejects it and so do we")
        return None
    p = Path(os.path.expanduser(spec))
    if not p.is_absolute():
        p = base_dir / p
    p = Path(os.path.normpath(p))  # lexical only; symlinks are refused below, never resolved through
    if p.is_symlink():
        # AGENTS.md §5: never follow a symlink inside the daemon home. OpenClaw follows it if the
        # target stays inside an allowed root; we say so instead of reading it.
        ctx.notes.append(f"{label} is a symlink; not followed (read the target directly if it is yours)")
        return None
    real = _real(p)
    if len(str(real)) >= MAX_INCLUDE_PATH:
        ctx.notes.append(f"{label} resolves to a path ≥ {MAX_INCLUDE_PATH} chars; OpenClaw rejects it and so do we")
        return None
    if not _inside(real, ctx.roots):
        ctx.notes.append(f"{label} resolves outside the config directory and OPENCLAW_INCLUDE_ROOTS; OpenClaw refuses it, so it is not part of the effective config")
        return None
    if real in ctx.active:
        ctx.notes.append(f"{label} is circular; not followed")
        return None
    if depth >= MAX_INCLUDE_DEPTH:
        ctx.notes.append(f"{label} nests deeper than {MAX_INCLUDE_DEPTH} levels; OpenClaw refuses it, so it is not part of the effective config")
        return None
    text = read_text_nofollow(ctx.plat, p, MAX_INCLUDE_BYTES, ctx.notes, label)
    if text is None:
        return None
    try:
        loaded = _json5.loads(text)
    except ValueError as e:
        ctx.notes.append(f"{label} unparsable ({e.__class__.__name__})")
        return None
    if not isinstance(loaded, dict):
        ctx.notes.append(f"{label} is a {type(loaded).__name__}, not an object; not merged")
        return None
    ctx.included.append(p)
    ctx.active.append(real)
    try:
        return _resolve_includes(loaded, p.parent, ctx, depth + 1)
    finally:
        ctx.active.pop()


def _resolve_includes(node: Any, base_dir: Path, ctx: _IncludeContext, depth: int = 0) -> Any:
    """Expand `{"$include": "path" | ["paths"]}` (a sibling-key object merges over the include)."""
    if isinstance(node, list):
        return [_resolve_includes(n, base_dir, ctx, depth) for n in node]
    if not isinstance(node, dict):
        return node
    if "$include" in node:
        specs = node["$include"]
        specs = specs if isinstance(specs, list) else [specs]
        merged: dict = {}
        for spec in specs:
            loaded = _load_include(spec, base_dir, ctx, depth)
            if isinstance(loaded, dict):
                _merge(merged, loaded)
        rest = {k: _resolve_includes(v, base_dir, ctx, depth) for k, v in node.items() if k != "$include"}
        return _merge(merged, rest)
    return {k: _resolve_includes(v, base_dir, ctx, depth) for k, v in node.items()}


def include_roots(config_dir: Path, dotenv: dict[str, str]) -> list[Path]:
    """The config directory plus `OPENCLAW_INCLUDE_ROOTS` from the target's `.env` (`:`-separated,
    `;` on Windows), canonicalised. The audit shell's environment is deliberately ignored."""
    roots = [_real(config_dir)]
    raw = dotenv.get("OPENCLAW_INCLUDE_ROOTS", "")
    for part in raw.split(os.pathsep):
        part = part.strip()
        if part:
            roots.append(_real(Path(os.path.expanduser(part))))
    return roots


@dataclass
class OpenClawSettings(Settings):
    included: list[Path] = field(default_factory=list)  # $include files actually read

    # --- helpers the policy checks share ---
    def agent_entries(self) -> list[dict]:
        lst = self.get("agents.list")
        return [a for a in lst if isinstance(a, dict)] if isinstance(lst, list) else []

    def exec_policy(self, scope: dict | None = None) -> dict[str, Any]:
        """Effective tools.exec.* (agent override over defaults). Defaults per docs: security=full, ask=off, host=auto."""
        base = self.get("tools.exec") if isinstance(self.get("tools.exec"), dict) else {}
        agent = (scope or {}).get("tools", {}).get("exec") if isinstance((scope or {}).get("tools"), dict) else None
        eff = {"security": "full", "ask": "off", "host": "auto", "autoAllowSkills": False, "strictInlineEval": False, "safeBins": []}
        eff.update({k: v for k, v in base.items() if v is not None})
        if isinstance(agent, dict):
            eff.update({k: v for k, v in agent.items() if v is not None})
        return eff

    def sandbox_mode(self, scope: dict | None = None) -> str:
        d = self.get("agents.defaults.sandbox.mode")
        a = (scope or {}).get("sandbox", {}).get("mode") if isinstance((scope or {}).get("sandbox"), dict) else None
        return str(a or d or "off")

    def sandbox_docker(self, scope: dict | None = None) -> dict[str, Any]:
        """Effective sandbox.docker.* for a scope: agent keys override the defaults key by key."""
        d = self.get("agents.defaults.sandbox.docker")
        eff: dict[str, Any] = dict(d) if isinstance(d, dict) else {}
        sb = (scope or {}).get("sandbox")
        a = sb.get("docker") if isinstance(sb, dict) else None
        if isinstance(a, dict):
            eff.update(a)
        return eff

    def sandbox_scopes(self) -> list[tuple[str, dict | None]]:
        """[(label, agent entry or None for the defaults)] — the defaults apply to every agent
        without its own entry, including `main`."""
        scopes: list[tuple[str, dict | None]] = [("defaults", None)]
        for a in self.agent_entries():
            if isinstance(a.get("id"), str):
                scopes.append((a["id"], a))
        return scopes

    def gateway_bind(self) -> str:
        return str(self.get("gateway.bind") or "loopback")

    def gateway_auth_mode(self) -> str:
        """token | password | trusted-proxy | none. Unset = token if a token/password is configured (env counts), else none."""
        mode = self.get("gateway.auth.mode")
        if isinstance(mode, str) and mode:
            return mode
        if self.get("gateway.auth.token") or self.env_set("OPENCLAW_GATEWAY_TOKEN"):
            return "token"
        if self.get("gateway.auth.password") or self.env_set("OPENCLAW_GATEWAY_PASSWORD"):
            return "password"
        return "none"

    def gateway_port(self) -> int:
        for cand in (self.env("OPENCLAW_GATEWAY_PORT")[0], self.get("gateway.port")):
            if isinstance(cand, str) and cand.isdigit():
                cand = int(cand)
            if isinstance(cand, int) and not isinstance(cand, bool) and 0 < cand < 65536:
                return cand
        from daemonaudit.discover.openclaw import DEFAULT_PORT

        return DEFAULT_PORT

    def channels_configured(self) -> list[str]:
        ch = self.get("channels")
        return sorted(k for k, v in ch.items() if isinstance(v, dict) and v.get("enabled") is not False) if isinstance(ch, dict) else []

    # --- network facts for NET-001 / RED-001 ---
    def service_ports(self) -> dict[str, int]:
        ports = {"gateway": self.gateway_port()}
        bp = self.get("browser.controlPort")
        if isinstance(bp, int) and not isinstance(bp, bool) and 0 < bp < 65536:
            ports["browser_control"] = bp
        return ports

    def unauthenticated_ports(self) -> set[int]:
        return {self.gateway_port()} if self.gateway_auth_mode() == "none" else set()

    def bind_loopback_fix(self) -> str:
        return ("Set gateway.bind: \"loopback\" in openclaw.json (reach it over SSH/Tailscale, or gateway.tailscale.mode: serve), "
                "and keep gateway.auth.mode: token with a long random token. Then `openclaw gateway restart`.")

    def require_auth_fix(self) -> str:
        return "Set gateway.auth.mode: token (or password) with a long random secret in openclaw.json and restart the gateway; never gateway.auth.mode: none."


def load_openclaw_settings(target: Target, plat: Platform) -> OpenClawSettings:
    s = OpenClawSettings(home=target.home)
    cfg_path = Path(target.meta.get("config_path") or (target.home / "openclaw.json"))
    s.config_path = cfg_path
    # .env first: it can name extra include roots. Absence is normal and not a note; unreadable is.
    env_notes: list[str] = []
    text = read_text_nofollow(plat, target.home / ".env", 4 * 1024 * 1024, env_notes, ".env")
    if text is not None:
        s.dotenv = parse_dotenv(text)
    s.notes += [n for n in env_notes if "not found" not in n]

    text = read_text_nofollow(plat, cfg_path, MAX_CONFIG_BYTES, s.notes, cfg_path.name)
    if text is not None:
        try:
            loaded = _json5.loads(text)
        except ValueError as e:
            loaded = None
            s.parse_error = f"{cfg_path.name} unparsable ({e.__class__.__name__}); checks that read it were skipped, not passed"
        if isinstance(loaded, dict):
            ctx = _IncludeContext(plat, include_roots(cfg_path.parent, s.dotenv), s.notes, s.included, [_real(cfg_path)])
            s.cfg = _resolve_includes(loaded, cfg_path.parent, ctx)
        elif loaded is not None:
            s.parse_error = f"{cfg_path.name} is a {type(loaded).__name__}, not an object; checks that read it were skipped, not passed"
        if s.parse_error:
            s.notes.append(s.parse_error)
    return s
