"""OpenClaw settings view: openclaw.json (JSON5) + `$include` files + .env + the shell.

Values are held in memory for policy evaluation only. Checks must never put a
value from the config into a Finding — names only, or redacted displays.
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

MAX_INCLUDE_DEPTH = 3

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


def _resolve_includes(node: Any, base_dir: Path, plat: Platform, notes: list[str], included: list[Path], depth: int = 0) -> Any:
    """Expand `{"$include": "path" | ["paths"]}` (a sibling-key object merges over the include)."""
    if isinstance(node, list):
        return [_resolve_includes(n, base_dir, plat, notes, included, depth) for n in node]
    if not isinstance(node, dict):
        return node
    if "$include" in node:
        if depth >= MAX_INCLUDE_DEPTH:
            notes.append("$include nesting too deep; not followed")
            return {k: v for k, v in node.items() if k != "$include"}
        specs = node["$include"]
        specs = specs if isinstance(specs, list) else [specs]
        merged: dict = {}
        for spec in specs:
            if not isinstance(spec, str):
                continue
            p = Path(os.path.expanduser(spec))
            if not p.is_absolute():
                p = base_dir / p
            if p.is_symlink():
                notes.append(f"$include {spec} is a symlink; not followed")
                continue
            text = read_text_nofollow(plat, p, 8 * 1024 * 1024, notes, f"$include {spec}")
            if text is None:
                continue
            try:
                loaded = _json5.loads(text)
            except ValueError as e:
                notes.append(f"$include {spec} unparsable: {e.__class__.__name__}")
                continue
            included.append(p)
            loaded = _resolve_includes(loaded, p.parent, plat, notes, included, depth + 1)
            if isinstance(loaded, dict):
                _merge(merged, loaded)
        rest = {k: _resolve_includes(v, base_dir, plat, notes, included, depth) for k, v in node.items() if k != "$include"}
        return _merge(merged, rest)
    return {k: _resolve_includes(v, base_dir, plat, notes, included, depth) for k, v in node.items()}


@dataclass
class OpenClawSettings(Settings):
    included: list[Path] = field(default_factory=list)  # $include files actually read
    parse_error: bool = False

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
            if isinstance(cand, int) and 0 < cand < 65536:
                return cand
            if isinstance(cand, str) and cand.isdigit():
                return int(cand)
        from daemonaudit.discover.openclaw import DEFAULT_PORT

        return DEFAULT_PORT

    def channels_configured(self) -> list[str]:
        ch = self.get("channels")
        return sorted(k for k, v in ch.items() if isinstance(v, dict) and v.get("enabled") is not False) if isinstance(ch, dict) else []

    # --- network facts for NET-001 / RED-001 ---
    def service_ports(self) -> dict[str, int]:
        ports = {"gateway": self.gateway_port()}
        bp = self.get("browser.controlPort")
        if isinstance(bp, int):
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
    text = read_text_nofollow(plat, cfg_path, 8 * 1024 * 1024, s.notes, cfg_path.name)
    if text is not None:
        try:
            loaded = _json5.loads(text)
        except ValueError as e:
            s.notes.append(f"{cfg_path.name} unparsable ({e.__class__.__name__}): policy checks ran against defaults")
            s.parse_error = True
            loaded = {}
        loaded = _resolve_includes(loaded, cfg_path.parent, plat, s.notes, s.included)
        s.cfg = loaded if isinstance(loaded, dict) else {}
    text = read_text_nofollow(plat, target.home / ".env", 4 * 1024 * 1024, [], ".env")  # absence is normal here
    if text is not None:
        s.dotenv = parse_dotenv(text)
    return s
