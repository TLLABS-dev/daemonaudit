"""Hermes settings view: config.yaml + .env + (fallback) the audit shell's environment.

Generic machinery (dotted `get`, env lookup with source tracking, dotenv parsing)
lives in `discover/settings.py`; this module adds what only Hermes has. Checks
must never put a value from `.env` into a Finding — names only, or redacted displays.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import yaml

from daemonaudit.discover.settings import SECRET_NAME, Settings, load_settings, parse_dotenv, read_text_nofollow  # noqa: F401 - re-exported for checks
from daemonaudit.model import Target
from daemonaudit.platform import Platform

# platform → (env var that means "configured", per-platform allowed-users var, per-platform allow-all var)
PLATFORM_ENV = {
    "telegram": ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USERS", "TELEGRAM_ALLOW_ALL_USERS"),
    "discord": ("DISCORD_BOT_TOKEN", "DISCORD_ALLOWED_USERS", "DISCORD_ALLOW_ALL_USERS"),
    "slack": ("SLACK_BOT_TOKEN", "SLACK_ALLOWED_USERS", "SLACK_ALLOW_ALL_USERS"),
    "whatsapp": ("WHATSAPP_CLOUD_ACCESS_TOKEN", "WHATSAPP_ALLOWED_USERS", "WHATSAPP_ALLOW_ALL_USERS"),
    "teams": ("TEAMS_CLIENT_SECRET", "TEAMS_ALLOWED_USERS", "TEAMS_ALLOW_ALL_USERS"),
}


@dataclass
class HermesSettings(Settings):
    # --- platforms ---
    def platforms_enabled(self) -> list[str]:
        out = set()
        plats = self.get("platforms", {}) or {}
        if isinstance(plats, dict):
            for name, conf in plats.items():
                if isinstance(conf, dict) and conf.get("enabled") is True:
                    out.add(name)
        for name, (token_var, _, _) in PLATFORM_ENV.items():
            if self.env_set(token_var):
                out.add(name)
        return sorted(out)

    def pairing_approved(self, platform: str) -> int:
        p = self.home / "pairing" / f"{platform}-approved.json"
        try:
            data = json.loads(p.read_text())
            return len(data) if isinstance(data, (list, dict)) else 0
        except (OSError, ValueError):
            return 0

    # --- network facts for NET-001 / RED-001 ---
    def service_ports(self) -> dict[str, int]:
        from daemonaudit.discover.hermes import DEFAULT_PORTS

        ports = dict(DEFAULT_PORTS)
        api_port, _ = self.env("API_SERVER_PORT")
        if api_port and api_port.isdigit():
            ports["api_server"] = int(api_port)
        return ports

    def unauthenticated_ports(self) -> set[int]:
        if self.env_truthy("API_SERVER_ENABLED") and not self.env_set("API_SERVER_KEY"):
            return {self.service_ports()["api_server"]}
        return set()

    def bind_loopback_fix(self) -> str:
        return ("Bind to 127.0.0.1 (e.g. API_SERVER_HOST=127.0.0.1) and reach it over SSH/Tailscale, "
                "or put it behind an authenticating reverse proxy. Set API_SERVER_KEY if the API server is enabled.")

    def require_auth_fix(self) -> str:
        return "Put authentication in front of it (API_SERVER_KEY for the API server; OAuth/OIDC for the dashboard) or bind it to loopback and tunnel."


def load_hermes_settings(target: Target, plat: Platform) -> HermesSettings:
    s = HermesSettings(home=target.home)
    cfg_path = target.home / "config.yaml"
    s.config_path = cfg_path
    text = read_text_nofollow(plat, cfg_path, 8 * 1024 * 1024, s.notes, "config.yaml")
    if text is not None:
        try:
            loaded = yaml.safe_load(text)
            s.cfg = loaded if isinstance(loaded, dict) else {}
        except yaml.YAMLError as e:
            s.notes.append(f"config.yaml unreadable: {e.__class__.__name__}")
    text = read_text_nofollow(plat, target.home / ".env", 4 * 1024 * 1024, s.notes, ".env")
    if text is not None:
        s.dotenv = parse_dotenv(text)
    return s
