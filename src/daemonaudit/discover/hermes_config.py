"""Hermes settings view: config.yaml + .env + (fallback) the audit shell's environment.

Values are held in memory for policy evaluation only. Checks must never put a
value from `.env` into a Finding — names only, or redacted displays.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from daemonaudit.model import Target
from daemonaudit.platform import NotSupported, Platform

TRUTHY = {"1", "true", "yes", "on"}

# platform → (env var that means "configured", per-platform allowed-users var, per-platform allow-all var)
PLATFORM_ENV = {
    "telegram": ("TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_USERS", "TELEGRAM_ALLOW_ALL_USERS"),
    "discord": ("DISCORD_BOT_TOKEN", "DISCORD_ALLOWED_USERS", "DISCORD_ALLOW_ALL_USERS"),
    "slack": ("SLACK_BOT_TOKEN", "SLACK_ALLOWED_USERS", "SLACK_ALLOW_ALL_USERS"),
    "whatsapp": ("WHATSAPP_CLOUD_ACCESS_TOKEN", "WHATSAPP_ALLOWED_USERS", "WHATSAPP_ALLOW_ALL_USERS"),
    "teams": ("TEAMS_CLIENT_SECRET", "TEAMS_ALLOWED_USERS", "TEAMS_ALLOW_ALL_USERS"),
}

SECRET_NAME = re.compile(r"(?i)(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY)")


def parse_dotenv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if v[:1] in ("'", '"') and v[-1:] == v[:1] and len(v) >= 2:
            v = v[1:-1]
        elif " #" in v:
            v = v.split(" #", 1)[0].rstrip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            out[k] = v
    return out


@dataclass
class HermesSettings:
    cfg: dict[str, Any] = field(default_factory=dict)
    dotenv: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)  # coverage notes for checks to surface
    home: Path = Path(".")

    # --- config.yaml ---
    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.cfg
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    # --- env (.env first, then the shell we're running in) ---
    def env(self, name: str) -> tuple[str | None, str | None]:
        """(value, source) — source is '.env', 'shell' or None."""
        if name in self.dotenv:
            return self.dotenv[name], ".env"
        if name in os.environ:
            return os.environ[name], "shell"
        return None, None

    def env_set(self, name: str) -> bool:
        v, _ = self.env(name)
        return v is not None and v.strip() != ""

    def env_truthy(self, name: str) -> bool:
        v, _ = self.env(name)
        return v is not None and v.strip().lower() in TRUTHY

    def env_falsy(self, name: str) -> bool:
        v, _ = self.env(name)
        return v is not None and v.strip().lower() in {"0", "false", "no", "off"}

    def env_names_matching(self, pattern: str) -> list[str]:
        rx = re.compile(pattern)
        names = set(self.dotenv) | set(os.environ)
        return sorted(n for n in names if rx.search(n))

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


def load_settings(target: Target, plat: Platform) -> HermesSettings:
    cached = target.meta.get("_settings")
    if cached is not None:
        return cached
    s = HermesSettings(home=target.home)
    cfg_path = target.home / "config.yaml"
    try:
        raw = plat.read_nofollow(cfg_path, 8 * 1024 * 1024)
        loaded = yaml.safe_load(raw.decode("utf-8", "replace"))
        s.cfg = loaded if isinstance(loaded, dict) else {}
    except FileNotFoundError:
        s.notes.append("config.yaml not found (defaults assumed)")
    except NotSupported:
        try:
            loaded = yaml.safe_load(cfg_path.read_text(errors="replace"))
            s.cfg = loaded if isinstance(loaded, dict) else {}
        except (OSError, yaml.YAMLError) as e:
            s.notes.append(f"config.yaml unreadable: {e.__class__.__name__}")
    except (OSError, yaml.YAMLError) as e:
        s.notes.append(f"config.yaml unreadable: {e.__class__.__name__}")

    env_path = target.home / ".env"
    try:
        s.dotenv = parse_dotenv(plat.read_nofollow(env_path, 4 * 1024 * 1024).decode("utf-8", "replace"))
    except FileNotFoundError:
        s.notes.append(".env not found")
    except NotSupported:
        try:
            s.dotenv = parse_dotenv(env_path.read_text(errors="replace"))
        except OSError as e:
            s.notes.append(f".env unreadable: {e.__class__.__name__}")
    except OSError as e:
        s.notes.append(f".env unreadable: {e.__class__.__name__}")
    target.meta["_settings"] = s
    return s
