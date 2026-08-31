"""Framework-neutral settings view: a parsed config mapping + a dotenv + the audit
shell's environment, with source tracking.

Values are held in memory for policy evaluation only. Checks must never put a
value from the vault into a Finding — names only, or redacted displays.

`load_settings(target, plat)` dispatches on `target.framework` and caches the
result in `target.meta["_settings"]` (underscore keys never reach the report).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from daemonaudit.model import Target
from daemonaudit.platform import NotSupported, Platform
from daemonaudit.registry import Skipped

TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"0", "false", "no", "off"}

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


def read_text_nofollow(plat: Platform, path: Path, max_bytes: int, notes: list[str], label: str) -> str | None:
    """Read a config-ish file without following symlinks. Missing/unreadable → note, None."""
    try:
        return plat.read_nofollow(path, max_bytes).decode("utf-8", "replace")
    except FileNotFoundError:
        notes.append(f"{label} not found")
    except NotSupported:
        try:
            return path.read_text(errors="replace")
        except FileNotFoundError:
            notes.append(f"{label} not found")
        except OSError as e:
            notes.append(f"{label} unreadable: {e.__class__.__name__}")
    except OSError as e:
        notes.append(f"{label} unreadable: {e.__class__.__name__}")
    return None


@dataclass
class Settings:
    cfg: dict[str, Any] = field(default_factory=dict)
    dotenv: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)  # coverage notes for checks to surface
    home: Path = Path(".")
    config_path: Path | None = None
    # Set when the config file exists but could not be parsed (or is not a mapping). `cfg` is then
    # empty, and every value a check would read from it is a *default*, not a fact about this install.
    parse_error: str | None = None

    def require_config(self) -> None:
        """Policy checks call this before reading `cfg`. AGENTS.md §4: a check that cannot run
        raises Skipped; it never evaluates defaults and reports them as a pass."""
        if self.parse_error:
            raise Skipped(self.parse_error)

    # --- config mapping ---
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
        return v is not None and v.strip().lower() in FALSY

    def env_names_matching(self, pattern: str) -> list[str]:
        rx = re.compile(pattern)
        names = set(self.dotenv) | set(os.environ)
        return sorted(n for n in names if rx.search(n))

    # --- network facts the generic NET/RED checks ask for; adapters override ---
    def service_ports(self) -> dict[str, int]:
        """name → port, with configured overrides applied to the framework defaults."""
        return {}

    def unauthenticated_ports(self) -> set[int]:
        """Ports whose service is configured to answer without credentials."""
        return set()

    def bind_loopback_fix(self) -> str:
        return "Bind the service to 127.0.0.1 and reach it over SSH/Tailscale, or put it behind an authenticating reverse proxy."

    def require_auth_fix(self) -> str:
        return "Put authentication in front of the service, or bind it to loopback and tunnel."


def load_settings(target: Target, plat: Platform) -> Settings:
    cached = target.meta.get("_settings")
    if cached is not None:
        return cached
    if target.framework == "hermes":
        from daemonaudit.discover.hermes_config import load_hermes_settings as loader
    elif target.framework == "openclaw":
        from daemonaudit.discover.openclaw_config import load_openclaw_settings as loader
    else:  # pragma: no cover - the registry only runs checks for known frameworks
        raise RuntimeError(f"no settings loader for framework {target.framework!r}")
    s = loader(target, plat)
    target.meta["_settings"] = s
    return s
