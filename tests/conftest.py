import os
import stat
from pathlib import Path

import pytest

# Obviously fake, but shaped so the detectors fire. Never use real keys in fixtures.
FAKE_ANTHROPIC = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000"
FAKE_GITHUB = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00"
FAKE_TELEGRAM = "123456789:AAFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0"


def _w(p: Path, content: str | bytes, mode: int) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content)
    os.chmod(p, mode)
    return p


@pytest.fixture
def hermes_home(tmp_path: Path) -> Path:
    """A fake ~/.hermes with one of everything we want to catch."""
    h = tmp_path / ".hermes"
    h.mkdir()
    os.chmod(h, 0o700)
    _w(h / ".env", f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\nGITHUB_TOKEN={FAKE_GITHUB}\n", 0o600)
    _w(h / "auth.json", '{"anthropic": {"token": "' + FAKE_ANTHROPIC + '"}}', 0o644)  # PERM-001 HIGH
    _w(h / "config.yaml", "model:\n  provider: anthropic\n", 0o600)
    _w(h / "config.yaml.bak.20260827", f"model:\n  api_key: {FAKE_ANTHROPIC}\n", 0o644)  # PERM-002 HIGH + SEC-001 HIGH
    _w(h / "state.db", b"SQLite format 3\x00" + b"\x00" * 64 + FAKE_TELEGRAM.encode() + b"\x00" * 16, 0o644)  # SEC-001 HIGH + PERM-001 MED
    _w(h / "gateway.pid", "320\n", 0o775)  # PERM-003 group-writable + exec
    _w(h / "logs" / "agent.log", "2026-08-27 started\n", 0o600)
    (h / "runtime").mkdir()
    os.chmod(h / "runtime", 0o775)
    _w(h / "hermes-agent" / "pyproject.toml", 'version = "0.20.6"\n', 0o644)
    _w(h / "hermes-agent" / "tests" / "fixture.py", f'KEY = "{FAKE_ANTHROPIC}"\n', 0o644)  # excluded tree, must NOT be reported
    # symlink trap: a skill pointing at something outside home must be ignored
    outside = tmp_path / "outside.txt"
    _w(outside, f"TOKEN={FAKE_GITHUB}\n", 0o644)
    (h / "sessions").mkdir()
    try:
        os.symlink(outside, h / "sessions" / "evil-link")
    except (OSError, NotImplementedError):
        pass  # Windows without developer mode cannot create symlinks; POSIX-only tests still exercise the trap
    return h
