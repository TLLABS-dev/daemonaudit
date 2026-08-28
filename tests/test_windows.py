"""Native Windows coverage for the ACL/reparse-point platform adapter."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from daemonaudit.discover.hermes import hermes_home
from daemonaudit.platform.base import FileTooLarge, NotSupported, WindowsPlatform


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows only")


def _icacls(path: Path, *args: str) -> None:
    subprocess.run(["icacls", str(path), *args], check=True, capture_output=True, text=True)


def test_acl_modes_exclude_owner_system_and_administrators(tmp_path: Path) -> None:
    path = tmp_path / "private.txt"
    path.write_text("FAKE fixture")
    user = os.environ.get("USERNAME")
    assert user
    _icacls(path, "/inheritance:r", "/grant:r", f"{user}:F")
    plat = WindowsPlatform()
    private = plat.file_mode(path)
    assert not private.readable_by_others
    assert not private.group_writable and not private.other_writable

    _icacls(path, "/grant", "*S-1-1-0:R")
    readable = plat.file_mode(path)
    assert readable.group_readable and readable.other_readable
    assert not readable.group_writable and not readable.other_writable

    _icacls(path, "/grant", "*S-1-1-0:M")
    writable = plat.file_mode(path)
    assert writable.group_writable and writable.other_writable


def test_read_nofollow_regular_size_and_reparse_point(tmp_path: Path) -> None:
    plat = WindowsPlatform()
    path = tmp_path / "data.txt"
    path.write_bytes(b"FAKE data")
    assert plat.read_nofollow(path, 100) == b"FAKE data"
    with pytest.raises(FileTooLarge):
        plat.read_nofollow(path, 2)

    link = tmp_path / "link.txt"
    try:
        link.symlink_to(path)
    except OSError as e:
        pytest.skip(f"creating symlinks requires Developer Mode or elevation: {e}")
    with pytest.raises(OSError, match="reparse point"):
        plat.read_nofollow(link, 100)


def test_stat_cmd_uses_literal_path_and_escapes_quotes(tmp_path: Path) -> None:
    cmd = WindowsPlatform().stat_cmd(tmp_path / "it's FAKE.txt")
    assert "Get-Acl -LiteralPath" in cmd
    assert "it''s FAKE.txt" in cmd
    cp = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    assert cp.returncode != 0  # nonexistent path, but PowerShell parsed the quoted command


def test_psutil_windows_methods_smoke() -> None:
    plat = WindowsPlatform()
    try:
        sockets = plat.listening_sockets()
    except NotSupported as e:
        pytest.skip(f"socket enumeration requires elevation on this host: {e}")
    assert isinstance(sockets, list)
    assert isinstance(plat.process_env(os.getpid()), dict)
    assert isinstance(plat.children(os.getpid()), list)


def test_default_hermes_home_uses_user_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("HERMES_HOME", raising=False)
    assert hermes_home() == Path.home() / ".hermes"
