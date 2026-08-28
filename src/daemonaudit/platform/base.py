"""Platform abstraction.

Everything OS-specific lives behind this interface so checks stay portable.
A platform that can't answer a question raises NotSupported; the registry turns
that into SKIP (see AGENTS.md: "no false passes").
"""

from __future__ import annotations

import os
import shlex
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


class NotSupported(Exception):
    """Raised by a platform when it cannot answer; checks turn this into SKIP."""


@dataclass(frozen=True)
class FileMode:
    mode: int
    is_dir: bool
    is_symlink: bool
    is_socket: bool

    @property
    def octal(self) -> str:
        return oct(stat.S_IMODE(self.mode))[2:].rjust(3, "0")

    @property
    def group_readable(self) -> bool:
        return bool(self.mode & stat.S_IRGRP)

    @property
    def other_readable(self) -> bool:
        return bool(self.mode & stat.S_IROTH)

    @property
    def group_writable(self) -> bool:
        return bool(self.mode & stat.S_IWGRP)

    @property
    def other_writable(self) -> bool:
        return bool(self.mode & stat.S_IWOTH)

    @property
    def executable(self) -> bool:
        return bool(self.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    @property
    def readable_by_others(self) -> bool:
        return self.group_readable or self.other_readable

    def extra_bits_vs(self, other: "FileMode") -> int:
        return stat.S_IMODE(self.mode) & ~stat.S_IMODE(other.mode) & 0o077


def q(path: os.PathLike | str) -> str:
    """Shell-quote a path for verify/fix commands."""
    return shlex.quote(str(path))


class Platform:
    name = "generic"
    posix_modes = False
    is_darwin = False

    def home(self) -> Path:
        return Path.home()

    def file_mode(self, path: Path) -> FileMode:
        raise NotSupported(f"{self.name}: file permission bits not supported")

    def read_nofollow(self, path: Path, max_bytes: int) -> bytes:
        """Read a regular file without following a symlink at the final component.
        Raises OSError (incl. IsADirectoryError / FileTooLarge as OSError)."""
        raise NotSupported(f"{self.name}: no-follow reads not supported")

    def stat_cmd(self, path: Path) -> str:
        """A shell command printing '<octal mode> <path>' for verify_cmd."""
        raise NotSupported(f"{self.name}: no stat command")

    # --- process / network (psutil-backed, all OSes) ---

    def listening_sockets(self) -> list[dict]:
        try:
            import psutil
        except ImportError as e:  # pragma: no cover
            raise NotSupported("psutil not installed") from e
        out = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as e:
            raise NotSupported(f"cannot list sockets (try with elevated privileges): {e}") from e
        for c in conns:
            if c.status == psutil.CONN_LISTEN and c.laddr:
                out.append({"ip": c.laddr.ip, "port": c.laddr.port, "pid": c.pid, "family": str(c.family)})
        return out

    def process_env(self, pid: int) -> dict[str, str]:
        try:
            import psutil
        except ImportError as e:  # pragma: no cover
            raise NotSupported("psutil not installed") from e
        try:
            return psutil.Process(pid).environ()
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError) as e:
            raise NotSupported(f"cannot read environ of pid {pid}: {e}") from e

    def children(self, pid: int) -> list[dict]:
        """Descendants of pid: [{'pid','name'}]."""
        try:
            import psutil
        except ImportError:  # pragma: no cover
            return []
        try:
            return [{"pid": c.pid, "name": c.name()} for c in psutil.Process(pid).children(recursive=True)]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []

    def find_processes(self, needle: str) -> list[dict]:
        try:
            import psutil
        except ImportError:  # pragma: no cover
            return []
        out = []
        for p in psutil.process_iter(["pid", "cmdline", "username"]):
            try:
                cmd = " ".join(p.info.get("cmdline") or [])
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            if needle in cmd:
                out.append({"pid": p.info["pid"], "cmdline": cmd, "user": p.info.get("username")})
        return out


class FileTooLarge(OSError):
    pass


class PosixPlatform(Platform):
    name = "posix"
    posix_modes = True
    is_darwin = sys.platform == "darwin"

    def file_mode(self, path: Path) -> FileMode:
        st = os.lstat(path)  # never follow symlinks: a hostile skill could plant one
        return FileMode(
            mode=st.st_mode,
            is_dir=stat.S_ISDIR(st.st_mode),
            is_symlink=stat.S_ISLNK(st.st_mode),
            is_socket=stat.S_ISSOCK(st.st_mode),
        )

    def read_nofollow(self, path: Path, max_bytes: int) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"not a regular file: {path}")
            if st.st_size > max_bytes:
                raise FileTooLarge(f"{path} is {st.st_size} bytes (> {max_bytes})")
            chunks = []
            remaining = st.st_size + 1
            while remaining > 0:
                b = os.read(fd, min(1 << 20, remaining))
                if not b:
                    break
                chunks.append(b)
                remaining -= len(b)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def stat_cmd(self, path: Path) -> str:
        if self.is_darwin:
            return f"stat -f '%Lp %N' {q(path)}"
        return f"stat -c '%a %n' {q(path)}"


class WindowsPlatform(Platform):
    """v0.2: ACL-based permission checks. Until then every permission check SKIPs."""

    name = "windows"
    posix_modes = False


def get_platform() -> Platform:
    if sys.platform.startswith("win"):
        return WindowsPlatform()
    return PosixPlatform()
