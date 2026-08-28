"""Platform abstraction.

Everything OS-specific lives behind this interface so checks stay portable.
A platform that can't answer a question raises NotSupported; the registry turns
that into SKIP (see AGENTS.md: "no false passes").
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
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
    """Windows adapter.

    POSIX group/other bits are synthetic: both represent an ACL allow entry for a
    principal other than the owner, SYSTEM, or BUILTIN\\Administrators.  Treating an
    allow as exposure even when another ACE may deny it is deliberately conservative;
    an audit must not turn an ACL it cannot fully resolve into a clean result.
    """

    name = "windows"
    posix_modes = True

    # System and local Administrators, by name and well-known SID.  Get-Acl normally
    # translates SIDs to names, but disconnected/domain machines may leave a SID.
    _TRUSTED = {
        "nt authority\\system",
        "builtin\\administrators",
        "s-1-5-18",
        "s-1-5-32-544",
    }
    # System.Security.AccessControl.FileSystemRights values.
    _READ_RIGHTS = 0x0001 | 0x0008 | 0x0020 | 0x0080 | 0x20000 | 0x80000000
    _WRITE_RIGHTS = 0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x40000 | 0x40000000

    @staticmethod
    def _ps_literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _acl(self, path: Path) -> tuple[str, list[dict]]:
        """Return (owner, explicit/effective allow ACE data) via built-in PowerShell."""
        script = (
            "try{$a=Get-Acl -LiteralPath " + self._ps_literal(str(path)) + " -ErrorAction Stop;"
            "[pscustomobject]@{Owner=$a.Owner;Access=@($a.Access|ForEach-Object{"
            "[pscustomobject]@{Identity=$_.IdentityReference.Value;"
            "Type=$_.AccessControlType.ToString();Rights=[uint32]$_.FileSystemRights}})}"
            "|ConvertTo-Json -Compress -Depth 4}"
            "catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}"
        )
        try:
            cp = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as e:
            raise NotSupported(f"cannot query Windows ACL for {path}: {e}") from e
        if cp.returncode:
            msg = (cp.stderr or cp.stdout).strip().splitlines()
            raise OSError(msg[-1] if msg else f"Get-Acl failed for {path}")
        try:
            data = json.loads(cp.stdout)
            access = data.get("Access") or []
            if isinstance(access, dict):
                access = [access]
            return str(data.get("Owner") or ""), access
        except (json.JSONDecodeError, AttributeError, TypeError) as e:
            raise OSError(f"invalid Get-Acl output for {path}") from e

    def file_mode(self, path: Path) -> FileMode:
        st = os.lstat(path)
        owner, entries = self._acl(path)
        owner = owner.casefold()
        readable = writable = False
        for ace in entries:
            identity = str(ace.get("Identity") or "").casefold()
            if not identity or identity == owner or identity in self._TRUSTED:
                continue
            if str(ace.get("Type") or "").casefold() != "allow":
                continue
            rights = int(ace.get("Rights") or 0) & 0xFFFFFFFF
            readable = readable or bool(rights & self._READ_RIGHTS)
            writable = writable or bool(rights & self._WRITE_RIGHTS)

        mode = st.st_mode & ~0o077
        if readable:
            mode |= stat.S_IRGRP | stat.S_IROTH
        if writable:
            mode |= stat.S_IWGRP | stat.S_IWOTH
        return FileMode(
            mode=mode,
            is_dir=stat.S_ISDIR(st.st_mode),
            is_symlink=stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400),
            is_socket=stat.S_ISSOCK(st.st_mode),
        )

    def read_nofollow(self, path: Path, max_bytes: int) -> bytes:
        """Open a final component as a reparse point, then reject all reparse points."""
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        get_info = kernel32.GetFileInformationByHandleEx
        get_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        get_info.restype = wintypes.BOOL
        get_size = kernel32.GetFileSizeEx
        get_size.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
        get_size.restype = wintypes.BOOL
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID,
        ]
        read_file.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        handle = create_file(
            str(path), 0x80000000, 0x1 | 0x2 | 0x4, None, 3,
            0x00200000, None,  # FILE_FLAG_OPEN_REPARSE_POINT
        )
        invalid = wintypes.HANDLE(-1).value
        if handle == invalid:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            class FileAttributeTagInfo(ctypes.Structure):
                _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

            info = FileAttributeTagInfo()
            # FileAttributeTagInfo = 9. Query the opened object, not the pathname, so a
            # rename/swap after CreateFileW cannot change what these checks describe.
            if not get_info(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.FileAttributes & 0x400:
                raise OSError(f"refusing to read reparse point: {path}")
            if info.FileAttributes & 0x10:
                raise IsADirectoryError(str(path))
            size = ctypes.c_longlong()
            if not get_size(handle, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            if size.value > max_bytes:
                raise FileTooLarge(f"{path} is {size.value} bytes (> {max_bytes})")
            chunks: list[bytes] = []
            remaining = size.value + 1
            while remaining > 0:
                want = min(1 << 20, remaining)
                buf = ctypes.create_string_buffer(want)
                got = wintypes.DWORD()
                if not read_file(handle, buf, want, ctypes.byref(got), None):
                    raise ctypes.WinError(ctypes.get_last_error())
                if not got.value:
                    break
                chunks.append(buf.raw[: got.value])
                remaining -= got.value
            return b"".join(chunks)
        finally:
            close_handle(handle)

    def stat_cmd(self, path: Path) -> str:
        literal = self._ps_literal(str(path))
        # -ErrorAction Stop: a missing path must exit non-zero so the command is CI-usable.
        return f'powershell.exe -NoProfile -Command "(Get-Acl -LiteralPath {literal} -ErrorAction Stop).AccessToString"'


def get_platform() -> Platform:
    if sys.platform.startswith("win"):
        return WindowsPlatform()
    return PosixPlatform()
