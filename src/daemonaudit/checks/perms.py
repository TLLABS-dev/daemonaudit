"""PERM-001/002/003: file permission hygiene under the daemon home."""

from __future__ import annotations

from pathlib import Path

from daemonaudit.checks._walk import rel, walk_entries, walk_files
from daemonaudit.checks.secrets import scan_file
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import Platform, q
from daemonaudit.registry import Skipped, check


def _need_posix(plat: Platform) -> None:
    if not plat.posix_modes:
        raise Skipped(f"{plat.name}: POSIX permission bits unavailable (Windows ACL support is v0.2)")


def _mode(plat: Platform, p: Path, out: CheckOutput):
    """lstat via the platform; OSError becomes a coverage note. NotSupported propagates."""
    try:
        return plat.file_mode(p)
    except OSError as e:
        out.note(f"cannot stat {p} ({e.strerror or e})")
        return None


@check("PERM-001", "Vault and private files readable by others", Position.LOCAL)
def vault_permissions(target: Target, plat: Platform) -> CheckOutput:
    _need_posix(plat)
    home, lay = target.home, target.layout
    out = CheckOutput()

    def single(path: Path, is_vault: bool) -> None:
        mode = _mode(plat, path, out)
        if mode is None or mode.is_dir or mode.is_socket or not mode.readable_by_others:
            return
        r_path = rel(home, path)
        if is_vault and mode.other_readable:
            sev = Severity.HIGH
        elif mode.other_readable:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
        who = "any user on the host" if mode.other_readable else "the file's group"
        what = "credentials" if is_vault else "transcripts, config or state"
        out.findings.append(
            Finding(
                check_id="PERM-001",
                title=f"{r_path} is readable by {who} (mode {mode.octal})",
                severity=sev,
                position=Position.LOCAL,
                asset=str(path),
                why=f"This file holds {what}. It should be 0600: any local process running as another user can read it as-is.",
                fix=f"chmod 600 {q(path)}",
                verify_cmd=f"{plat.stat_cmd(path)}  # expect 600",
                evidence=[f"mode {mode.octal}"],
                tags=["secret:vault-readable"] if (is_vault and mode.other_readable) else [],
            )
        )

    for name in lay.vault_files:
        p = home / name
        if p.exists():
            single(p, True)
    for d in lay.vault_dirs:
        for p in walk_files(home / d, lay.exclude_dirs, max_depth=2):
            single(p, True)
    for name in lay.private_files:
        p = home / name
        if p.exists():
            single(p, False)

    # Private directories: one finding per directory, not one per log file.
    for d in lay.private_dirs:
        dpath = home / d
        exposed: list[str] = []
        worst_other = False
        for p in walk_files(dpath, lay.exclude_dirs, max_depth=3):
            if p.suffix == ".lock":
                continue
            m = _mode(plat, p, out)
            if m is None or m.is_socket or not m.readable_by_others:
                continue
            exposed.append(f"{rel(home, p)} ({m.octal})")
            worst_other = worst_other or m.other_readable
        if not exposed:
            continue
        out.findings.append(
            Finding(
                check_id="PERM-001",
                title=f"{len(exposed)} file(s) in {d}/ readable by {'any user on the host' if worst_other else 'the group'}",
                severity=Severity.MEDIUM if worst_other else Severity.LOW,
                position=Position.LOCAL,
                asset=str(dpath),
                why=(
                    f"{d}/ holds transcripts, prompts and daemon state. Anything you or the agent said, "
                    "and any error that echoed a config value, is in here. It should be 0600."
                ),
                fix=f"find {q(dpath)} -type f -exec chmod 600 {{}} + && chmod 700 {q(dpath)}",
                verify_cmd=f"find {q(dpath)} -type f \\( -perm -g+r -o -perm -o+r \\)  # expect no output",
                evidence=exposed[:15],
            )
        )
    return out


def _original_for(path: Path, lay) -> Path | None:
    n = path.name
    for m in lay.backup_markers:
        if m.startswith(".") and m in n:
            return path.with_name(n.split(m, 1)[0])
        if not m.startswith(".") and n.endswith(m):
            return path.with_name(n[: -len(m)])
    return None


@check("PERM-002", "Backup file more permissive than its original", Position.LOCAL)
def backup_weaker_than_original(target: Target, plat: Platform) -> CheckOutput:
    _need_posix(plat)
    home, lay = target.home, target.layout
    out = CheckOutput()
    for bak in walk_files(home, lay.exclude_dirs, max_depth=2, exclude_root=lay.exclude_root_dirs):
        orig = _original_for(bak, lay)
        if orig is None:
            continue
        bmode = _mode(plat, bak, out)
        if bmode is None or bmode.is_dir:
            continue
        extra = 0
        omode_str = "n/a"
        if orig.exists():
            omode = _mode(plat, orig, out)
            if omode is not None:
                omode_str = omode.octal
                extra = bmode.extra_bits_vs(omode)
        else:
            extra = int(bmode.readable_by_others)
        if not extra:
            continue
        hits, reason = scan_file(plat, bak)
        if reason:
            out.note(reason)
        kinds = sorted({h.kind for h in hits})
        sev = Severity.HIGH if hits and bmode.other_readable else Severity.MEDIUM if hits else Severity.LOW
        r_bak = rel(home, bak)
        out.findings.append(
            Finding(
                check_id="PERM-002",
                title=f"Backup {r_bak} is {bmode.octal}; original is {omode_str}"
                + (f" — and it contains {', '.join(kinds)}" if kinds else ""),
                severity=sev,
                position=Position.LOCAL,
                asset=str(bak),
                why=(
                    "The original was locked down but its backup was not. Backups are written by migrations and "
                    "editors with the default umask, so they quietly leak what the original protects. "
                    + ("This one contains live-looking credentials." if hits else "")
                    + (" (Its contents could not be inspected.)" if reason else "")
                ),
                fix=f"chmod 600 {q(bak)}  # or delete it once you're sure you don't need it",
                verify_cmd=plat.stat_cmd(bak),
                evidence=[f"backup mode {bmode.octal}, original mode {omode_str}"] + [f"contains {k}" for k in kinds],
                tags=["secret:sprawl:readable"] if (hits and bmode.other_readable) else [],
            )
        )
    return out


@check("PERM-003", "State files writable by others or executable", Position.LOCAL)
def writable_or_executable_state(target: Target, plat: Platform) -> CheckOutput:
    _need_posix(plat)
    home, lay = target.home, target.layout
    out = CheckOutput()
    world_w: list[str] = []
    group_w: list[str] = []
    exec_data: list[str] = []
    for p in walk_entries(home, lay.exclude_dirs, max_depth=3, exclude_root=lay.exclude_root_dirs):
        m = _mode(plat, p, out)
        if m is None or m.is_socket:
            continue
        r = rel(home, p) + ("/" if m.is_dir else "")
        if m.other_writable:
            world_w.append(f"{r} ({m.octal})")
        elif m.group_writable:
            group_w.append(f"{r} ({m.octal})")
        if not m.is_dir and m.executable and p.suffix.lower() in lay.data_extensions:
            exec_data.append(f"{r} ({m.octal})")

    ext_expr = " -o ".join(f"-name '*{e}'" for e in sorted(lay.data_extensions))
    if world_w:
        out.findings.append(
            Finding(
                check_id="PERM-003",
                title=f"{len(world_w)} path(s) under the daemon home are world-writable",
                severity=Severity.HIGH,
                position=Position.LOCAL,
                asset=str(home),
                why="Any local user can replace state the daemon trusts — PID files, lock files, config, skills.",
                fix=f"find {q(home)} -perm -o+w -not -type l -exec chmod o-w {{}} +",
                verify_cmd=f"find {q(home)} -perm -o+w -not -type s -not -type l  # expect no output",
                evidence=world_w[:15],
            )
        )
    if group_w:
        out.findings.append(
            Finding(
                check_id="PERM-003",
                title=f"{len(group_w)} path(s) under the daemon home are group-writable",
                severity=Severity.LOW,
                position=Position.LOCAL,
                asset=str(home),
                why=(
                    "Members of the file's group can tamper with daemon state. On a single-user box this is "
                    "usually harmless; on a shared host it is not. It also shows the daemon is not creating "
                    "files with a tight umask."
                ),
                fix=f"find {q(home)} -perm -g+w -not -type l -exec chmod g-w {{}} +  # and consider umask 077 in the daemon's service unit",
                verify_cmd=f"find {q(home)} -perm -g+w -not -type s -not -type l  # expect no output",
                evidence=group_w[:15],
            )
        )
    if exec_data:
        out.findings.append(
            Finding(
                check_id="PERM-003",
                title=f"{len(exec_data)} data file(s) carry an executable bit",
                severity=Severity.LOW,
                position=Position.LOCAL,
                asset=str(home),
                why="A .pid/.log/.json that is executable is a sign of sloppy file creation, and a handy place to hide a payload.",
                fix=f"find {q(home)} -type f \\( {ext_expr} \\) -perm /111 -exec chmod -x {{}} +",
                verify_cmd=f"find {q(home)} -type f \\( {ext_expr} \\) -perm /111  # expect no output",
                evidence=exec_data[:15],
            )
        )
    return out
