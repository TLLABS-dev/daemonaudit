"""SEC-001: credentials living outside the vault.

The framework keeps credentials in its vault files (Layout.vault_files). A key
anywhere else — config, a backup, a transcript, sqlite state — is sprawl: it
survives rotation, gets copied by backups, and is usually readable by more than
the daemon.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from daemonaudit.checks._walk import rel, walk_files
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import NotSupported, Platform, q
from daemonaudit.platform.base import FileTooLarge
from daemonaudit.redact import MAX_SCAN_BYTES, Hit, find_hits, redact
from daemonaudit.registry import check


def scan_file(plat: Platform, path: Path) -> tuple[list[Hit], str | None]:
    """Return (hits, skip_reason). A non-None reason means the file was NOT inspected."""
    try:
        data = plat.read_nofollow(path, MAX_SCAN_BYTES)
    except FileTooLarge as e:
        return [], f"too large: {e}"
    except NotSupported:
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                return [], f"too large: {path}"
            data = path.read_bytes()
        except OSError as e:
            return [], f"unreadable: {path} ({e.strerror or e})"
    except OSError as e:
        return [], f"unreadable: {path} ({e.strerror or e})"
    return find_hits(data), None


def _candidate_files(target: Target):
    home, lay = target.home, target.layout
    seen: set[Path] = set()
    vault_files = {home / v for v in lay.vault_files}
    vault_dirs = [home / d for d in lay.vault_dirs]

    def in_vault(p: Path) -> bool:
        return p in vault_files or any(p.is_relative_to(d) for d in vault_dirs)

    for name in lay.sprawl_paths:
        for p in walk_files(home / name, lay.exclude_dirs):
            if p not in seen and not in_vault(p):
                seen.add(p)
                yield p
    for p in walk_files(home, lay.exclude_dirs, max_depth=2, exclude_root=lay.exclude_root_dirs):
        if p not in seen and lay.is_backup(p.name):
            seen.add(p)
            yield p


@check("SEC-001", "Credentials found outside the vault", Position.LOCAL, frameworks=("hermes", "openclaw"))
def secrets_outside_vault(target: Target, plat: Platform) -> CheckOutput:
    home, lay = target.home, target.layout
    out = CheckOutput()
    inspected = 0
    for path in _candidate_files(target):
        hits, reason = scan_file(plat, path)
        if reason:
            out.note(reason)
            continue
        inspected += 1
        if not hits:
            continue

        by_kind: dict[str, set[str]] = defaultdict(set)
        redacted: list[tuple[object, str]] = []  # (RedactedSecret, via)
        for h in hits:
            r = redact(h.kind, h.raw)
            if r.fingerprint in by_kind[h.kind]:
                continue
            by_kind[h.kind].add(r.fingerprint)
            redacted.append((r, h.via))

        try:
            mode = plat.file_mode(path)
            exposed = mode.readable_by_others
            perm_note = f"mode {mode.octal}"
        except NotSupported:
            exposed = False
            perm_note = "permissions unknown on this platform"
        except OSError as e:
            exposed = False
            perm_note = f"permissions unreadable ({e.strerror or e})"

        r_path = rel(home, path)
        is_backup = lay.is_backup(path.name)
        is_transcript = any(h in r_path for h in lay.transcript_hints)
        where = "a backup file" if is_backup else "a transcript/state file" if is_transcript else "a config file"
        kinds = ", ".join(f"{k}×{len(v)}" for k, v in sorted(by_kind.items()))
        vault = target.vault_path

        out.findings.append(
            Finding(
                check_id="SEC-001",
                title=f"Credential in {where}: {r_path}",
                severity=Severity.HIGH if exposed else Severity.MEDIUM,
                position=Position.LOCAL,
                asset=str(path),
                why=(
                    f"{kinds} found in {r_path} ({perm_note}). Credentials belong in {lay.preferred_vault} only. "
                    + ("This file is readable by other users/processes on the host. " if exposed else "")
                    + ("Backups outlive key rotation and are copied by sync tools. " if is_backup else "")
                    + ("Transcripts and state get shared, pasted and backed up without anyone treating them as secret. " if is_transcript else "")
                ),
                fix=(
                    f"Move the credential to {vault} (chmod 600), remove it from this file, "
                    "then rotate the key at the provider — assume it is already copied."
                    + (" If this backup is not needed, delete it." if is_backup else "")
                ),
                verify_cmd=f"daemonaudit scan --home {q(home)}  # SEC-001 must not list {r_path}",
                evidence=[
                    f"{r.kind}: {r.display} (fp {r.fingerprint}" + (f", via {via}" if via != "direct" else "") + ")"
                    for r, via in redacted[:10]
                ],
                secrets=[r for r, _ in redacted],
                tags=["secret:sprawl"] + (["secret:sprawl:readable"] if exposed else []),
            )
        )
    if inspected == 0 and out.coverage_notes:
        # Nothing could be read at all: that is a skip, not a clean result.
        from daemonaudit.registry import Skipped

        raise Skipped(f"no candidate file could be inspected: {out.coverage_notes[0]}")
    return out
