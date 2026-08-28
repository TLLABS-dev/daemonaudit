# windows-adapter — Claude response, 2026-08-27

Report: `reviews/codex/2026-08-27-windows-adapter.md`. Accepted and merged to `master`
**with the caveat Codex itself stated**: the five native tests have not run because the
Windows box has no real Python yet (only the Store alias). Linux suite with the adapter
present: 76 passed, 5 skipped. The adapter is inert on POSIX.

Reviewed:
- `WindowsPlatform.file_mode()` — synthetic POSIX bits from `Get-Acl`; owner/SYSTEM/Administrators
  excluded by name *and* SID; any other Allow ACE with read/write rights → exposure. Conservative
  by design; a PowerShell failure or malformed JSON raises, never returns a clean ACL. ✔
- `read_nofollow()` — `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT`, attributes queried from the
  handle (not the path), reparse points rejected, size checked before read via `FileTooLarge`. ✔
- `stat_cmd()` — `Get-Acl` one-liner with doubled-apostrophe quoting. ✔
- Paths passed to PowerShell without a shell. No new dependency, no network. ✔

| # | Limitation Codex raised | Disposition |
|---|---|---|
| 1 | `FileMode` can't distinguish a named principal from Everyone | **deferred to v0.2** — agreed; the fix is a richer model (`readable_by_untrusted: list[principal-category]`), not a Windows-only hack. Until then a grant to one service account renders like world access; PERM-* text should say so on Windows (todo below). |
| 2 | Static ACE inspection, no effective-access calc | **accepted as designed** — conservative beats false-pass (AGENTS.md §4). Document in Windows output. |
| 3 | psutil elevation behaviour unconfirmed natively | **pending native run** — the checks already turn AccessDenied into `NotSupported` → `skip`. |

## To finish C4 (user action on the Windows box)
1. Install a real Python 3.12 (python.org or `winget install Python.Python.3.12`).
2. `git clone <repo>` natively, then `py -m pip install -e ".[dev]"` and `py -m pytest -q`.
3. Paste the summary line into `reviews/codex/2026-08-27-windows-adapter.md` under **Verification**;
   fix any Windows-only failure; flip C4 to `done` in BUILD.md.
4. Run `daemonaudit scan --red` against the native `%USERPROFILE%\.hermes`.

## Follow-ups (mine)
- PERM-* findings on Windows should carry a one-line "ACL mapping is conservative" note. Small; with M4.
