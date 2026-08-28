# windows-adapter — Codex report, 2026-08-27

## Scope

Implemented the Windows platform stub in `src/daemonaudit/platform/base.py` and
added native-only coverage in `tests/test_windows.py` on branch
`codex/windows-adapter`.

Implemented:

- ACL-backed synthetic `FileMode` permissions via built-in PowerShell `Get-Acl`.
- Owner, SYSTEM, and local Administrators exclusions by translated name and SID.
- Conservative handling of non-trusted allow ACEs; `posix_modes = True` so PERM
  checks run.
- Final-component no-follow reads using `CreateFileW` with
  `FILE_FLAG_OPEN_REPARSE_POINT`, handle-based attribute/size inspection, bounded
  `ReadFile`, and rejection of every reparse point.
- PowerShell `Get-Acl ... AccessToString` verification command with literal-path
  quoting.
- Native tests for ACL read/write mapping, no-follow/size behavior, stat command,
  inherited psutil methods, `%USERPROFILE%` home behavior, and bundled process
  assumptions.

## Verification

- WSL/Linux full suite: `76 passed, 5 skipped in 1.94s`.
- Windows PowerShell 5.1 live read-only probe against `C:\Windows\win.ini`:
  owner and 5 ACEs parsed successfully; a nonexistent path raised `OSError`
  rather than returning a clean ACL.
- Native Windows pytest summary: **not available in this session**. The only
  discovered `C:\Users\TL\...\WindowsApps\python.exe` is an uninstalled Store
  alias. The five Windows tests therefore remain skipped under WSL. C4 must not
  be considered fully verified until these tests run with a native win32 Python.

## Interface limitations

### 1. `FileMode` cannot distinguish a named user/group ACL from Everyone  [severity: should-fix]

The fixed interface exposes POSIX `group_*` and `other_*` bits, while Windows
ACLs contain arbitrary users and groups. Per the C4 brief, both synthetic fields
are set when any principal other than owner/SYSTEM/Administrators has the right.
This makes existing PERM checks conservative, but a grant to one named service
account can render like world access and receive the corresponding severity.
A future model should express `readable_by_untrusted_principal` and carry redacted
principal categories/counts rather than pretending the ACL is POSIX.

### 2. Static ACE inspection is conservative, not a full effective-access calculation  [severity: should-fix]

The adapter treats any non-trusted Allow ACE containing read/write rights as
exposure, even if a Deny ACE or group membership would change effective access.
Computing effective rights for every local/domain principal requires token/group
resolution beyond the fixed interface and may require domain availability.
Conservatism avoids false passes but can produce false positives; the limitation
should be documented in Windows output.

### 3. psutil elevation behavior still needs native confirmation  [severity: should-fix]

`listening_sockets()`, `process_env()`, and `children()` retain the shared psutil
implementation. It already converts socket/process access denial to
`NotSupported` where appropriate, but native tests must confirm which calls work
unelevated on the supported Windows versions. Cross-user process environments
are expected to require elevation; socket PID attribution may be incomplete.

## Things checked that are fine

- PowerShell paths are single-quoted with embedded apostrophes doubled and passed
  without a shell for ACL collection.
- PowerShell failures explicitly exit nonzero; malformed/empty JSON becomes an
  error, never a clean ACL.
- Reparse attributes are queried from the opened handle, not by re-resolving the
  pathname after open.
- File sizes are checked before allocation/read and use the shared
  `FileTooLarge` exception.
- `discover/hermes.py` already uses `Path.home() / ".hermes"`, which maps to
  `%USERPROFILE%\.hermes` under native Windows Python.
- No dependency was added and no network operation is performed.

## Native Windows handoff

From a native PowerShell prompt with Python 3.10+ and this branch checked out:

```powershell
py -m pip install -e ".[dev]"
py -m pytest -q
```

Paste the summary line here, resolve any Windows-only failure, then change C4
from `native verification pending` to `done` in `BUILD.md`.
