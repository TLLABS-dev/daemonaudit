# BUILD.md — plan, status, and the Codex task queue

Two agents work on this repo. **Claude Code** builds `src/` during milestones 1–2.
**Codex** reviews, writes adversarial fixtures, and (milestone 3) builds the Windows
platform adapter. Both read `AGENTS.md` first. Humans read this file to see where things are.

## Milestones

| # | Scope | Status |
|---|-------|--------|
| 1 | Skeleton, model, redaction, Hermes discovery, checks SEC-001 / PERM-001..003, terminal + JSON report, tests | **done 2026-08-27** (pending Codex review) |
| 2 | Checks 5–16: policy (`approvals`, yolo, `terminal.backend`, `WRITE_SAFE_ROOT`), gateway/platform allowlists, API server exposure, webhook secrets, redaction flags, SSRF guard, MCP/env passthrough secrets, skills heuristics, listening sockets, advisories | next |
| 3 | Red probes (localhost only): unauth gateway/API hit, `/proc/<pid>/environ` read, protected-file read as daemon UID. Chain rules → attack paths + per-secret blast radius | |
| 4 | HTML report, README with real screenshot, `uvx` install, mascot SVG, tag v0.1.0 | |
| v0.2 | Windows ACL adapter, canary-injection probe, OpenClaw + generic MCP adapters, local-Ollama semantic skill review, guided remediation with rollback, `dir_fd`-relative walking for hostile trees, scrub-only pattern set broader than finding patterns | |

## Threat model (what every check maps to)
- **remote** — unauthenticated, on the network: exposed gateway/dashboard/API, no auth, default tokens
- **content** — controls something the agent reads: prompt injection → tool use with no allowlist/sandbox
- **supply-chain** — ships a skill / MCP server / plugin: install scripts, env passthrough, tool descriptions that instruct exfil
- **local** — another user/process on the host: file perms, secrets in transcripts/backups/process env

## How Codex and Claude hand work to each other

### Where reports go
- Codex writes every report to `reviews/codex/YYYY-MM-DD-<task-slug>.md`.
- Claude answers in `reviews/claude/YYYY-MM-DD-<task-slug>.md` with one line per item:
  `fixed (commit/diff ref)` · `rejected — <why>` · `deferred to M<n>`.
- A report is "closed" when every item has a disposition. Don't reopen closed reports; write a new one.

### Rules for Codex tasks
- **Review tasks: do not edit `src/`.** Report only. Suggested patches go in the report as diff blocks.
- **Fixture tasks:** add files only under `tests/fixtures/` and new `tests/test_evasion_*.py`. Fake secrets only (see AGENTS.md §8). A fixture that the current scanner *misses* is the goal — mark those tests `xfail` with a reason so the suite stays green until Claude patches the detector.
- **Code tasks (M3 Windows adapter):** branch `codex/<slug>`, touch only the files the task lists, run `pytest` before finishing.
- Never run the scanner against a real home and paste output into a report without checking it for secrets/chat IDs/phone numbers first. Prefer the pytest fixture home.

### Report template
```markdown
# <task slug> — Codex report, <date>

## Scope
What was reviewed / produced, with file paths.

## Findings
### <n>. <title>  [severity: blocker | should-fix | nit]
- **Where:** path:line
- **What:** one paragraph
- **Why it matters:** one paragraph
- **Suggested fix:** diff block or description

## Things I checked that are fine
Bullet list. This matters as much as the findings — it tells Claude what not to re-verify.

## Open questions for Claude
```

## Lessons from the first real run (2026-08-27, WSL2 box)
Codex: read these before C1/C2 — they are the known state, don't re-report them.
- **Two false positives shipped and were fixed the same night.** A placeholder
  (`your-password-here`) in a world-readable backup was reported as a HIGH credential leak,
  and an English hyphenated word inside `state.db` matched the `sk-` regex. Fixes: left
  boundary lookbehind on prefix patterns, `_looks_random()` (digits + mixed case) on
  non-structural kinds, broader placeholder substrings. **This is exactly the class of bug C2
  should hunt** — the detector now leans toward false negatives, and that trade-off is untested.
- `verify_cmd` uses GNU `stat -c`; macOS needs `stat -f`. Not yet platform-aware.
- PERM-001 emits one finding per *directory* for logs/sessions/etc. (was one per file —
  8 near-identical panels). Top-level files still get individual findings.
- Real result on a fresh, default Hermes 0.20.6 install: 0 high, 4 medium, 3 low. The
  mediums are all Hermes writing `state.db`, logs and history with the default umask
  (644) despite its docs saying 0600. Worth an upstream issue once we're confident.
- Dev env: no system `venv`/`pip` on this box; `uv` is at `~/.local/bin`. `uv venv --python 3.12 .venv && uv pip install -p .venv/bin/python -e '.[dev]'`.

## Decisions recorded from C1 (2026-08-27)
- Result statuses: `pass · fail · skip · off · error · incomplete`. `off` = deliberate opt-out
  (red probes without `--red`) and does not make a scan incomplete.
- Exit codes: 0 clean+complete · 1 findings · 2 high/critical · 3 no target · 4 no findings but
  incomplete · 5 tool error. Precedence 2 > 1 > 4 > 0. Source of truth: `model.EXIT_CODE_HELP`.
- Checks return `CheckOutput(findings, coverage_notes)`; anything not inspected is a note, never silence.
- `--home` may be a symlink: resolved once at discovery (`meta.home_as_given` kept). Nothing below
  the root is ever followed; reads use `O_NOFOLLOW` + `fstat`. Full `dir_fd` walking → v0.2.
- Framework layout lives in `model.Layout`, filled by `discover/<fw>.py`. Checks never import adapter constants.
- Shell snippets in findings: paths via `platform.q()` (shlex), `stat` via `Platform.stat_cmd()` (Darwin-aware).

## Decisions recorded from C2 (2026-08-27)
- Detection runs over bounded derived streams (`shell`, `nfkc`, `yaml-fold`, `nulls`, `base64`, `hex`).
  **Derived streams only yield structural/provider kinds; `generic-credential` must match as written.**
- Two randomness heuristics: prefixed (strict) vs assignment-anchored generic (relaxed) + a
  non-secret-name denylist. Change one without the other and you re-open a known bug.
- `scrub()` is deliberately broader than findings: replaces hit carriers and any 40+-char opaque blob.
- The evasion matrix is enforced (no xfails left). New evasions go in as `xfail`; promote when fixed.
- `Hit.via` is user-visible evidence; `Hit.carrier` never leaves memory.

## Codex task queue

Take the top unclaimed task. Mark it `claimed <date>` here, then `done <date> → reviews/codex/<file>` when the report is written.

### C1 — Milestone 1 review  `[closed 2026-08-27 → reviews/codex/2026-08-27-m1-review.md · answered in reviews/claude/2026-08-27-m1-review.md]`
Review everything under `src/daemonaudit/` and `tests/` against the AGENTS.md invariants. Specifically:
1. **Redaction end-to-end.** Can a raw secret reach stdout, the JSON file, a traceback, or a `rich` panel title? Trace `Finding.evidence`, `title`, `why`, `CheckResult.note` (tracebacks!), and `to_json()`. Try to construct a Finding that leaks.
2. **False passes.** Any code path where a check returns `[]` because of an error it swallowed (look at every `except OSError` / `except NotSupported` in `checks/`). Each one should be judged: is silently skipping that *file* acceptable, or should the whole check SKIP?
3. **Symlink / traversal safety.** `checks/_walk.py` and `platform/base.py`. Can a symlink inside the home make the scanner read or report a path outside it?
4. **Regex quality in `redact.py`.** False positives you'd expect on real config (e.g. `generic-credential` on `HERMES_SESSION_KEY=` style non-secrets, base64 blobs), and false negatives for common providers (OpenRouter, Google, Discord, Azure, Slack app tokens, JWTs, `Bearer …`).
5. **macOS.** Anything here that behaves differently on Darwin (psutil `net_connections` needs root on macOS; `os.lstat` fine; `stat -c` in `verify_cmd` is GNU-only — macOS is `stat -f '%A'`). Propose how `verify_cmd` should be platform-aware.
6. **Exit codes / CLI ergonomics.** Anything that would surprise someone wiring this into cron or CI.
Output: `reviews/codex/YYYY-MM-DD-m1-review.md`. Do not edit `src/`.

### C2 — Evasion fixtures for the secret scanner  `[closed 2026-08-27 → reviews/codex/2026-08-27-evasion-secrets.md · answered in reviews/claude/2026-08-27-evasion-secrets.md — all 10 rows now enforced]`
Your own C1 item #6 is the brief: the detector now leans toward false negatives (`_looks_random()` rejects lowercase-only tokens with <4 digits; `generic-credential` is keyword-context only; no Azure/Google-OAuth/Discord-bot coverage tests). Pin all of that. Write `tests/fixtures/evasion/` + `tests/test_evasion_secrets.py`: a set of files that contain credential-shaped secrets the current `redact.find_secrets()` **misses** or **mis-classifies** — split across lines, base64/hex-wrapped, in YAML block scalars, in sqlite pages with interleaved nulls, URL-embedded (`https://user:token@host`), in `.env` with `export`, quoted with backslashes, unicode look-alikes. Also files that should produce **no** hit (docs with example keys marked as examples, `${VAR}` references, `op://` refs). Every missed case is an `xfail` test with a one-line reason. Report: `reviews/codex/YYYY-MM-DD-evasion-secrets.md` summarising the detection matrix.

### C3 — Evasion fixtures for skill heuristics  `[blocked: waits for M2 SKILL-001]`
Same idea against the skills scanner once it exists: `SKILL.md` and scripts that hide `curl | sh`, network calls, secret reads, and invisible-Unicode instructions in ways a regex misses.

### C4 — Windows platform adapter  `[blocked: waits for M3]`
`src/daemonaudit/platform/windows.py`: implement `file_mode()`-equivalent semantics on top of ACLs (is the file readable/writable by users other than the owner and SYSTEM/Administrators?), plus `listening_sockets()` verification on Windows. Interface is fixed by `platform/base.py`; report anything the interface can't express rather than changing it.

## Claude's queue (for the record)
- M2 checks, in the order listed in the milestone table; `NET-001` listening sockets first because it's the only remote-position check and the report is lopsided without it.
- Answer C1 in `reviews/claude/` before starting M2 if the report is in by then.
