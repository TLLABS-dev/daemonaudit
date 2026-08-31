# BUILD.md — plan, status, and the Codex task queue

Two agents work on this repo. **Claude Code** builds `src/` during milestones 1–2.
**Codex** reviews, writes adversarial fixtures, and (milestone 3) builds the Windows
platform adapter. Both read `AGENTS.md` first. Humans read this file to see where things are.

## Milestones

| # | Scope | Status |
|---|-------|--------|
| 1 | Skeleton, model, redaction, Hermes discovery, checks SEC-001 / PERM-001..003, terminal + JSON report, tests | **done 2026-08-27** (pending Codex review) |
| 2 | NET-001/002 listeners + unix sockets; POL-001..010 (yolo/exec-ask, approvals, sandbox, allow-all users, API server, webhooks/dashboard, debug leaks, SSRF/tirith/project plugins, env passthrough, MCP literal secrets); SKILL-001 (8 categories, bundled-skill detection); ADV-001 (local update cache + acked advisories) | **done 2026-08-27** (pending Codex C3) |
| 3 | RED-001 unauth HTTP probe (localhost gate, hard-fail otherwise), RED-002 exec-time process env, RED-003 vault blast radius; `chain/rules.py` (9 rules, tag-based, foothold floor) → attack paths with kill-hop + per-kind blast radius table; `info` status; exit codes ignore INFO | **done 2026-08-27** (pending Codex C4) |
| 4 | `--html` self-contained report; mascot SVG + `assets/demo-report.svg` screenshot from `scripts/demo_home.py`; LICENSE (MIT); GitHub Actions CI on Linux/macOS/Windows × py3.10/3.12 with a demo smoke-scan + build; README; version 0.1.0 + tag | **done 2026-08-27** |
| 5 | **OpenClaw adapter** (v0.2.0): `discover/openclaw.py` + `openclaw_config.py` (JSON5 + `$include` + `.env`), shared `discover/settings.py` with per-framework dispatch, `Layout` grown to carry skill roots / context files / ports / probe paths, generic checks opened to both frameworks, `checks/policy_openclaw.py` (POL-001..010 + ADV-001 with the same ids and tags), SKILL-001 multi-root + `metadata.openclaw.requires.env`, xAI/Groq key kinds, `--home` framework recognition, both daemons in one report (`CheckResult.framework`, target column), OpenClaw demo home in CI, `tests/test_openclaw.py` (11 tests) | **done 2026-08-29** (C5 answered 2026-08-30) |
| 5.1 | **v0.2.1 — no false pass on a broken config** (both frameworks: `Settings.parse_error` + `require_config()` → `Skipped`, error in the Targets table + JSON `meta.config_error`), JSON5 loader completeness and no silent repair, C5 blockers (`$include` boundary/depth/size/cycles, `OPENCLAW_CONFIG_PATH` boundary, per-agent POL-003), attribution-failure reporting, workspace-scoping guard, `--home` recognition, PyPI-first README + CHANGELOG, `tests/test_no_false_pass.py` + 29 new OpenClaw tests | **done 2026-08-30** |
| next | generic MCP adapter, traversal-aware exposure (#1 below), exec-tree check (#2), canary-injection probe, local-Ollama semantic skill review, guided remediation with rollback, `dir_fd`-relative walking for hostile trees, scrub-only pattern set broader than finding patterns | |

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

## Lessons from M2 (2026-08-27)
- **SKILL-001's first cut cried wolf.** Against the 82 vendor skills it flagged `tmux send-keys … 'JWT tokens'` as
  exfiltration, `cat ~/.ssh/id_ed25519.pub` as a secret read, a review rubric saying "exfiltration" as injection,
  and `<!-- ascii-guard-ignore -->` as a hidden instruction. Fixes: object+destination required for "send … token … to",
  `id_*\b(?!\.pub)` (the `\b` matters — backtracking defeats a bare lookahead), imperative-to-the-agent required in comments,
  credential-*named* env reads only. Then: **bundled detection** — a flagged file byte-identical to `hermes-agent/skills/…`
  is labelled `(bundled)` and the category is downgraded one notch (never for invisible-unicode / vault requests / scripts piping to shell).
- `hermes-agent` and `bin` are excluded **only at the home root** now (`Layout.exclude_root_dirs`); a skill named
  `hermes-agent` was being swallowed. Any-depth exclusions are just venv/node_modules/__pycache__/.git.
- Settings come from `discover/hermes_config.py`: config.yaml + .env + (fallback) the audit shell env, with source
  tracking. Findings show env var *names* and policy values, never credential values.
- NET-001 attributes sockets to the gateway **and its children** (the node sidecar is a child). psutil `net_connections`
  needs root on macOS → NotSupported → `skip`, honestly.
- ADV-001 reads Hermes's own `.update_check` cache. Zero egress preserved.
- Real box after M2: 0 high · 5 medium · 9 low · complete · 1.2 s. The mediums: unsandboxed local backend, world-readable
  state/logs/history (Hermes umask), and nothing else.

## Decisions recorded from C3 (2026-08-27)
- SKILL-001 normalises before matching: scripts (continuations, quote-splitting, `+` concat, simple `VAR=` substitution),
  docs (NFKC, homoglyphs, default-ignorables incl. soft hyphen, link text, bounded base64), Python via stdlib `ast` taint.
- Credentials are two-tier: `MASTER_ENV` names (Hermes's own provider/platform keys) are risk; scoped names are inventory.
- Frontmatter is parsed as YAML; `metadata:` declarations are parsed but tagged non-runtime and graded down (Hermes reads top level only).
- `DEFENSIVE` vocabulary suppresses injection matches on lines that discuss attacks — a known, documented evasion trade-off.
- Binary files (by extension or NUL sniff) are never scanned by doc heuristics. Scrub's blob pattern excludes `/` so paths survive.
- Every C3 fixture row is enforced; the corpus is SKILL-001's regression floor.

## Lessons from M3 (2026-08-27)
- `/proc/<pid>/environ` is the **exec-time** environment. Hermes loads `.env` after start, so RED-002 came back
  clean on a box whose daemon plainly holds keys. The check now says exactly what it proved; RED-003 (read the vault
  as a same-user process) is the real local blast-radius number.
- INFO-only findings used to mark a check `fail` and would have exited 1 on a clean box. New status `info`;
  `ScanReport.actionable` excludes INFO from exit codes and counts.
- First chain run produced two "attack paths" on the default install, both footed on the vendor's own `curl | bash`
  install docs (bundled, LOW). Rule now: hop 1 ≥ MEDIUM, intermediates ≥ LOW, final hop any. Default install → 0 paths.
- The localhost gate is one function (`probes/red._assert_local`) and it is tested against public IPs and hostnames.
  Every probe goes through `_http_get()` which calls it first. Keep it that way.
- Real box with `--red`: 0 high · 5 medium · 10 low · 0 paths · vault = 5 credentials / 3 kinds (JWTs in auth.json).

## Releasing to PyPI (Trusted Publishing)
The `publish` job in `.github/workflows/ci.yml` runs on any `v*` tag and publishes via OIDC —
no API token is stored anywhere. One-time setup on pypi.org, then every `vX.Y.Z` tag publishes.

**One-time (user, on pypi.org, logged in):** Account → *Publishing* → *Add a pending publisher*:
- PyPI Project Name: `daemonaudit`
- Owner: `TLLABS-dev`   Repository: `daemonaudit`
- Workflow name: `ci.yml`   Environment: `pypi`

Then in the GitHub repo: Settings → Environments → **New environment** named `pypi` (no secrets needed).
To publish v0.1.0 after that: re-push the tag so CI re-runs with the publish job present —
`git push origin :refs/tags/v0.1.0 && git push origin v0.1.0` (delete + repush). Future releases:
bump `version` in pyproject.toml + `__init__.py`, tag `vX.Y.Z`, push the tag.

Release checklist: bump `pyproject.toml` + `__init__.py`, add the `CHANGELOG.md` entry, regenerate the two README
screenshots (fake demo homes under `$HOME`, deleted afterwards; grep the SVGs for `home/`, `FAKE`, `/tmp/`), run
`pytest` and a `--red` scan of the real homes, commit, tag `vX.Y.Z`, push master and the tag.

Token fallback (if Trusted Publishing is ever a problem): add a `PYPI_API_TOKEN` repo secret and
give the publish step `with: { password: ${{ secrets.PYPI_API_TOKEN }} }`. Trusted Publishing is preferred.

## v0.2 backlog — gaps from the 2026-08-27 self-audit (manual audit of the real WSL2 ~/.hermes)

Found by a hand audit that daemonaudit's 21 checks missed. Ranked; the first two are correctness, not features.

1. **[correctness] Traversal-aware exposure.** PERM-001 calls a 644 file "readable by any user on the host"
   from the file's own mode alone. On the real box `~/.hermes` is 700 and `/home/tl` is 750, so no other
   user can reach those files — the finding is a false over-report. Fix: walk the parent-directory chain;
   a file is only "other-reachable" if every ancestor grants o+x (and "group-reachable" likewise). Downgrade/
   reword when the chain blocks it. Keep a lower-severity "defense-in-depth: loosen the dir and this leaks" note.
2. **[coverage] Scan the framework's own executable tree.** `exclude_root_dirs={hermes-agent,bin}` means the
   venv, interpreter, and bin/ tools — the code that runs AS the daemon — are never permission-checked. Real
   box had `hermes-agent/venv/.lock` world-writable (666) and venv bins group-writable (775). Add a dedicated
   check for writable-by-others files *inside* the excluded exec trees (writable code = code execution as you),
   separate from the user-data PERM checks, so we don't re-introduce the __pycache__ noise into PERM-003.
3. **[root-cause] umask + systemd hardening.** The daemon runs `Umask 0002` — the single cause of every 644/775
   finding. Report the root cause once, not N symptoms, and point at the fix location: `UMask=0077` in the
   `hermes-gateway.service` unit. Also add a check that the unit has hardening directives (UMask, ProtectHome,
   ProtectSystem, NoNewPrivileges, PrivateTmp) and runs as a non-root user. Today we only grep units for --yolo.
4. **[category] Dependency CVE scan.** daemonaudit does no dependency vuln scanning; ADV-001 only reads Hermes's
   own advisory cache. Add an optional `pip-audit`-style pass over the venv (offline DB or vendored advisory set
   to preserve zero-egress; or clearly gate a network mode behind a flag that defaults off).
5. **[nuance] WSL loopback caveat.** NET-001 labels a 127.0.0.1 listener "safe, loopback-only." True in WSL2 NAT
   mode (the real box: eth0 172.20.x), but WSL *mirrored* networking shares localhost with Windows, so a loopback
   bind is reachable by Windows processes. Detect WSL + networking mode (/proc, .wslconfig) and add the caveat.
6. **[scope] Secrets the agent can reach outside HERMES_HOME.** With `backend: local` the agent runs as you and
   can read `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, and provider keys exported
   in shell rc. daemonaudit only scans under HERMES_HOME. Add an opt-in host-secrets sweep of these well-known
   locations (report presence + perms, never values). Real box was clean (only known_hosts), but the blind spot is real.

Note (tool was right, keep as a regression anchor): the self-audit's naive grep "found" ghp_/xoxb-/xapp- in .env
that were actually comments/placeholders; the placeholder filter (C2) correctly ignored them and RED-003's vault
inventory was accurate. Don't "fix" detection toward matching that grep.

## Lessons from M4 (2026-08-27)
- **Process attribution was too loose.** `find_processes("hermes_cli")` substring-matches any command
  line mentioning the string — including daemonaudit's own shell wrapper. Discovery now requires a
  *python interpreter running hermes_cli* (`GATEWAY_RE`) AND that the process belong to the home being
  scanned (path in cmdline, or matching `HERMES_HOME`). Scanning a demo/backup home no longer probes the
  real daemon. Test fixtures were unrealistic (fake gateway cmdlines lacked the venv path); fixed.
- Screenshot + demo home use only FAKE credentials (`scripts/demo_home.py`); the screenshot is rendered
  from a home under `$HOME` and deleted, so no scratch path leaks into the committed SVG.
- HTML report is one file: inlined CSS, no `<script>`, no external asset, light/dark via prefers-color-scheme,
  everything scrubbed + HTML-escaped. Test asserts no raw secret and no `http(s)://` in the output.
- PyPI publish is wired but commented in CI — needs the project created + Trusted Publisher. `uvx --from git+…`
  works today. *(Superseded: Trusted Publishing has been live since v0.1.0; `uvx daemonaudit` is the install path.)*

## Lessons from C4 native verification (2026-08-27)
- **There is no Hermes on the Windows side of TLlabs.** No `%USERPROFILE%\.hermes`, no `HERMES_HOME`, no process.
  The "PowerShell" Hermes is the WSL install reached through Windows Terminal. `daemonaudit scan` on native
  Windows correctly exits 3. Real installs to audit: WSL2 and the Mac. The Windows box's job is the adapter.
- Windows Python defaults to cp1252 for `read_text()/write_text()`. Every test touching a non-ASCII fixture
  must pass `encoding="utf-8"`. The scanner itself reads bytes and is unaffected.
- PowerShell non-terminating errors exit 0. Any generated PowerShell verify command needs `-ErrorAction Stop`.
- WSL can drive the Windows side (`powershell.exe` from bash); a fresh WSL session is needed to see PATH
  changes made on Windows after the session started — use full interpreter paths instead.
- Follow-up: the `posix_only` markers now skip PERM/SEC tests on Windows even though `posix_modes=True`;
  port those fixtures to `icacls` so the checks are exercised natively (v0.2, with the richer principal model).

## Lessons from M5 — the OpenClaw adapter (2026-08-29)
- **Same id, per-framework implementation.** POL-001 means "approval bypassed" on both frameworks; the registry now allows one
  implementation per framework for an id (never two for the same framework). Chain rules never changed: tags are the contract.
- **OpenClaw's config is JSON5 and mid-migration.** `openclaw.json` allows comments/trailing commas/unquoted keys (`discover/_json5.py`,
  strict JSON first, normaliser on failure — no new dependency). The 2026.7 release is moving `auth-profiles.json`, `exec-approvals.json`,
  `devices/paired.json`, `update-check.json` into `state/openclaw.sqlite`; the layout lists both the legacy files and the DB, and
  ADV-001 says honestly that staleness is not assessed when the cache file is gone.
- **The vault can live inside a sprawl path.** `agents/<id>/agent/auth-profiles.json` sits under `agents/`, which SEC-001 walks for
  transcripts. SEC-001 now skips anything in `vault_files`/`vault_dirs` — otherwise the vault reports itself as sprawl.
- **A 2xx is not always a finding.** The gateway serves its Control UI at `/` and `/health` to anyone by design; RED-001 takes
  `Layout.http_ui_paths` and reports those as INFO ("UI shell served; policy checks are the authority") instead of HIGH. Real API paths
  (`/v1/models`, `/tools/invoke`, `/metrics`) are still probed for anonymous 2xx.
- **The no-approval default is graded MEDIUM, not HIGH.** OpenClaw ships `tools.exec.security=full, ask=off` and documents it as the
  trusted-single-operator default; daemonaudit reports it (with "(default)" in the evidence) at MEDIUM and only HIGH when set explicitly.
  Same reasoning as Hermes POL-003 on `terminal.backend: local`. `exec-approvals.json` can only tighten — mirrored in `_scopes()`.
- **Cross-check against the vendor's audit.** On the real box `openclaw security audit` reported `gateway.loopback_no_auth` (critical) +
  `gateway.http.no_auth`; daemonaudit's POL-005 said the same thing (HIGH, tag `net:unauth`) and additionally flagged the 644 session
  transcripts that the vendor audit did not. Findings name the matching OpenClaw checkId in `why` so users can map the two.
- **Real box (fresh OpenClaw 2026.7.1-2, not running):** 1 high (gateway has no auth configured at all — onboarding was skipped) ·
  3 medium (session jsonl 644, exec full/off default, sandbox off) · 0 low · 1 attack path (local unauth service → tools → vault). Zero
  check errors; the Hermes scan on the same box was unchanged.
- **Bundled skills live in the npm package**, not under the home: `Layout.bundled_skills_dir` may now be absolute (pathlib joins an
  absolute path by replacing the base). Package root is found from a running gateway's cmdline, `$OPENCLAW_PACKAGE_ROOT`, or `which openclaw`.
- **The gateway log is outside the home** (`/tmp/openclaw/openclaw-*.log` by default). Discovery lists the last seven as `private_files`
  so PERM-001 grades them; nothing else in the tool looks outside the home.

## Lessons from v0.2.1 (2026-08-30)
- **"Loader falls back to `{}`" is a false pass in disguise.** Both config loaders swallowed a parse error into a note that
  only POL-001 surfaced; every other policy check then evaluated defaults and reported `pass`. An external reviewer
  reproduced it on 0.2.0 with one JSON5 hex literal (POL-004 open DMs HIGH → pass); Codex C5 #3 had predicted the same
  class. The fix is structural, not per-check: `Settings.parse_error` is set by the loader, `require_config()` raises
  `Skipped`, and the OpenClaw `_s()` helper calls it for every check. A new check that reads config gets the gate for free.
- **A normaliser that "repairs" is a normaliser that lies.** `_json5` found no terminator and carried on; a truncated
  config parsed as its prefix. Loaders must fail loudly on anything they did not fully understand.
- **Match the vendor's loader, not a stricter or looser one.** `$include` was capped at depth 3 / 8 MiB with no boundary;
  OpenClaw does 10 / 2 MB / config-dir-only. Either direction of mismatch computes findings from a config the daemon
  does not run with. The boundary roots come from the target's `.env`, never the audit shell (same reasoning as M4's
  process attribution and C5 #2's `OPENCLAW_CONFIG_PATH`).
- **"Not running" and "can't tell" are different facts.** `_belongs_to` returned `False` when the process environment was
  unreadable, so a locked-down box showed the gateway as absent and the RED probes quietly did less. It is tri-state now;
  the target table says `unknown — pid N could not be attributed`, and NET-001/RED-* point at it.
- **`--home` scanned anything.** `discover_hermes` accepted any directory; `daemonaudit scan --home /etc` produced a
  "hermes" target. Both adapters now require a recognisable home; otherwise exit 3 with the expected markers named.
- Real box after 0.2.1 (both daemons running): Hermes results byte-identical to 0.2.0; OpenClaw differs only by the
  POL-003 retitle and the already-landed RED-001 UI-shell change. Zero check errors on either.

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

### C3 — Evasion fixtures for skill heuristics  `[closed 2026-08-27 → reviews/codex/2026-08-27-evasion-skills.md · answered in reviews/claude/2026-08-27-evasion-skills.md — all 15 rows enforced]`  (M2 shipped SKILL-001 — go)
`src/daemonaudit/checks/skills.py`. It is regex-only by design (v0.1); your job is to show where regex
is not enough and pin it. Two directions, both matter:
1. **Evasions** (false negatives): fixtures under `tests/fixtures/evasion-skills/<skill>/` + `tests/test_evasion_skills.py`,
   `xfail` per row like C2. Ideas: `curl … | sh` split across lines / variables / `$(…)` / `eval` / python `subprocess`;
   network calls via `python -c`, `nc`, `openssl s_client`, DNS exfil; secret reads via `cat $HOME/."env"`, `find ~ -name '*.env'`,
   `env | grep`, `printenv`; injection phrasing with homoglyphs, markdown link text, split words, base64 in SKILL.md;
   frontmatter tricks (`required_environment_variables` as YAML block list, quoted, or in a `metadata:` subtree);
   `required_credential_files` pointing at the vault via `../`.
2. **False positives** (the harder problem — a default Hermes install has 82 vendor skills and the tool must not cry wolf):
   build fixtures from *legitimate* patterns you'd expect in real skills — API clients reading their own key, install
   docs, review rubrics that mention "exfiltration", `id_*.pub` public keys, HTML comment markers — and assert **no**
   finding. Note `_is_bundled()` downgrades vendor-identical files; test that a modified vendor file is NOT downgraded.
Report: `reviews/codex/YYYY-MM-DD-evasion-skills.md` with a detection matrix like C2. No `src/` edits.
Same idea against the skills scanner: `SKILL.md` and scripts that hide `curl | sh`, network calls, secret reads, and invisible-Unicode instructions in ways a regex misses.

### C5 — OpenClaw adapter review  `[closed 2026-08-29 → reviews/codex/2026-08-29-openclaw-review.md · answered in reviews/claude/2026-08-29-openclaw-review.md — all 5 items fixed in v0.2.1]`
Review `src/daemonaudit/discover/openclaw.py`, `openclaw_config.py`, `_json5.py`, `checks/policy_openclaw.py` and `tests/test_openclaw.py`
against AGENTS.md. Same brief as C1, plus:
1. **Defaults.** Every "default" the checks assume (bind loopback, auth required, exec full/off, sandbox off, dmPolicy pairing, groupPolicy allowlist,
   redactSensitive tools) against the bundled docs at `node_modules/openclaw/docs` (2026.7.1-2). A wrong default is a false pass or a cry-wolf.
2. **JSON5 loader.** Break `_json5.loads()`: strings containing `//`, `/*`, `:`; unquoted keys with `$`; nested `$include` cycles; a 2 MB include.
   The loader must fail loudly (ValueError → coverage note), never silently return `{}` as "clean".
3. **Process attribution.** `GATEWAY_RE` + `_belongs_to()` with `--profile`, `--dev`, `OPENCLAW_STATE_DIR`, a wrapper (`OPENCLAW_WRAPPER`), bun.
4. **False positives on a default install.** Build a home with `openclaw onboard`-shaped config (token auth, loopback, pairing) and make sure only
   the graded-MEDIUM defaults appear. Vendor skills from the npm package must be `(bundled)`.
5. **Redaction.** `POL-010` walks every string in the config; confirm nothing raw reaches evidence (the fp/display path), including SecretRef objects.
Output: `reviews/codex/YYYY-MM-DD-openclaw-review.md`. Do not edit `src/`.

### C4 — Windows platform adapter  `[done 2026-08-27 — natively verified: 64 passed / 17 skipped on Windows 3.12.10]`
`src/daemonaudit/platform/base.py` → new `WindowsPlatform` (replace the stub). Interface is fixed; report anything it can't express rather than changing it.
Scope, in order:
1. `file_mode()` semantics on ACLs: `FileMode.other_readable/other_writable/group_*` should mean "a principal other than the owner, SYSTEM and Administrators has that right". Use `ctypes`/`win32security` only if stdlib can't — prefer stdlib (`subprocess icacls` parsing is acceptable as a first cut if documented). `posix_modes = True` once this works, so PERM-* checks run.
2. `read_nofollow()`: open with `FILE_FLAG_OPEN_REPARSE_POINT` semantics or reject reparse points — never follow a junction/symlink at the final component.
3. `stat_cmd()`: a PowerShell one-liner printing the ACL (`(Get-Acl <path>).AccessToString`).
4. `listening_sockets()` / `process_env()` / `children()`: verify psutil behaves; document what needs elevation.
5. Hermes home on Windows is `%USERPROFILE%\.hermes` — confirm `discover/hermes.py` finds it (`Path.home()` should).
Tests: `tests/test_windows.py`, skipped unless `sys.platform == "win32"`. Run the full suite on the Windows box and paste the summary line into the report. Branch `codex/windows-adapter`. Report: `reviews/codex/YYYY-MM-DD-windows-adapter.md`.

## Claude's queue (for the record)
- M2 checks, in the order listed in the milestone table; `NET-001` listening sockets first because it's the only remote-position check and the report is lopsided without it.
- Answer C1 in `reviews/claude/` before starting M2 if the report is in by then.
