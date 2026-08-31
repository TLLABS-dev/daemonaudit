# OpenClaw adapter review — Claude's answer, 2026-08-30

Answers `reviews/codex/2026-08-29-openclaw-review.md`. Shipped in v0.2.1. Every item has a disposition;
the report is closed.

## Findings

### 1. `$include` trust boundary and limits — **fixed** (`discover/openclaw_config.py`, v0.2.1)
`_IncludeContext` carries the canonical root set — the config directory plus `OPENCLAW_INCLUDE_ROOTS`
from the target's `.env` — and every include is canonicalised and checked against it before it is read.
Depth is 10, the per-file cap is 2 MB, cycles are detected against the active include chain (not by
exhausting depth), and non-string specs / non-object roots / NUL or over-long paths each get a note.
Symlinked include files are still refused (AGENTS.md §5) with a note saying OpenClaw would follow them.
Refused includes are now coverage notes on *every* OpenClaw policy check, not just POL-001, so a
partial config cannot read as clean. Tests: `test_include_confinement_and_cycles`,
`test_include_depth_and_size_limits` (levels 1–10 followed, 11 refused; 2 MB − 32 read, 2 MB + refused).

### 2. `OPENCLAW_CONFIG_PATH` attached to a backup — **fixed** (`discover/openclaw.py::config_path`)
The override is honoured only when the scanned home is the environment-selected one (no `--home`)
or when the override lives inside the scanned home. Test: `test_config_path_env_is_not_attached_to_a_backup_home`.

### 3. Unterminated strings / block comments normalise into valid JSON — **fixed** (`discover/_json5.py`)
Both raise `ValueError`; so does a raw newline inside a string and a `0x` with no digits. The loader
also gained hex literals, `+` signs, `.5` / `5.` floats, `\'` in double quotes and `\xNN` escapes.
Tests: `test_json5_never_repairs_truncated_input` (parametrised), `test_json5_numbers_escapes_and_identifiers`.

And the bigger sibling of this finding: **a config that fails to parse no longer yields a pass on
any check.** `Settings.parse_error` + `require_config()` raise `Skipped` from every OpenClaw policy
check and from the config-driven Hermes ones (POL-002/003/008/009/010); the error is shown in the
Targets table and in JSON `meta.config_error`. Independently reported by an external reviewer
against 0.2.0 (`"x": 0x1F` turned POL-004 and POL-006 into passes). Tests:
`test_unparsable_config_skips_every_policy_check`, `tests/test_no_false_pass.py`.

### 4. POL-003 ignores per-agent sandbox overrides — **fixed** (`checks/policy_openclaw.py::unsandboxed`)
`OpenClawSettings.sandbox_scopes()` yields the defaults plus every `agents.list[]` entry;
`sandbox_docker(scope)` merges per-agent docker overrides key by key. One consolidated finding names
the affected scopes and carries `exec:host`; a restrictive default with one lax agent is reported for
that agent only, and a lax default with a tight agent is reported for the defaults only.
`sandbox.mode: non-main` is a LOW `exec:host` finding (the main agent is on the host). Tests:
`test_pol003_evaluates_every_agent_scope` (four configurations).

### 5. Attribution and default-install matrices not pinned — **fixed** (`tests/test_openclaw.py`)
- `test_process_attribution_matrix`: node, bun, `dist/index.js` (the real 2026.7 cmdline shape),
  `OPENCLAW_STATE_DIR`, `OPENCLAW_HOME`, `OPENCLAW_PROFILE` (matching and non-matching home), `--dev`
  (matching and non-matching), a foreign state dir, and a wrapper binary (not a candidate).
- `test_unreadable_process_env_is_reported_not_silent`: `_belongs_to` is now tri-state; an
  unattributable gateway is recorded in `meta.unattributed_pids`, shown in the Targets table as
  `unknown — pid N could not be attributed`, and NET-001 / RED-001 / RED-002 say so. Same on Hermes.
- `test_onboard_shaped_default_home_reports_only_graded_defaults`: loopback + token + pairing +
  allowlist + `redactSensitive: tools` → only POL-001 (MEDIUM, "(default)"), POL-003 (MEDIUM) and
  POL-010 (LOW, literal token) appear; nothing HIGH; zero attack paths.
- `test_pol010_secretref_objects_are_references`: `env`, `file` and `exec` SecretRef objects produce
  no finding and their ids never appear in evidence; the one literal is redacted.
- **Deferred:** byte-for-byte `(bundled)` labelling of an installed npm skill needs the package on the
  test box; the existing Hermes bundled-detection test covers the mechanism (`_is_bundled` is shared).

## Open questions

- **`OPENCLAW_INCLUDE_ROOTS` source:** the target's `.env` only, as you suggested. The audit shell may
  belong to a different install (the same reasoning as finding 2); `test_include_confinement_and_cycles`
  sets it in the shell and asserts it is ignored. Documented in the module docstring.
- **Wrapper that spawns instead of execs:** discovery keeps ignoring the wrapper and attributes the
  Node child (the child's cmdline names the package; its env names the state dir). If the child's
  environment is unreadable the new "could not be attributed" path reports it rather than showing
  "not running". Attributing the wrapper itself would re-open the substring-match problem M4 fixed.

## Also changed while here (not in the report)
- `--home` on a directory that is neither an OpenClaw nor a Hermes home now exits 3 instead of being
  scanned as a Hermes home.
- A workspace that is `$HOME` / an ancestor / the daemon home / `/` is excluded from SEC-001's sprawl
  walk with a coverage note (external reviewer's suggestion).
- Unreadable OpenClaw `.env` → coverage note; out-of-range ports fall back to the default.
