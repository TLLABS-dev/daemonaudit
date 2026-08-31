# OpenClaw adapter review — Codex report, 2026-08-29

## Scope

Reviewed `src/daemonaudit/discover/openclaw.py`, `openclaw_config.py`, `_json5.py`, `checks/policy_openclaw.py`, and `tests/test_openclaw.py` against `AGENTS.md` and the bundled OpenClaw 2026.7.1-2 docs/package at `/home/tl/.nvm/versions/node/v24.20.0/lib/node_modules/openclaw`.

I exercised JSON5 strings containing URLs, comment markers and colons; unterminated strings/comments; `$` keys; include depth/cycles and documented limits; node/bun/wrapper-shaped process command lines; profile/dev state attribution; default policy values; and report redaction paths.

## Findings

### 1. `$include` resolution does not enforce OpenClaw's trust boundary or documented limits  [severity: blocker]

- **Where:** `src/daemonaudit/discover/openclaw_config.py:56-92`
- **What:** The scanner accepts arbitrary absolute paths and `../` traversal, caps files at 8 MiB instead of 2 MiB, stops at depth 3 instead of 10, and detects cycles only by exhausting that smaller depth. OpenClaw 2026.7.1-2 permits includes only inside the top-level config directory or explicit `OPENCLAW_INCLUDE_ROOTS`, caps each include at 2 MiB, permits 10 nested levels, and reports circular includes distinctly. Non-string include specs and included non-object roots are also silently ignored here.
- **Why it matters:** The scanner can read and classify a file OpenClaw would reject, while failing to inspect valid levels 4-10 that OpenClaw loads. Both directions produce incorrect policy results. An attacker-controlled config can also make an audit read files outside the target's configured include roots. The depth note prevents a clean pass, but it does not prevent findings from being computed from a materially different effective config.
- **Suggested fix:** Carry the resolved top-level include root set through `_resolve_includes`; reject paths outside it after canonicalisation, reject invalid spec/root types with coverage notes, track a canonical active-path stack for cycles, use a 2 MiB per-file cap, and set the nesting limit to 10. Add cases for an allowed external root, `../` rejection, an explicit cycle, levels 4 and 10, level 11, and files immediately below/above 2 MiB.

### 2. `OPENCLAW_CONFIG_PATH` can attach the live config to an unrelated backup target  [severity: blocker]

- **Where:** `src/daemonaudit/discover/openclaw.py:65-72`
- **What:** `config_path()` accepts an external `OPENCLAW_CONFIG_PATH` whenever the scanned home has no local `openclaw.json`: `p.parent == home or not (home / "openclaw.json").exists()`. That second branch contradicts the adjacent comment that the override is honored only for the home it belongs to.
- **Why it matters:** Scanning a copied/legacy home recognized through `agents/` plus `credentials/` can read the operator's live config outside the requested target, build the backup's layout and policy findings from it, and potentially enumerate its external workspaces/includes. This is the same cross-target attribution class that M4 explicitly fixed for processes.
- **Suggested fix:** Honor an external config path only when discovery has evidence that it belongs to this target (for example, the target is the state dir selected by the current OpenClaw environment), or require `p.parent == home` for explicit `--home` scans. Add a regression test with an external env override, a recognized config-less backup home, and a separate live home.

### 3. Unterminated JSON5 strings and block comments can normalize into valid JSON  [severity: should-fix]

- **Where:** `src/daemonaudit/discover/_json5.py:19-57`
- **What:** The normalizer does not check whether its string or block-comment scan found a terminator. Demonstrations: `loads("'unterminated")` returns the string `"unterminated"`, and `loads("{} /* unterminated")` returns `{}`. Valid strings containing `//`, `/*`, `:`, and unquoted `$key` worked correctly.
- **Why it matters:** A truncated or partially-written config can be treated as successfully parsed. In the block-comment case policy checks run against the surviving prefix without a coverage note, violating the no-false-pass invariant.
- **Suggested fix:** Raise `ValueError` when `j >= n` for a quoted string or `find("*/") < 0` for a block comment. Pin both reproductions in `test_json5_loader`; the existing `{ nope` case does not exercise the normalizer's silent-repair paths.

### 4. Per-agent sandbox overrides are ignored by POL-003  [severity: blocker]

- **Where:** `src/daemonaudit/checks/policy_openclaw.py:225-266`; helper support exists at `src/daemonaudit/discover/openclaw_config.py:115-118`
- **What:** `unsandboxed()` evaluates only `agents.defaults.sandbox`, global `tools.exec`, and the default Docker settings. It never iterates `agents.list[]`, even though OpenClaw supports per-agent `sandbox` and `tools.exec` overrides and `sandbox_mode(scope)` was written for this purpose. A default of `sandbox.mode: all` with one agent overriding `sandbox.mode: off` therefore passes this check; per-agent dangerous Docker settings are similarly missed.
- **Why it matters:** One content-reachable agent can execute on the host while POL-003 reports no host-execution finding. That suppresses the `exec:host` tag used by attack-path rules, so both the weakness and its blast-radius chain disappear.
- **Suggested fix:** Compute the effective sandbox/exec/Docker policy for the default scope and every agent, emit consolidated evidence naming affected agent ids, and tag the finding `exec:host`. Add a restrictive-default/lax-agent regression plus the inverse (lax default/tight agent) to prevent over-reporting.

### 5. C5's default-install and process-attribution matrices are not pinned  [severity: should-fix]

- **Where:** `tests/test_openclaw.py:113-293`
- **What:** The tests cover one node command line and a foreign shell string, but not bun, `--dev`, named profiles, `--profile=...`, wrapper installs, or inaccessible process environments. The supposed default-home test uses only `{gateway:{mode:"local"}}`; there is no onboard-shaped token/loopback/pairing/group-allowlist/redaction fixture, nor an assertion that bundled npm skills are labeled `(bundled)`. SecretRef objects are not directly tested in POL-010 (only `${VAR}` strings are).
- **Why it matters:** These are the highest-risk assumptions in the adapter and were explicit acceptance criteria for C5. In particular, `GATEWAY_RE` does not match a wrapper command such as `/home/me/.local/bin/openclaw-doppler gateway ...`; whether that is correct depends on the wrapper having already `exec`'d its eventual OpenClaw/Node child. A regression in child discovery or environment access could silently detach the daemon and disable listener/probe attribution.
- **Suggested fix:** Add a parameterized attribution matrix with expected ownership for node, bun, dev, both profile flag forms, `OPENCLAW_STATE_DIR`, and the documented `OPENCLAW_WRAPPER` lifecycle. Add an onboard-shaped home asserting the expected two MEDIUM defaults and no unintended policy findings, copy one installed bundled skill byte-for-byte to verify `(bundled)`, and cover all three canonical SecretRef object sources (`env`, `file`, `exec`) with raw-value absence assertions.

## Things I checked that are fine

- Bundled docs and package code confirm the assumed defaults: gateway bind `loopback`, exec `security=full` / `ask=off`, sandbox `off`, DM policy `pairing`, group policy `allowlist`, `logging.redactSensitive="tools"`, and `update.checkOnStart=true`.
- Strict JSON is attempted first, and valid JSON5 strings containing URLs/comment markers/colons are preserved; `$` is accepted in unquoted keys.
- Parse failures and unreadable/depth-limited includes add coverage notes rather than silently producing a clean pass.
- Include files use no-follow reads and explicit symlinks are rejected.
- Process ownership fails closed when a process cannot be attributed. Node and bun command lines containing the installed package path match; `--profile` is promoted by OpenClaw itself to `OPENCLAW_PROFILE`, and `--dev` is handled.
- `gateway_auth_mode()` recognizes literal, environment, and object-shaped gateway credentials without placing their values in evidence.
- POL-010 evidence is built only from `RedactedSecret` display/fingerprint data. The end-to-end terminal/JSON/HTML test covers fake xAI, GitHub, Telegram, Anthropic, and gateway credentials.
- Framework-specific ids are unique per framework and generic checks consume `Layout`; no OpenClaw home path was hard-coded into generic checks.
- Vault files are excluded from sprawl, workspace skill/context roots are layout-driven, and symlink escape coverage is present.

## Open questions for Claude

- Should `OPENCLAW_INCLUDE_ROOTS` be read only from the audited target's `.env`, or may the scanner also honor its own shell environment? Using the audit shell environment could repeat the cross-target problem in finding 2; target `.env` appears safer and closer to the daemon's effective configuration.
- For a configured wrapper that remains as a parent and spawns rather than execs the gateway despite the documented contract, should discovery intentionally ignore the wrapper and rely on the Node child, or attribute both for process-tree/socket coverage?
