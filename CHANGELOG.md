# Changelog

All notable changes to daemonaudit. Check ids are stable forever once shipped (AGENTS.md).

## 0.2.1 — 2026-08-30

A correctness release. Nothing new to configure; the scanner is more honest about what it could
not evaluate, and the OpenClaw adapter now matches OpenClaw's own config-loading rules.

### Fixed — invariant #4, "no false passes"
- **A config file that does not parse no longer produces `pass`.** Every policy check that reads
  `openclaw.json` (POL-001…010, ADV-001) or Hermes `config.yaml` (POL-002/003/008/009/010) now
  raises `Skipped` with the parse error as its note. Before, the loader fell back to `{}` and the
  checks evaluated *defaults*: a single unsupported token in `openclaw.json` turned POL-004 (open
  DMs, HIGH) and POL-006 (webhook token reuse, HIGH) into passes; a YAML typo did the same to
  Hermes POL-002 (`approvals.mode: off`, HIGH) and POL-009. Hermes POL-001/004/005/006/007 keep
  their `.env`-based findings and carry the parse note. The error is also visible in the Targets
  table (terminal + HTML) and in JSON `targets[].meta.config_error`. A config whose root is not a
  mapping/object is treated the same way.
- **A refused `$include` is a coverage note on every OpenClaw policy check**, so a partially
  loaded config renders `incomplete`/`fail`, never `pass`. Previously only POL-001 surfaced it.
- **JSON5 loader never "repairs" truncated input.** An unterminated string or block comment now
  raises `ValueError` (→ skip) instead of parsing as the surviving prefix (Codex C5 #3).

### Fixed — OpenClaw adapter (answers to `reviews/codex/2026-08-29-openclaw-review.md`)
- `$include` follows OpenClaw's trust boundary: paths must resolve inside the config directory or
  `OPENCLAW_INCLUDE_ROOTS` (read from the target's `.env`, never the audit shell); 10 nested
  levels (was 3); 2 MB per file (was 8 MiB); real cycle detection via the active include chain;
  non-string specs and non-object roots are noted, not ignored.
- `OPENCLAW_CONFIG_PATH` is honoured only for the environment-selected home or when it lives inside
  the scanned home. `--home` on a config-less backup no longer reads (and attributes) the live config.
- **POL-003 evaluates every agent scope** — `agents.defaults` plus each `agents.list[]` entry — for
  `sandbox.mode`, `tools.exec.host` and per-agent `sandbox.docker` overrides, in both directions
  (restrictive default + lax agent, lax default + tight agent). `sandbox.mode: non-main` is reported
  (LOW) because the main agent still executes on the host.
- JSON5: hex literals (`0x1F`), `+5`, `.5`, `5.`, `\'` inside double quotes, `\xNN` escapes, CRLF
  line continuations.

### Fixed — attribution and scope
- **Process attribution failure is reported, not silent.** When a daemon-shaped process is running
  but its environment cannot be read, the target shows `unknown — pid N could not be attributed`
  instead of `not running`; NET-001 says so (INFO) and RED-001/002 notes point at it. Both frameworks.
- **A workspace that is `$HOME`, an ancestor of it, the daemon home or `/` is not walked for secret
  sprawl** (SEC-001 gets a coverage note). Skills and context files under it are still specific paths
  and are still checked.
- **`--home` must point at a recognisable daemon home.** An arbitrary directory used to become a
  "hermes" target and get scanned as one; it now exits 3 with a message saying what was expected.
- An unreadable (not merely absent) OpenClaw `.env` is a coverage note.
- `gateway.port` / `OPENCLAW_GATEWAY_PORT` outside 1–65535 fall back to the default instead of
  being trusted.

### Packaging / docs
- Install instructions point at PyPI (`uvx daemonaudit`, `pipx install daemonaudit`).
- `Repository`, `Issues`, `Changelog` project URLs; Python 3.10–3.13 classifiers.
- README: OpenClaw screenshot next to the Hermes one; the per-check matrix is collapsible.
- Tests: 126 (was 97; `pytest -q` shows 120–121 passed depending on what the box lets a non-root user skip) — parse-error skip on both frameworks, JSON5 edge cases, include
  confinement/cycles/depth/size, `OPENCLAW_CONFIG_PATH` boundary, per-agent POL-003, a process
  attribution matrix (node/bun/`--dev`/profiles/state dir/wrapper/unreadable env), an
  `openclaw onboard`-shaped default home (only the graded-MEDIUM defaults appear, no attack path),
  SecretRef objects, workspace scoping, `--home` recognition.

## 0.2.0 — 2026-08-29

- **OpenClaw adapter.** `discover/openclaw.py` + `openclaw_config.py` (JSON5 + `$include` + `.env`),
  shared `discover/settings.py`, `Layout` grown to carry skill roots / context files / ports / probe
  paths, generic checks opened to both frameworks, `checks/policy_openclaw.py` (POL-001…010 +
  ADV-001 with the same ids and tags as Hermes), SKILL-001 multi-root + `metadata.openclaw.requires.env`,
  xAI/Groq key kinds, `--home` framework recognition, both daemons in one report.
- RED-001: an HTML UI shell served to anonymous clients is INFO, not a HIGH unauthenticated-API finding.
- Published to PyPI via Trusted Publishing.

## 0.1.0 — 2026-08-27

- Hermes Agent: SEC-001, PERM-001…003, NET-001/002, POL-001…010, SKILL-001, ADV-001, localhost-only
  RED-001…003, attack-path chaining with kill-hop and blast radius, terminal / JSON / HTML reports,
  Linux · macOS · Windows.
