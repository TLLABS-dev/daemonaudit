# daemonaudit — shared brief for every agent working here

This file is read by Codex (AGENTS.md) and by Claude Code (CLAUDE.md points here).
It holds the invariants. BUILD.md holds the plan and the task queue.

## What this is
A Python CLI that audits self-hosted AI agent daemons (Hermes Agent and OpenClaw;
generic MCP configs later) for secrets on disk, exposed ports, weak policy config
and risky skills, then reports **attack paths and blast radius**, grouped by attacker
position (remote / injected content / supply-chain / local).

## Invariants — never break these
1. **Read-only.** The scanner never modifies the host. `Remediation.apply()` is v0.2
   and is not wired to anything.
2. **Zero network egress.** No telemetry, no update checks, no "phone home". Red-team
   probes connect to **localhost only** and must hard-fail on any non-loopback target.
3. **Secrets are redacted at detection.** `RedactedSecret` has no raw-value field on
   purpose. Evidence strings are redacted. All report output passes through
   `redact.scrub()` as a safety net. A test asserts no fixture secret appears in output.
4. **No false passes.** A check that cannot run raises `Skipped` → status `skip`.
   An exception → status `error`. Neither ever renders as `pass`.
5. **Never follow symlinks** when walking the daemon home. A hostile skill can plant one.
6. **Every Finding** has `why`, `fix`, and (almost always) `verify_cmd`. If you can't
   tell the user how to verify the fix, the finding isn't done.
7. **Framework layout knowledge lives in `discover/<framework>.py` only.** Checks ask
   the Target for paths; they never hard-code `~/.hermes` or `~/.openclaw`. Generic checks
   (SEC/PERM/NET/SKILL/RED) read `Layout`; policy checks are per framework and share an id
   with the other framework's implementation when they cover the same class of weakness.
   Tags (`exec:noapproval`, `net:public`, …) are the contract with `chain/rules.py` and must
   mean the same thing on every framework.
8. **Fixtures use obviously fake secrets** (`FAKE` in the body, correct shape). Never
   commit a real key, a real chat ID, or a real phone number — not even in a report.

## Layout
```
src/daemonaudit/
  model.py       Finding / CheckResult / Target / ScanReport / RedactedSecret
  redact.py      detection patterns, display(), fingerprint(), scrub()
  registry.py    @check decorator, run_all(), Skipped
  platform/      OS abstraction (posix now, windows v0.2); psutil-backed
  discover/      framework adapters: hermes.py + hermes_config.py, openclaw.py + openclaw_config.py,
                 settings.py (shared Settings + load_settings dispatch), _json5.py (OpenClaw config is JSON5)
  checks/        BLUE passive checks — one file per area; policy.py is Hermes, policy_openclaw.py is OpenClaw
  probes/        RED active probes — localhost only (milestone 3)
  chain/         attack-path rules (milestone 3)
  report/        terminal (rich), json, html (milestone 4)
tests/           pytest; conftest.py builds a fake ~/.hermes, test_openclaw.py a fake ~/.openclaw, one of everything each
reviews/codex/   Codex writes its reports here (see BUILD.md)
reviews/claude/  Claude's responses to those reports
```

## Conventions
- Python ≥ 3.10, deps: psutil, rich, pyyaml. Don't add more without a reason in BUILD.md.
- Check ids: `AREA-NNN` (SEC, PERM, NET, POL, SKILL, PROC, RED). Stable forever once shipped.
- Severity: CRITICAL = remote unauth → code exec or all secrets; HIGH = secrets exposed
  or unauth reachable service; MEDIUM = policy weakness that needs one more hop; LOW = hygiene.
- Run `pytest` before declaring anything done. `daemonaudit scan` against a real home is
  the smoke test.
