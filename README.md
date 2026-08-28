<img src="assets/daemon.svg" align="right" width="120" alt="daemonaudit mascot">

# daemonaudit

> Who can hurt your AI agent — and how badly.

`daemonaudit` is a red/blue security audit for self-hosted AI agent daemons. It finds the
secrets, the open doors and the weak policies on the machine your agent runs on, then tells
you the **attack paths** and the **blast radius**: what an attacker gets, from where, and
which single fix kills the whole chain.

Supports **Hermes Agent** today. OpenClaw and generic MCP configs are on the roadmap.

![daemonaudit scan --red](assets/demo-report.svg)

*(above: `daemonaudit scan --red` against a deliberately-broken demo home — build your own with `python scripts/demo_home.py`)*

## Why not just the built-in audit?
Framework auditors ask *"is my config right?"*. `daemonaudit` asks *"what does an attacker
standing here actually get?"* — and it looks at the **host**, not just the config: backups,
transcripts, sqlite state, process environments, listening sockets, and the skills you installed.
Then it **chains** the findings: an exposed port *plus* an unsandboxed backend *plus* keys in the
environment is one attack path, and it names the one hop whose fix breaks it.

## Install
```bash
uvx --from git+https://github.com/TLLABS-dev/daemonaudit daemonaudit scan     # zero-install run
# or
pipx install git+https://github.com/TLLABS-dev/daemonaudit
```
From a clone:
```bash
python -m pip install -e '.[dev]'
daemonaudit scan
```
Requires Python ≥ 3.10. Dependencies: `psutil`, `rich`, `pyyaml`. Linux, macOS and Windows.

## Use
```bash
daemonaudit scan                       # passive audit (safe anywhere): secrets, perms, policy, skills, listeners
daemonaudit scan --red                 # + active probes against THIS host, attack paths, blast radius
daemonaudit scan --html report.html    # a self-contained HTML report (also --json)
daemonaudit scan --home /path/to/.hermes
daemonaudit checks                     # list every check
```
`--red` adds three probes that only ever touch **localhost**: it connects to the daemon's own
listeners to see which answer without a password, reads the daemon's process environment, and
reads the vault the way any process running as you could — to measure the real local blast radius.

## What it checks (v0.1, Hermes)
- **Secrets** outside the vault — config, backups, transcripts, sqlite state — with encoded/obfuscated variants
- **Permissions** — world-readable vault/state, backups looser than their originals, writable sockets
- **Policy** — yolo/approval bypasses, unsandboxed host execution, allow-all users, exposed/unauthenticated API server, unverified webhooks, secret-leaking debug flags, SSRF guard, credentials forwarded into tool shells, literal secrets in MCP config
- **Skills** — `curl | sh` (incl. split/`eval`/Python-subprocess forms), exfiltration shapes, prompt-injection and invisible-Unicode in `SKILL.md`, frontmatter that asks for master keys or the vault; vendor-shipped skills are recognised and graded down
- **Freshness** — updates behind and dismissed advisories, from the daemon's own local cache
- **Red probes** — unauthenticated HTTP, process-environment secrets, vault blast radius

Each finding says **why it matters**, the exact **fix**, and a command to **verify** it.

## Principles
- **Read-only.** It never changes your system.
- **Zero network egress.** Nothing leaves the box. The active probes connect to localhost only, and refuse any target that isn't this host.
- **Redacted by construction.** The report can show you `sk-ant-…4f2a`; it cannot show you the key. Nothing that leaves the process — terminal, JSON, HTML — contains a raw credential.
- **No false passes.** A check that can't run says *skipped*, never *ok*. A scan that couldn't complete exits non-zero.

## Exit codes (for cron / CI)
| code | meaning |
|---|---|
| 0 | clean, and every check completed |
| 1 | findings (low/medium) |
| 2 | high or critical findings |
| 3 | no supported daemon found (use `--home`) |
| 4 | no findings, but a check was skipped/errored/incomplete — **not** a clean bill |
| 5 | the tool itself failed (`--debug` for a scrubbed traceback) |

Precedence 2 > 1 > 4 > 0. INFO-only findings don't affect the exit code.

## Roadmap
- **v0.1** — Hermes: secrets, permissions, policy, skills, exposed services, localhost red probes, attack-path report. Linux · macOS · Windows.
- **v0.2** — OpenClaw + generic MCP adapters, canary-injection probe, local-LLM (Ollama) semantic skill review, guided remediation with rollback, richer Windows ACL model, continuous monitoring / drift alerts.

## Development
`pytest` runs the suite (Linux/macOS/Windows in CI). The design invariants live in
[`AGENTS.md`](AGENTS.md); the plan and history in [`BUILD.md`](BUILD.md). Built with a two-model
workflow — one model builds, another reviews and writes adversarial fixtures; the review
rounds are under [`reviews/`](reviews/).

## License
MIT — see [LICENSE](LICENSE).
