# daemonaudit

> Who can hurt your AI agent — and how badly.

`daemonaudit` is a red/blue security audit for self-hosted AI agent daemons.
It finds the secrets, the open doors and the weak policies on the machine your
agent runs on, then tells you the **attack paths** and the **blast radius**:
what an attacker gets, from where, and which single fix kills the whole path.

Supports **Hermes Agent** today. OpenClaw and generic MCP configs are on the roadmap.

## Why not just the built-in audit?
Framework auditors ask *"is my config right?"*. `daemonaudit` asks *"what does an attacker
standing here actually get?"* — and it looks at the host, not just the config: backups,
transcripts, sqlite state, process environments, listening sockets, the skills you installed.

## Install
```
pip install daemonaudit        # soon
uvx daemonaudit                # soon
```
Dev:
```
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
daemonaudit scan
```

## Exit codes (for cron / CI)
| code | meaning |
|---|---|
| 0 | clean, and every check completed |
| 1 | findings (low/medium) |
| 2 | high or critical findings |
| 3 | no supported daemon found (use `--home`) |
| 4 | no findings, but at least one check was skipped, errored or incomplete — **not** a clean bill |
| 5 | the tool itself failed (`--debug` for a scrubbed traceback) |

Precedence 2 > 1 > 4 > 0. `--json` writes JSON to stdout (or `--json FILE`); diagnostics always go to stderr.

## Principles
- **Read-only.** It never changes your system.
- **Zero egress.** Nothing leaves the box. Active probes hit localhost only.
- **Redacted by construction.** The report can show you `sk-ant-…4f2a`; it cannot show you the key.
- **No false passes.** A check that can't run says *skipped*, never *ok*.

## Roadmap
- **v0.1** — Hermes: secrets sprawl, file permissions, policy config, allowlists, exposed
  services, skills heuristics, localhost red probes, attack-path report. Linux + macOS.
- **v0.2** — Windows, OpenClaw + generic MCP adapters, canary injection probe,
  local-LLM (Ollama) semantic skill review, guided remediation with rollback.

## Mascot
A small demon. (Because *daemon*.) Coming to this README once it exists.

## License
MIT
