"""Self-contained HTML report: one file, no external assets, no scripts, light/dark
via prefers-color-scheme. Every dynamic string is scrubbed and HTML-escaped."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from daemonaudit import __version__
from daemonaudit.model import Position, ScanReport, Severity
from daemonaudit.redact import scrub


def e(s: object) -> str:
    return html.escape(scrub(str(s)), quote=True)


CSS = """
:root{--bg:#fbfaf7;--fg:#1f1d1a;--muted:#6b665e;--card:#ffffff;--line:#e6e2da;--code:#f1eee8;
--crit:#7a0f1f;--high:#b3261e;--med:#a15c00;--low:#0b6e8a;--info:#5c5750;--ok:#1d7a3a;--accent:#6b2fa0}
@media (prefers-color-scheme:dark){:root{--bg:#161513;--fg:#ebe7df;--muted:#a39d92;--card:#1f1d1a;--line:#2f2c27;--code:#26231f;
--crit:#ff8a99;--high:#ff7b72;--med:#f0b25a;--low:#6cc4e0;--info:#a39d92;--ok:#5fd38a;--accent:#c79cf0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px 60px}
header{display:flex;gap:18px;align-items:center;margin-bottom:8px}header h1{margin:0;font-size:28px}header p{margin:2px 0 0;color:var(--muted)}
h2{font-size:20px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:22px 0 8px;color:var(--muted);font-weight:600}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}.chip{padding:4px 10px;border-radius:999px;border:1px solid var(--line);background:var(--card);font-size:13px}
.chip b{margin-right:4px}.chip.crit b{color:var(--crit)}.chip.high b{color:var(--high)}.chip.med b{color:var(--med)}.chip.low b{color:var(--low)}.chip.ok{color:var(--ok)}.chip.warn{color:var(--med)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:13px}tr:last-child td{border-bottom:0}
.wrap{overflow-x:auto}
.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;padding:14px 16px;margin:10px 0}
.card.critical{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}.card.medium{border-left-color:var(--med)}.card.low{border-left-color:var(--low)}
.card h4{margin:0 0 6px;font-size:16px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.sev{font-size:11px;font-weight:700;letter-spacing:.06em;padding:2px 7px;border-radius:4px;color:#fff;background:var(--info)}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}.sev.low{background:var(--low)}
.id{color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.kv{display:grid;grid-template-columns:70px 1fr;gap:4px 12px;margin-top:8px;font-size:14px}.kv dt{color:var(--muted);font-weight:600}.kv dd{margin:0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}pre{background:var(--code);padding:8px 10px;border-radius:6px;overflow-x:auto;margin:4px 0}
ul.ev{margin:4px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
.path ol{margin:8px 0;padding-left:22px}.path li{margin:4px 0}.path li.kill{font-weight:600}.path li.kill::marker{color:var(--ok)}
.narr{font-style:italic;color:var(--muted);margin:0 0 6px}.kill-fix{margin-top:8px}.kill-fix b{color:var(--ok)}
.st{font-weight:600}.st.pass,.st.info{color:var(--ok)}.st.fail{color:var(--high)}.st.skip,.st.incomplete{color:var(--med)}.st.error{color:var(--crit)}.st.off{color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:12px}
"""

DEMON = (
    '<svg width="56" height="56" viewBox="0 0 64 64" aria-hidden="true">'
    '<path d="M14 22 L8 6 L22 16 Z M50 22 L56 6 L42 16 Z" fill="#c0392b"/>'
    '<circle cx="32" cy="36" r="22" fill="#7d3c98"/>'
    '<circle cx="24" cy="32" r="4" fill="#fff"/><circle cx="40" cy="32" r="4" fill="#fff"/>'
    '<circle cx="25" cy="33" r="2" fill="#111"/><circle cx="41" cy="33" r="2" fill="#111"/>'
    '<path d="M22 44 Q32 52 42 44" stroke="#fff" stroke-width="3" fill="none" stroke-linecap="round"/>'
    '</svg>'
)


def _sev(s: Severity) -> str:
    return f'<span class="sev {s.value}">{s.value}</span>'


def render_html(report: ScanReport) -> str:
    c = report.counts()
    out: list[str] = []
    w = out.append
    w("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    w(f"<title>daemonaudit report — {e(report.host.get('hostname', ''))}</title><style>{CSS}</style></head><body><main>")
    w(f"<header>{DEMON}<div><h1>daemonaudit report</h1><p>{e(report.host.get('hostname', ''))} · {e(report.host.get('os', ''))} {e(report.host.get('release', ''))} · {e(report.started_at)} · v{e(report.tool_version)}</p></div></header>")

    w('<div class="chips">')
    for key, cls in (("critical", "crit"), ("high", "high"), ("medium", "med"), ("low", "low")):
        w(f'<span class="chip {cls}"><b>{c[key]}</b>{key}</span>')
    w(f'<span class="chip {"ok" if report.is_complete else "warn"}">{"complete" if report.is_complete else "INCOMPLETE — some checks did not run"}</span>')
    w(f'<span class="chip">exit code {report.exit_code()}</span>')
    w(f'<span class="chip">{"red probes on" if report.red_enabled else "passive only — run with --red for attack paths and blast radius"}</span>')
    w("</div>")

    w('<div class="wrap"><table><tr><th>framework</th><th>home</th><th>version</th><th>running pids</th></tr>')
    for t in report.targets:
        w(f"<tr><td>{e(t.framework)}</td><td><code>{e(t.home)}</code></td><td>{e(t.version or '?')}</td><td>{e(', '.join(map(str, t.pids)) or 'not running')}</td></tr>")
    w("</table></div>")

    if report.attack_paths:
        w(f"<h2>Attack paths ({len(report.attack_paths)})</h2>")
        for i, ap in enumerate(report.attack_paths, 1):
            w(f'<div class="card path {ap.severity.value}"><h4>{_sev(ap.severity)} path {i}: {e(ap.name)}</h4><p class="narr">{e(ap.narrative)}</p><ol>')
            for n, h in enumerate(ap.hops, 1):
                w(f'<li class="{"kill" if n == ap.kill_hop else ""}"><span class="id">{e(h.check_id)}</span> {e(h.title)}</li>')
            w(f'</ol><div><b>reaches</b> {e(ap.reaches)}</div><div class="kill-fix"><b>kill it at hop {ap.kill_hop}:</b> {e(ap.hops[ap.kill_hop - 1].fix)}</div></div>')
    elif report.red_enabled:
        w('<h2>Attack paths</h2><p>No attack paths chain together from these findings.</p>')

    if report.blast_radius:
        w('<h2>Blast radius — what a stolen credential grants</h2><div class="wrap"><table><tr><th>kind</th><th>count</th><th>grants</th></tr>')
        for b in report.blast_radius:
            w(f"<tr><td><code>{e(b.kind)}</code></td><td>{b.count}</td><td>{e(b.grants)}</td></tr>")
        w("</table></div>")

    w("<h2>Findings</h2>")
    if not report.actionable:
        w(f'<p class="st {"pass" if report.is_complete else "skip"}">{"No findings. All checks completed." if report.is_complete else "No findings among completed checks — but some checks did not complete (see below)."}</p>')
    for pos in Position:
        fs = [f for f in report.findings if f.position == pos]
        if not fs:
            continue
        w(f"<h3>{e(pos.label)} ({len(fs)})</h3>")
        for f in fs:
            w(f'<div class="card {f.severity.value}"><h4>{_sev(f.severity)}<span class="id">{e(f.check_id)}</span>{e(f.title)}</h4><p>{e(f.why)}</p><dl class="kv">')
            w(f"<dt>fix</dt><dd>{e(f.fix)}</dd>")
            if f.verify_cmd:
                w(f"<dt>verify</dt><dd><pre>{e(f.verify_cmd)}</pre></dd>")
            if f.evidence:
                w("<dt>evidence</dt><dd><ul class=\"ev\">" + "".join(f"<li>{e(x)}</li>" for x in f.evidence) + "</ul></dd>")
            w("</dl></div>")

    multi = len(report.targets) > 1
    w("<h2>Checks</h2><div class=\"wrap\"><table><tr><th>id</th>" + ("<th>target</th>" if multi else "") + "<th>status</th><th>check</th><th>note</th></tr>")
    for r in report.results:
        note = (r.note or "").strip().splitlines()
        fw = f"<td>{e(r.framework or '?')}</td>" if multi else ""
        w(f'<tr><td class="id">{e(r.check_id)}</td>{fw}<td class="st {e(r.status)}">{e(r.status)}</td><td>{e(r.title)}</td><td>{e(note[-1] if note else "")}</td></tr>')
    w("</table></div>")

    w(f"<footer>Generated by daemonaudit v{e(__version__)} at {e(datetime.now(timezone.utc).isoformat(timespec='seconds'))}. "
      "Read-only. Zero network egress. Secrets are redacted at detection and never written to this file.</footer></main></body></html>")
    return "".join(out)
