"""Terminal renderer. Every dynamic string goes through scrub() and is wrapped in
rich.Text so it is never interpreted as markup."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from daemonaudit.banner import banner
from daemonaudit.model import Position, ScanReport, Severity
from daemonaudit.redact import scrub

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
BORDER = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
STATUS_STYLE = {"pass": "green", "info": "green", "fail": "red", "skip": "yellow", "off": "dim", "error": "bold red", "incomplete": "yellow"}


def T(s: object, style: str = "") -> Text:
    """Scrubbed, markup-safe text."""
    return Text(scrub(str(s)), style=style)


def render(report: ScanReport, console: Console | None = None, show_banner: bool = True) -> None:
    con = console or Console()
    if show_banner:
        con.print(Text(banner(), style="magenta"))

    notes_any = any(tg.meta.get("notes") for tg in report.targets)
    t = Table(title="Targets", expand=False)
    for col in ("framework", "home", "version", "running pids") + (("notes",) if notes_any else ()):
        t.add_column(col)
    for tg in report.targets:
        cells = [T(tg.framework), T(tg.home), T(tg.version or "?"), T(tg.running_label(), "" if tg.pids or not tg.unattributed_pids else "yellow")]
        if notes_any:
            cells.append(T("\n".join(tg.meta.get("notes") or []), "yellow"))
        t.add_row(*cells)
    con.print(t)

    if report.attack_paths:
        con.rule(T(f"Attack paths  ({len(report.attack_paths)})", "bold red"))
        for i, ap in enumerate(report.attack_paths, 1):
            body = Text()
            body.append_text(T(ap.narrative + "\n\n", "italic"))
            for n, h in enumerate(ap.hops, 1):
                marker = "▶" if n == ap.kill_hop else " "
                body.append(f" {marker} {n}. ", style="bold")
                body.append(h.check_id + "  ", style="dim")
                body.append_text(T(h.title + "\n"))
            body.append_text(T(f"\nreaches  {ap.reaches}\n", "bold"))
            body.append("kill it  ", style="bold green")
            body.append_text(T(f"fix hop {ap.kill_hop}: {ap.hops[ap.kill_hop - 1].fix}\n"))
            title = Text.assemble(Text(ap.severity.value.upper(), style=SEV_STYLE[ap.severity]), "  ", T(f"path {i}: {ap.name}"))
            con.print(Panel(body, title=title, title_align="left", border_style=BORDER[ap.severity]))
    elif report.red_enabled:
        con.print(Panel(T("No attack paths chain together from the findings above.", "bold green")))

    if report.blast_radius:
        b = Table(title="Blast radius — what a stolen credential grants", expand=False)
        for col in ("kind", "count", "grants"):
            b.add_column(col)
        for e in report.blast_radius:
            b.add_row(T(e.kind), T(str(e.count)), T(e.grants))
        con.print(b)
    elif not report.red_enabled:
        con.print(T("run with --red to measure the local blast radius (vault + process environment) and verify listeners", "dim"))

    if not report.actionable:
        if report.is_complete:
            con.print(Panel(T("No findings. All checks completed.", "bold green")))
        else:
            n = len(report.incomplete_results)
            con.print(Panel(T(f"No findings among completed checks — but {n} check(s) did not complete. See the table below.", "bold yellow")))

    for pos in Position:
        fs = [f for f in report.findings if f.position == pos]
        if not fs:
            continue
        con.rule(T(f"{pos.label}  ({len(fs)})", "bold"))
        for f in fs:
            body = Text()
            body.append_text(T(f.why + "\n"))
            body.append("fix     ", style="bold green")
            body.append_text(T(f.fix + "\n"))
            if f.verify_cmd:
                body.append("verify  ", style="bold blue")
                body.append_text(T(f.verify_cmd + "\n"))
            if f.evidence:
                body.append("evidence\n", style="bold")
                for e in f.evidence:
                    body.append_text(T(f"  · {e}\n", "dim"))
            title = Text.assemble(
                Text(f.severity.value.upper(), style=SEV_STYLE[f.severity]), "  ", T(f.check_id, "dim"), "  ", T(f.title)
            )
            con.print(Panel(body, title=title, title_align="left", border_style=BORDER[f.severity]))

    multi = len(report.targets) > 1
    s = Table(title="Checks", expand=False)
    for col in (("id", "target", "status", "check", "note") if multi else ("id", "status", "check", "note")):
        s.add_column(col)
    for r in report.results:
        note = (r.note or "").strip().splitlines()
        cells = [T(r.check_id)] + ([T(r.framework or "?")] if multi else []) + [T(r.status, STATUS_STYLE.get(r.status, "")), T(r.title), T(note[-1] if note else "")]
        s.add_row(*cells)
    con.print(s)

    c = report.counts()
    con.print(
        T(
            f"summary  critical {c['critical']}  high {c['high']}  medium {c['medium']}  low {c['low']}  "
            f"· {'complete' if report.is_complete else 'INCOMPLETE'} · exit code {report.exit_code()}",
            "bold",
        )
    )
