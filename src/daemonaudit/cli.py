"""daemonaudit CLI.

  daemonaudit scan [--home PATH] [--json [FILE]] [--red] [--no-banner] [--debug]
  daemonaudit checks
  daemonaudit version
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from daemonaudit import __version__
from daemonaudit.model import EXIT_CODE_HELP, EXIT_NO_TARGET, EXIT_OPERATIONAL, ScanReport
from daemonaudit.redact import scrub


def _scan(args: argparse.Namespace) -> int:
    from daemonaudit.discover import discover_all
    from daemonaudit.platform import get_platform
    from daemonaudit.registry import load_builtin_checks, run_all

    load_builtin_checks()
    plat = get_platform()
    targets = discover_all(plat, args.home)
    if not targets:
        print("no supported agent daemon found (looked for Hermes at $HERMES_HOME / ~/.hermes; use --home)", file=sys.stderr)
        return EXIT_NO_TARGET
    report = ScanReport(tool_version=__version__, targets=targets)
    for t in targets:
        report.results.extend(run_all(t, plat, include_red=args.red))

    if args.json is not None:
        from daemonaudit.report.json_out import to_json

        text = to_json(report)
        if args.json == "-":
            sys.stdout.write(text + "\n")
        else:
            Path(args.json).write_text(text)
            print(f"wrote {args.json}", file=sys.stderr)
    else:
        from daemonaudit.report.terminal import render

        render(report, show_banner=not args.no_banner)
    return report.exit_code()


def _checks(_: argparse.Namespace) -> int:
    from daemonaudit.registry import CHECKS, load_builtin_checks

    load_builtin_checks()
    for c in CHECKS:
        print(f"{c.id:10} {c.mode:5} {c.position.value:13} {c.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="daemonaudit",
        description="Red/blue security audit for self-hosted AI agent daemons.",
        epilog=EXIT_CODE_HELP,
    )
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="audit the daemons on this machine (default)", epilog=EXIT_CODE_HELP)
    s.add_argument("--home", help="daemon home directory (default: $HERMES_HOME or ~/.hermes)")
    s.add_argument("--json", nargs="?", const="-", metavar="FILE", help="emit JSON to FILE, or to stdout with no FILE (diagnostics go to stderr)")
    s.add_argument("--red", action="store_true", help="also run active probes (localhost only; none in v0.1)")
    s.add_argument("--no-banner", action="store_true")
    s.add_argument("--debug", action="store_true", help="print a (scrubbed) traceback on tool errors")
    s.set_defaults(fn=_scan)

    c = sub.add_parser("checks", help="list registered checks")
    c.set_defaults(fn=_checks)

    v = sub.add_parser("version")
    v.set_defaults(fn=lambda _: print(__version__) or 0)

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-"):
        argv = ["scan", *argv]
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_OPERATIONAL
    except Exception as e:  # noqa: BLE001 - single boundary; scrub before printing
        print(scrub(f"daemonaudit: {type(e).__name__}: {e}"), file=sys.stderr)
        if getattr(args, "debug", False):
            print(scrub(traceback.format_exc()), file=sys.stderr)
        return EXIT_OPERATIONAL


if __name__ == "__main__":
    raise SystemExit(main())
