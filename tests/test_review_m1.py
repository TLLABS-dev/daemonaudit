"""Regression tests for the Codex M1 review (reviews/codex/2026-08-27-m1-review.md)."""
import os
import sys
from pathlib import Path

import pytest
from rich.console import Console

from daemonaudit.checks._walk import walk_entries, walk_files
from daemonaudit.cli import main
from daemonaudit.discover.hermes import HERMES_LAYOUT, discover_hermes
from daemonaudit.model import CheckResult, Finding, Position, ScanReport, Severity, Target
from daemonaudit.platform import get_platform
from daemonaudit.redact import find_secrets
from daemonaudit.registry import load_builtin_checks, run_all
from daemonaudit.report.terminal import render
from conftest import FAKE_ANTHROPIC, FAKE_GITHUB

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX modes")
not_root = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read anything")


# --- #1 terminal output is scrubbed everywhere, including target/check fields ---
def test_terminal_scrubs_every_dynamic_field():
    f = Finding("X-001", f"t {FAKE_ANTHROPIC}", Severity.HIGH, Position.LOCAL, f"/a/{FAKE_GITHUB}",
                f"why {FAKE_ANTHROPIC}", f"fix {FAKE_GITHUB}", f"verify {FAKE_ANTHROPIC}", [f"ev {FAKE_GITHUB}"])
    r = ScanReport(tool_version="t",
                   targets=[Target(framework=f"fw {FAKE_ANTHROPIC}", home=Path(f"/h/{FAKE_GITHUB}"), version=FAKE_ANTHROPIC)],
                   results=[CheckResult("X-001", f"check {FAKE_GITHUB}", "fail", [f]),
                            CheckResult("X-002", f"errored {FAKE_ANTHROPIC}", "error", note=f"Traceback ... {FAKE_GITHUB}")])
    con = Console(record=True, width=200, force_terminal=False)
    render(r, con, show_banner=False)
    text = con.export_text()
    assert FAKE_ANTHROPIC not in text and FAKE_GITHUB not in text
    assert "[bold" not in text  # markup was not interpreted from data


# --- #2 exit codes distinguish clean / findings / incomplete ---
def _rep(*results):
    return ScanReport(tool_version="t", results=list(results))

def _f(sev):
    return Finding("X", "t", sev, Position.LOCAL, "a", "w", "f")

def test_exit_code_matrix():
    assert _rep(CheckResult("A", "a", "pass")).exit_code() == 0
    assert _rep(CheckResult("A", "a", "off")).exit_code() == 0          # deliberate opt-out is not incomplete
    assert _rep(CheckResult("A", "a", "skip")).exit_code() == 4
    assert _rep(CheckResult("A", "a", "error")).exit_code() == 4
    assert _rep(CheckResult("A", "a", "incomplete")).exit_code() == 4
    assert _rep(CheckResult("A", "a", "fail", [_f(Severity.LOW)]), CheckResult("B", "b", "skip")).exit_code() == 1
    assert _rep(CheckResult("A", "a", "fail", [_f(Severity.HIGH)]), CheckResult("B", "b", "error")).exit_code() == 2

def test_incomplete_report_does_not_say_clean():
    con = Console(record=True, width=120, force_terminal=False)
    render(_rep(CheckResult("A", "a", "skip", note="nope")), con, show_banner=False)
    assert "did not complete" in con.export_text()


# --- #3 unreadable files become coverage notes, never a silent pass ---
@posix_only
@not_root
def test_unreadable_candidate_is_incomplete_not_pass(tmp_path):
    home = tmp_path / ".hermes"; home.mkdir()
    (home / "state.db").write_bytes(b"clean"); os.chmod(home / "state.db", 0)
    load_builtin_checks(); plat = get_platform()
    t = discover_hermes(plat, home)
    res = {r.check_id: r for r in run_all(t, plat)}
    assert res["SEC-001"].status == "skip"           # nothing could be inspected at all
    (home / "config.yaml").write_text("model: x\n")  # now one readable, one not
    res = {r.check_id: r for r in run_all(t, plat)}
    assert res["SEC-001"].status == "incomplete" and "unreadable" in res["SEC-001"].note


# --- #4 symlinked root is resolved once at discovery; walkers refuse symlink roots ---
@posix_only
def test_symlink_root_resolved_and_walkers_guard(tmp_path):
    real = tmp_path / "real"; real.mkdir(); (real / "state.db").write_bytes(b"x")
    link = tmp_path / "link"; os.symlink(real, link)
    plat = get_platform()
    t = discover_hermes(plat, link)
    assert t.home == real.resolve() and t.meta["home_as_given"] == str(link)
    assert list(walk_entries(link, set())) == []
    assert list(walk_files(link, set())) == []
    assert [p.name for p in walk_files(real, set())] == ["state.db"]


# --- #7 verify commands: platform-aware stat, quoted paths, grouped find predicates ---
@posix_only
def test_verify_cmds_are_quoted_and_platform_aware(tmp_path):
    home = tmp_path / "it's home"; home.mkdir()
    (home / "auth.json").write_text("{}"); os.chmod(home / "auth.json", 0o644)
    (home / "gateway.pid").write_text("1"); os.chmod(home / "gateway.pid", 0o775)
    load_builtin_checks(); plat = get_platform()
    t = discover_hermes(plat, home)
    fs = [f for r in run_all(t, plat) for f in r.findings]
    auth = next(f for f in fs if f.asset.endswith("auth.json"))
    import shlex
    assert shlex.quote(str(home / "auth.json")) in auth.verify_cmd
    assert ("stat -f" if sys.platform == "darwin" else "stat -c") in auth.verify_cmd
    ex = next(f for f in fs if "executable bit" in f.title)
    assert "\\(" in ex.verify_cmd and "-perm /111" in ex.verify_cmd


# --- #8 CLI never leaks a traceback; documented exit codes ---
def test_cli_no_target_and_operational_error(tmp_path, capsys):
    assert main(["scan", "--home", str(tmp_path / "nope")]) == 3
    assert main(["scan", "--home", str(tmp_path)]) == 3  # a directory that is not a daemon home is never scanned as one
    home = tmp_path / "h"; home.mkdir(); (home / "config.yaml").write_text("{}\n")
    rc = main(["scan", "--home", str(home), "--json", str(tmp_path / "no-such-dir" / "out.json")])
    err = capsys.readouterr().err
    assert rc == 5 and "Traceback" not in err and "daemonaudit:" in err


# --- #6 new structural patterns (full matrix is Codex task C2) ---
def test_new_structural_patterns():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123_-abcDEF123_-"
    cases = {
        "jwt": jwt,
        "slack-app-token": "xapp-1-A0123456789-0123456789012-" + "a1" * 32,
        "discord-webhook-url": "https://discord.com/api/webhooks/123456789012345678/" + "Ab_-" * 17,
        "url-embedded-credential": "postgres://user:S3cretPassw0rd@db.local/x",
        "bearer-token": "Authorization: Bearer AbCdEf0123456789GhIjKlMnOpQr",
    }
    for kind, text in cases.items():
        assert kind in {k for k, _ in find_secrets(text)}, kind
