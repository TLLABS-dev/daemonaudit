import json
from pathlib import Path

import pytest

from daemonaudit.cli import main
from daemonaudit.model import CheckResult, Finding, Position, ScanReport, Severity, Target
from daemonaudit.report.html import render_html
from conftest import FAKE_ANTHROPIC, FAKE_GITHUB

import sys

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="chmod exit-code semantics are POSIX")


def test_html_is_self_contained_and_scrubbed():
    f = Finding("X-1", f"t {FAKE_ANTHROPIC} <script>alert(1)</script>", Severity.HIGH, Position.LOCAL, "/a",
                f"why {FAKE_GITHUB}", "fix & verify", "stat -c '%a' x", [f"ev {FAKE_ANTHROPIC}"])
    r = ScanReport(tool_version="t", targets=[Target("hermes", Path("/h"), version=FAKE_GITHUB)],
                   results=[CheckResult("X-1", "check", "fail", [f])], red_enabled=True)
    out = render_html(r)
    assert out.startswith("<!doctype html>") and "<script" not in out and "http://" not in out and "https://" not in out
    assert FAKE_ANTHROPIC not in out and FAKE_GITHUB not in out
    assert "&lt;script&gt;" in out and "fix &amp; verify" in out
    assert "No attack paths" in out and "prefers-color-scheme" in out


@posix_only
def test_cli_writes_html_and_json(tmp_path, hermes_home):
    html_path, json_path = tmp_path / "r.html", tmp_path / "r.json"
    rc = main(["scan", "--home", str(hermes_home), "--html", str(html_path), "--json", str(json_path), "--no-banner"])
    assert rc == 2
    text = html_path.read_text(encoding="utf-8")
    assert "daemonaudit report" in text and "config.yaml.bak" in text and FAKE_ANTHROPIC not in text
    assert json.loads(json_path.read_text(encoding="utf-8"))["summary"]["exit_code"] == 2
