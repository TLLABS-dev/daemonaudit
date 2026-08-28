import json
import sys

import pytest

from daemonaudit.discover.hermes import discover_hermes
from daemonaudit.model import ScanReport, Severity
from daemonaudit.platform import get_platform
from daemonaudit.registry import load_builtin_checks, run_all
from daemonaudit.report.json_out import to_json
from conftest import FAKE_ANTHROPIC, FAKE_GITHUB, FAKE_TELEGRAM

pytestmark = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX modes")


@pytest.fixture
def report(hermes_home):
    load_builtin_checks()
    plat = get_platform()
    target = discover_hermes(plat, hermes_home)
    assert target is not None and target.version == "0.20.6"
    r = ScanReport(tool_version="test", targets=[target])
    r.results = run_all(target, plat)
    return r


def _by(report, check_id):
    return [f for f in report.findings if f.check_id == check_id]


def test_no_errors(report):
    assert not [r for r in report.results if r.status == "error"], [r.note for r in report.results]


def test_sec001_finds_backup_and_state_db_but_not_vault_or_source(report):
    fs = _by(report, "SEC-001")
    assets = {f.asset.rsplit("/", 1)[-1] for f in fs}
    assert "config.yaml.bak.20260827" in assets
    assert "state.db" in assets
    assert ".env" not in assets and "auth.json" not in assets
    assert not any("hermes-agent" in f.asset for f in fs)
    assert not any("evil-link" in f.asset or "outside.txt" in f.asset for f in fs)
    assert all(f.severity == Severity.HIGH for f in fs)  # both fixtures are world-readable


def test_perm001_flags_auth_json_high_and_state_db_medium(report):
    fs = {f.asset.rsplit("/", 1)[-1]: f for f in _by(report, "PERM-001")}
    assert fs["auth.json"].severity == Severity.HIGH
    assert fs["state.db"].severity == Severity.MEDIUM
    assert ".env" not in fs


def test_perm002_backup_weaker_with_secret_is_high(report):
    fs = _by(report, "PERM-002")
    assert len(fs) == 1 and fs[0].severity == Severity.HIGH
    assert "anthropic-api-key" in fs[0].title


def test_perm003_group_writable_and_exec_bit(report):
    titles = " ".join(f.title for f in _by(report, "PERM-003"))
    assert "group-writable" in titles and "executable bit" in titles
    assert "world-writable" not in titles


def test_no_raw_secret_in_any_output(report):
    text = to_json(report)
    for s in (FAKE_ANTHROPIC, FAKE_GITHUB, FAKE_TELEGRAM):
        assert s not in text
    json.loads(text)  # still valid JSON after scrubbing
    for f in report.findings:
        blob = json.dumps(f.to_dict())
        for s in (FAKE_ANTHROPIC, FAKE_GITHUB, FAKE_TELEGRAM):
            assert s not in blob


def test_exit_code(report):
    assert report.exit_code() == 2
