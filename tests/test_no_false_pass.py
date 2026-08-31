"""v0.2.1: a config that does not parse never yields a pass — on either framework — and a
directory that is not a daemon home is never scanned as one."""
import os
import sys
from pathlib import Path

import pytest

from daemonaudit.discover import discover_all
from daemonaudit.discover.hermes import discover_hermes
from daemonaudit.platform import get_platform
from daemonaudit.registry import load_builtin_checks, run_all
from daemonaudit.report.json_out import to_json
from daemonaudit.model import ScanReport

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX modes")


def _hermes(tmp_path: Path, config: str) -> tuple:
    h = tmp_path / ".hermes"; h.mkdir(exist_ok=True)
    (h / "config.yaml").write_text(config, encoding="utf-8")
    (h / ".env").write_text("HERMES_YOLO_MODE=1\nGATEWAY_ALLOW_ALL_USERS=true\n", encoding="utf-8")
    load_builtin_checks(); plat = get_platform()
    t = discover_hermes(plat, h)
    r = ScanReport(tool_version="t", targets=[t]); r.results = run_all(t, plat)
    return t, r, {x.check_id: x for x in r.results}


@posix_only
def test_hermes_unparsable_config_skips_config_checks_and_keeps_env_findings(tmp_path):
    t, r, st = _hermes(tmp_path, "approvals: [unclosed\n")
    for cid in ("POL-002", "POL-003", "POL-008", "POL-009", "POL-010"):
        assert st[cid].status == "skip" and "unparsable" in st[cid].note, (cid, st[cid])
    assert st["POL-001"].status == "fail" and any("HERMES_YOLO_MODE" in f.title for f in st["POL-001"].findings)  # .env still speaks
    assert st["POL-004"].status == "fail" and "unparsable" in st["POL-004"].note
    assert st["ADV-001"].status != "pass" and "unparsable" in st["ADV-001"].note
    assert "unparsable" in t.meta["config_error"] and "unparsable" in to_json(r) and not r.is_complete


@posix_only
def test_hermes_config_that_is_not_a_mapping_is_a_parse_error(tmp_path):
    t, r, st = _hermes(tmp_path, "- a\n- b\n")
    assert "not a mapping" in t.meta["config_error"] and st["POL-002"].status == "skip"


@posix_only
def test_hermes_valid_config_has_no_parse_error(tmp_path):
    t, r, st = _hermes(tmp_path, "approvals:\n  mode: \"off\"\n")
    assert t.meta["config_error"] is None and st["POL-002"].status == "fail"


def test_home_must_look_like_a_daemon_home(tmp_path):
    assert discover_all(get_platform(), tmp_path) == []
    (tmp_path / "state.db").write_bytes(b"x")
    assert [t.framework for t in discover_all(get_platform(), tmp_path)] == ["hermes"]
    oc = tmp_path / "oc"; oc.mkdir(); (oc / "openclaw.json").write_text("{}")
    assert [t.framework for t in discover_all(get_platform(), oc)] == ["openclaw"]
