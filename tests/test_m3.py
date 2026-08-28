"""Milestone 3: red probes (localhost only) and chain rules."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from daemonaudit.chain import build_attack_paths, build_blast_radius
from daemonaudit.discover.hermes import discover_hermes
from daemonaudit.model import Finding, Position, ScanReport, Severity
from daemonaudit.platform.base import NotSupported, PosixPlatform
from daemonaudit.probes.red import NotLocal, _assert_local
from daemonaudit.registry import load_builtin_checks, run_all
from daemonaudit.report.json_out import to_json
from conftest import FAKE_ANTHROPIC, FAKE_GITHUB, FAKE_TELEGRAM

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX")


def _server(status: int):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a):  # quiet
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class FakePlat(PosixPlatform):
    def __init__(self, ports, env=None, env_fail=False, home=None):
        self._ports, self._env, self._env_fail, self._home = ports, env or {}, env_fail, home
    def find_processes(self, needle):
        cmd = f"{self._home}/hermes-agent/venv/bin/python -m hermes_cli.main gateway run" if self._home else "/x/.hermes/hermes-agent/venv/bin/python -m hermes_cli.main gateway run"
        return [{"pid": 4242, "cmdline": cmd, "user": "tl"}]
    def children(self, pid):
        return []
    def listening_sockets(self):
        return [{"ip": "127.0.0.1", "port": p, "pid": 4242, "family": "v4"} for p in self._ports]
    def process_env(self, pid):
        if self._env_fail:
            raise NotSupported("denied")
        return self._env


@pytest.fixture
def home(tmp_path):
    h = tmp_path / ".hermes"; h.mkdir()
    (h / ".env").write_text(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\nGITHUB_TOKEN={FAKE_GITHUB}\nTELEGRAM_BOT_TOKEN={FAKE_TELEGRAM}\nSOME_FLAG=1\n")
    os.chmod(h / ".env", 0o600)
    (h / "config.yaml").write_text("terminal:\n  backend: local\n")
    return h


def _run(home, plat, red=True):
    load_builtin_checks()
    t = discover_hermes(plat, home)
    r = ScanReport(tool_version="t", targets=[t], red_enabled=red)
    r.results = run_all(t, plat, include_red=red)
    r.attack_paths = build_attack_paths(r)
    r.blast_radius = build_blast_radius(r)
    return r


def _by(r, cid):
    return [f for f in r.findings if f.check_id == cid]


# --- localhost gate ---
def test_probe_refuses_non_local_targets():
    assert _assert_local("0.0.0.0") == "127.0.0.1"
    assert _assert_local("127.0.0.1") == "127.0.0.1"
    assert _assert_local("::") == "::1"
    for bad in ("8.8.8.8", "93.184.216.34", "example.com", "10.0.0.5"):
        with pytest.raises(NotLocal):
            _assert_local(bad)


# --- RED-001 ---
def test_red001_unauth_vs_auth(home):
    open_srv, auth_srv = _server(200), _server(401)
    try:
        r = _run(home, FakePlat([open_srv.server_port, auth_srv.server_port], home=home))
        fs = _by(r, "RED-001")
        high = [f for f in fs if f.severity == Severity.HIGH]
        assert len(high) == 1 and str(open_srv.server_port) in high[0].title and "net:unauth:verified" in high[0].tags
        info = [f for f in fs if f.severity == Severity.INFO]
        assert len(info) == 1 and str(auth_srv.server_port) in info[0].title
    finally:
        open_srv.shutdown(); auth_srv.shutdown()


def test_red_probes_off_by_default(home):
    r = _run(home, FakePlat([], home=home), red=False)
    statuses = {x.check_id: x.status for x in r.results}
    assert statuses["RED-001"] == statuses["RED-002"] == statuses["RED-003"] == "off"
    assert r.exit_code() != 4  # "off" is not incomplete


# --- RED-002 / RED-003 ---
def test_red002_process_env_secrets_redacted(home):
    env = {"ANTHROPIC_API_KEY": FAKE_ANTHROPIC, "GITHUB_TOKEN": FAKE_GITHUB, "PATH": "/usr/bin", "MY_SECRET": "hunter2hunter2hunter2"}
    r = _run(home, FakePlat([], env=env, home=home))
    f = _by(r, "RED-002")[0]
    assert "3 credential(s)" in f.title and "secret:procenv" in f.tags
    blob = json.dumps(f.to_dict())
    assert FAKE_ANTHROPIC not in blob and FAKE_GITHUB not in blob and "hunter2" not in blob


def test_red002_denied_is_incomplete_not_pass(home):
    r = _run(home, FakePlat([], env_fail=True, home=home))
    assert next(x for x in r.results if x.check_id == "RED-002").status == "incomplete"


def test_red003_blast_radius(home):
    r = _run(home, FakePlat([], home=home))
    f = _by(r, "RED-003")[0]
    assert "3 credential(s) of 3 kind(s)" in f.title and "secret:vault" in f.tags
    kinds = {b.kind: b for b in r.blast_radius}
    assert {"anthropic-api-key", "github-token", "telegram-bot-token"} <= set(kinds)
    assert "impersonate" in kinds["telegram-bot-token"].grants or "become your bot" in kinds["telegram-bot-token"].grants
    assert FAKE_TELEGRAM not in to_json(r)


# --- chain rules ---
def _f(cid, sev, tags):
    return Finding(cid, f"{cid} title", sev, Position.LOCAL, "a", "why", f"fix {cid}", tags=tags)


def test_chain_remote_path_and_kill_hop():
    r = ScanReport(tool_version="t")
    from daemonaudit.model import CheckResult
    r.results = [CheckResult("X", "x", "fail", [
        _f("NET-001", Severity.HIGH, ["net:public"]),
        _f("RED-001", Severity.HIGH, ["net:unauth:verified"]),
        _f("POL-003", Severity.MEDIUM, ["exec:host"]),
        _f("RED-003", Severity.INFO, ["secret:vault"]),
    ])]
    paths = build_attack_paths(r)
    names = [p.name for p in paths]
    assert names[0].startswith("Remote → agent tools")
    p = paths[0]
    assert [h.check_id for h in p.hops] == ["NET-001", "RED-001", "POL-003", "RED-003"]
    assert p.kill_hop == 1 and p.to_dict()["kill_fix"] == "fix NET-001"
    assert p.severity == Severity.HIGH


def test_chain_needs_every_hop():
    r = ScanReport(tool_version="t")
    from daemonaudit.model import CheckResult
    r.results = [CheckResult("X", "x", "fail", [_f("NET-001", Severity.HIGH, ["net:public"]), _f("POL-003", Severity.MEDIUM, ["exec:host"])])]
    assert not any(p.name.startswith("Remote") for p in build_attack_paths(r))


@posix_only
def test_end_to_end_local_reader_path(home):
    os.chmod(home / ".env", 0o644)  # vault readable → "Local user → readable credentials"
    r = _run(home, FakePlat([], home=home))
    assert any(p.name.startswith("Local user → readable") for p in r.attack_paths)
    d = json.loads(to_json(r))
    assert d["attack_paths"] and d["red_probes"] is True and d["summary"]["attack_paths"] >= 1


def test_discovery_does_not_attribute_foreign_processes(tmp_path):
    """Scanning a demo/backup home must never probe the real daemon (M4 lesson)."""
    class P(PosixPlatform):
        def find_processes(self, needle):
            return [{"pid": 1, "cmdline": "/home/someone/.hermes/hermes-agent/venv/bin/python -m hermes_cli.main gateway run", "user": "x"}]
        def process_env(self, pid):
            raise NotSupported("denied")
    home = tmp_path / "demo"; home.mkdir()
    t = discover_hermes(P(), home)
    assert t.pids == [] and t.meta["gateway_pids"] == []
    mine = tmp_path / "mine"; mine.mkdir()
    class Q(P):
        def find_processes(self, needle):
            return [{"pid": 2, "cmdline": f"{mine}/hermes-agent/venv/bin/python -m hermes_cli.main gateway run", "user": "x"}]
    assert discover_hermes(Q(), mine).pids == [2]


def test_discovery_ignores_non_python_mentions(tmp_path):
    """A shell or editor whose command line merely contains 'hermes_cli' is not the daemon."""
    class P(PosixPlatform):
        def find_processes(self, needle):
            return [{"pid": 9, "cmdline": f"/bin/bash -c grep hermes_cli {tmp_path}/mine/notes", "user": "x"}]
        def process_env(self, pid):
            raise NotSupported("denied")
    home = tmp_path / "mine"; home.mkdir()
    assert discover_hermes(P(), home).pids == []
