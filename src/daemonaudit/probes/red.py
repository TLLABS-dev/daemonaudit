"""RED-001..003: active probes. LOCALHOST ONLY.

Invariant (AGENTS.md §2): a probe may only connect to an address that belongs to
this machine. `_assert_local()` is the single gate; it raises before any socket is
opened if the target is not loopback or one of this host's own interface addresses.
Probes send nothing but a minimal HTTP GET; they never send credentials.
"""

from __future__ import annotations

import ipaddress
import socket
from collections import defaultdict

from daemonaudit.chain.rules import BLAST
from daemonaudit.discover.settings import SECRET_NAME, load_settings
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import NotSupported, Platform
from daemonaudit.redact import find_hits, redact
from daemonaudit.registry import check

PROBE_TIMEOUT = 3.0


class NotLocal(RuntimeError):
    pass


def _host_addresses() -> set[str]:
    addrs = {"127.0.0.1", "::1"}
    try:
        import psutil

        for ifaddrs in psutil.net_if_addrs().values():
            for a in ifaddrs:
                if a.family in (socket.AF_INET, getattr(socket, "AF_INET6", None)):
                    addrs.add(a.address.split("%")[0])
    except Exception:  # noqa: BLE001 - psutil optional here; loopback is always allowed
        pass
    return addrs


def _assert_local(ip: str) -> str:
    """Return the address to connect to, or raise NotLocal. Wildcards map to loopback."""
    if ip in ("0.0.0.0", "", "*"):
        return "127.0.0.1"
    if ip == "::":
        return "::1"
    bare = ip.split("%")[0]
    try:
        if ipaddress.ip_address(bare).is_loopback:
            return bare
    except ValueError:
        raise NotLocal(f"refusing to probe non-address target {ip!r}")
    if bare in _host_addresses():
        return bare
    raise NotLocal(f"refusing to probe {ip}: not an address of this host")


def _http_get(ip: str, port: int, path: str) -> tuple[int | None, str]:
    """(status, first header line). status None on connect/timeout failure."""
    addr = _assert_local(ip)  # the gate — never bypass
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(PROBE_TIMEOUT)
            s.connect((addr, port))
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: daemonaudit-probe\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while len(data) < 4096:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
    except OSError as e:
        return None, str(e)
    line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split(" ", 2)
    if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
        return int(parts[1]), line
    return None, line[:80] or "no HTTP response"


@check("RED-001", "Probe: daemon HTTP services answer without authentication", Position.REMOTE, mode="red", frameworks=("hermes", "openclaw"))
def unauth_http(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    settings = load_settings(target, plat)
    pids = set(target.pids)
    for pid in list(pids):
        pids.update(c["pid"] for c in plat.children(pid))
    lay = target.layout
    known = set(settings.service_ports().values())
    sockets = plat.listening_sockets()  # NotSupported → skip
    targets = {(s["ip"], s["port"]) for s in sockets if s["pid"] in pids or s["port"] in known}
    if not targets:
        out.note("no daemon TCP listeners to probe" + ("" if target.pids else " (daemon not running)"))
        return out
    paths = tuple(dict.fromkeys(lay.http_probe_paths + lay.http_ui_paths))
    for ip, port in sorted(targets, key=lambda t: t[1]):
        try:
            results = {path: _http_get(ip, port, path) for path in paths}
        except NotLocal as e:
            out.note(str(e))
            continue
        statuses = {p: st for p, (st, _) in results.items() if st is not None}
        if not statuses:
            out.note(f"{ip}:{port} did not speak HTTP ({results[paths[0]][1]})")
            continue
        unauth_paths = [p for p, st in statuses.items() if 200 <= st < 300 and p not in lay.http_ui_paths]
        ui_paths = [p for p, st in statuses.items() if 200 <= st < 300 and p in lay.http_ui_paths]
        auth_paths = [p for p, st in statuses.items() if st in (401, 403, 407)]
        ev = [f"GET {p} → {st}" for p, st in statuses.items()]
        if unauth_paths:
            out.findings.append(Finding(
                "RED-001", f"Port {port} answers {', '.join(unauth_paths)} with 2xx and no credentials",
                Severity.HIGH, Position.REMOTE, f"{ip}:{port}",
                "Verified by connecting from this host: the service served content to an anonymous client. "
                "If NET-001 also shows this port bound beyond loopback, that is a remote, unauthenticated way in.",
                settings.require_auth_fix(),
                f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{port}{unauth_paths[0]}  # expect 401/403",
                ev, tags=["net:unauth:verified"],
            ))
        elif auth_paths:
            out.findings.append(Finding(
                "RED-001", f"Port {port} requires authentication (verified)",
                Severity.INFO, Position.REMOTE, f"{ip}:{port}",
                "The service rejected an anonymous request. Good — listed for the record.",
                "Nothing to do.", None, ev, tags=["net:auth:verified"],
            ))
        elif ui_paths:
            out.findings.append(Finding(
                "RED-001", f"Port {port} serves its web UI shell to anonymous clients; API paths did not answer 2xx",
                Severity.INFO, Position.REMOTE, f"{ip}:{port}",
                "The static UI is served to anyone (that is how single-page apps work); the API behind it did not serve content to an "
                "anonymous GET. This probe cannot exercise the WebSocket/device-pairing handshake, so the policy checks (POL-005) are "
                "the authority on whether that UI is actually gated.",
                "Keep the listener on loopback and the gateway auth mode set; see POL-005.", None, ev, tags=["net:ui:anon"],
            ))
        else:
            out.note(f"{ip}:{port} responded ({', '.join(ev)}) — neither 2xx nor 401/403; inspect manually")
    return out


@check("RED-002", "Probe: credentials readable from the daemon's process environment", Position.LOCAL, mode="red", frameworks=("hermes", "openclaw"))
def process_env_secrets(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    pids = list(target.pids)
    if not pids:
        out.note("daemon not running; process environment cannot be read")
        return out
    for pid in pids:
        try:
            env = plat.process_env(pid)
        except NotSupported as e:
            out.note(str(e))
            continue
        redacted = []
        names = []
        seen = set()
        for k, v in env.items():
            if not v:
                continue
            hits = find_hits(f"{k}={v}")
            if hits:
                r = redact(hits[0].kind, hits[0].raw)
            elif SECRET_NAME.search(k) and len(v) >= 8:
                r = redact("generic-credential", v)
            else:
                continue
            if r.fingerprint in seen:
                continue
            seen.add(r.fingerprint)
            redacted.append(r)
            names.append(f"{k}: {r.kind} {r.display}")
        if not redacted:
            out.findings.append(Finding(
                "RED-002", f"Exec-time environment of pid {pid} holds no credentials",
                Severity.INFO, Position.LOCAL, f"pid {pid}",
                "What this proves: the daemon was not *started* with keys in its environment. What it does not prove: "
                f"{target.layout.display_name} loads its vault into its own memory after start, and /proc/<pid>/environ only shows the exec-time "
                "environment — the keys are still in the process, just not in this file. RED-003 measures that vault directly.",
                "Nothing to do here. Keep secrets out of service units and shell profiles so this stays true.",
                None, [f"{len(env)} variable(s) inspected"], tags=["procenv:clean"],
            ))
            continue
        user = next((p["user"] for p in plat.find_processes(target.layout.process_needle or "") if p["pid"] == pid), None) or "your user"
        out.findings.append(Finding(
            "RED-002", f"{len(redacted)} credential(s) sit in the environment of pid {pid}, readable by any process running as {user}",
            Severity.MEDIUM, Position.LOCAL, f"pid {pid}",
            "Verified by reading the process environment as the same user. This is how .env works — but it means the "
            "blast radius of *any* code running as you (a browser exploit, a malicious npm postinstall, a bad skill) is every key listed. "
            "Nothing needs root.",
            f"Reduce what is loaded: keep only the keys this daemon actually uses in {target.layout.preferred_vault}; use the framework's "
            "secret-manager / secret-reference support so keys are fetched at start and rotated centrally; run the gateway as a dedicated user.",
            f"tr '\\0' '\\n' < /proc/{pid}/environ | grep -cE 'KEY|TOKEN|SECRET'  # Linux",
            names[:15], secrets=redacted, tags=["secret:procenv"],
        ))
    return out


@check("RED-003", "Probe: the vault as any process running as you sees it", Position.LOCAL, mode="red", frameworks=("hermes", "openclaw"))
def vault_blast_radius(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    home, lay = target.home, target.layout
    files = [home / f for f in lay.vault_files] + [
        p for d in lay.vault_dirs for p in (home / d).glob("*") if p.is_file() and not p.is_symlink()
    ]
    redacted = []
    seen = set()
    where: dict[str, list[str]] = defaultdict(list)
    read_any = False
    for p in files:
        if not p.exists() or p.is_symlink():
            continue
        try:
            data = plat.read_nofollow(p, 4 * 1024 * 1024)
        except NotSupported:
            try:
                data = p.read_bytes()
            except OSError as e:
                out.note(f"{p.name}: {e.strerror or e}")
                continue
        except OSError as e:
            out.note(f"{p.name}: {e.strerror or e}")
            continue
        read_any = True
        for h in find_hits(data):
            r = redact(h.kind, h.raw)
            if r.fingerprint in seen:
                continue
            seen.add(r.fingerprint)
            redacted.append(r)
            where[r.kind].append(p.name)
    if not read_any:
        out.note("no vault file could be read")
        return out
    kinds: dict[str, int] = defaultdict(int)
    for r in redacted:
        kinds[r.kind] += 1
    ev = [f"{k}×{n} ({', '.join(sorted(set(where[k])))}) → {BLAST.get(k, BLAST['generic-credential'])}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])]
    out.findings.append(Finding(
        "RED-003", f"Local blast radius: {len(redacted)} credential(s) of {len(kinds)} kind(s) readable by any process running as you",
        Severity.INFO if len(redacted) < 5 else Severity.LOW, Position.LOCAL, str(home),
        "Read the vault exactly as a same-user process would — no exploit, no root. This is what every attack path in this "
        "report ends at, so it is the number to shrink.",
        "Fewer keys in the vault, scoped tokens over master keys, secret-manager references instead of literals, and a dedicated user for the gateway.",
        None, ev[:15], secrets=redacted, tags=["secret:vault"],
    ))
    return out
