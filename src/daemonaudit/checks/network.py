"""NET-001: what the daemon listens on. NET-002: unix socket permissions."""

from __future__ import annotations

import ipaddress

from daemonaudit.checks._walk import rel, walk_entries
from daemonaudit.discover.hermes import DEFAULT_PORTS
from daemonaudit.discover.hermes_config import load_settings
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import Platform
from daemonaudit.registry import check


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return ip in ("localhost",)


def _is_wildcard(ip: str) -> bool:
    return ip in ("0.0.0.0", "::", "*", "")


@check("NET-001", "Daemon listeners reachable from the network", Position.REMOTE)
def listeners(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    settings = load_settings(target, plat)
    pids = set(target.pids)
    names = {}
    for pid in list(pids):
        for c in plat.children(pid):
            pids.add(c["pid"])
            names[c["pid"]] = c["name"]
    known_ports = dict(DEFAULT_PORTS)
    api_port, _ = settings.env("API_SERVER_PORT")
    if api_port and api_port.isdigit():
        known_ports["api_server"] = int(api_port)
    port_names = {v: k for k, v in known_ports.items()}

    sockets = plat.listening_sockets()  # NotSupported → registry marks skip
    ours = [s for s in sockets if (s["pid"] in pids) or (s["port"] in port_names)]

    if not target.pids:
        out.findings.append(
            Finding(
                check_id="NET-001",
                title="Daemon is not running — network exposure could not be observed",
                severity=Severity.INFO,
                position=Position.REMOTE,
                asset=str(target.home),
                why="Listeners can only be attributed to the daemon while it runs. Only well-known daemon ports were checked.",
                fix="Re-run the audit while the gateway is running for a complete picture.",
                verify_cmd="daemonaudit scan  # with the gateway up",
            )
        )

    loop: list[str] = []
    for s in sorted(ours, key=lambda s: (s["port"], s["ip"])):
        who = port_names.get(s["port"], names.get(s["pid"], "daemon"))
        label = f"{s['ip']}:{s['port']} ({who}, pid {s['pid']})"
        if _is_loopback(s["ip"]):
            loop.append(label)
            continue
        exposure = "every interface" if _is_wildcard(s["ip"]) else f"the {s['ip']} interface"
        api_unauth = s["port"] == known_ports["api_server"] and not settings.env_set("API_SERVER_KEY")
        out.findings.append(
            Finding(
                check_id="NET-001",
                title=f"Daemon port {s['port']} ({who}) is bound to {exposure}",
                severity=Severity.CRITICAL if api_unauth else Severity.HIGH,
                position=Position.REMOTE,
                asset=f"{s['ip']}:{s['port']}",
                why=(
                    f"Anything that can reach this host on port {s['port']} can talk to the daemon directly. "
                    + ("The API server has no API_SERVER_KEY, so that access is unauthenticated: remote prompt → tool use. "
                       if api_unauth else "Whether that is safe depends entirely on the auth in front of it. ")
                    + "On a laptop this includes every network you join."
                ),
                fix=(
                    "Bind to 127.0.0.1 (e.g. API_SERVER_HOST=127.0.0.1) and reach it over SSH/Tailscale, "
                    "or put it behind an authenticating reverse proxy. Set API_SERVER_KEY if the API server is enabled."
                ),
                verify_cmd=f"ss -tlnp 2>/dev/null | grep ':{s['port']} ' || lsof -nP -iTCP:{s['port']} -sTCP:LISTEN",
                evidence=[label],
                tags=["net:public"] + (["net:unauth"] if api_unauth else []),
            )
        )
    if loop:
        out.findings.append(
            Finding(
                check_id="NET-001",
                title=f"{len(loop)} daemon listener(s) are loopback-only",
                severity=Severity.INFO,
                position=Position.REMOTE,
                asset=str(target.home),
                why="Loopback listeners are reachable only by processes on this host. That is the right default; listed for inventory.",
                fix="Nothing to do — keep them this way.",
                evidence=loop[:15],
                tags=["net:loopback"],
            )
        )
    return out


@check("NET-002", "Unix sockets accessible to other users", Position.LOCAL)
def unix_sockets(target: Target, plat: Platform) -> CheckOutput:
    if not plat.posix_modes:
        from daemonaudit.registry import Skipped

        raise Skipped(f"{plat.name}: socket permission bits unavailable")
    out = CheckOutput()
    home, lay = target.home, target.layout
    for p in walk_entries(home, lay.exclude_dirs, max_depth=3, exclude_root=lay.exclude_root_dirs):
        try:
            m = plat.file_mode(p)
        except OSError as e:
            out.note(f"cannot stat {p} ({e.strerror or e})")
            continue
        if not m.is_socket:
            continue
        if m.other_writable:
            sev, who = Severity.HIGH, "any local user"
        elif m.group_writable:
            sev, who = Severity.LOW, "the file's group"
        else:
            continue
        r = rel(home, p)
        gateway = p.name == "gateway.sock"
        out.findings.append(
            Finding(
                check_id="NET-002",
                title=f"Socket {r} is writable by {who} (mode {m.octal})",
                severity=Severity.HIGH if (gateway and m.group_writable) else sev,
                position=Position.LOCAL,
                asset=str(p),
                why=(
                    "Connecting to a unix socket needs write permission on it. "
                    + ("This is the gateway control socket: whoever can write to it can drive the agent as you. "
                       if gateway else "Local processes running as other users can send it messages.")
                ),
                fix=f"chmod 600 {p}  # and set umask 077 for the daemon so it is created that way",
                verify_cmd=plat.stat_cmd(p),
                evidence=[f"mode {m.octal}"],
                tags=["local:gateway-socket"] if gateway else [],
            )
        )
    return out
