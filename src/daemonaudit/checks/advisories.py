"""ADV-001: version staleness and dismissed advisories — from Hermes's own local
cache only. daemonaudit never contacts the network."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from daemonaudit.discover.hermes_config import load_settings
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import NotSupported, Platform
from daemonaudit.registry import check


@check("ADV-001", "Outdated daemon or dismissed security advisories", Position.CONTENT)
def advisories(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    settings = load_settings(target, plat)
    p = target.home / ".update_check"
    try:
        raw = plat.read_nofollow(p, 64 * 1024)
    except NotSupported:
        raw = p.read_bytes() if p.exists() else b""
    except FileNotFoundError:
        raw = b""
    except OSError as e:
        out.note(f".update_check unreadable ({e.strerror or e})")
        raw = b""
    if raw:
        try:
            d = json.loads(raw.decode("utf-8", "replace"))
            behind = int(d.get("behind") or 0)
            ts = d.get("ts")
            age = ""
            if isinstance(ts, (int, float)):
                days = (datetime.now(timezone.utc) - datetime.fromtimestamp(ts, timezone.utc)).days
                age = f", checked {days} day(s) ago"
            if behind > 0:
                out.findings.append(
                    Finding(
                        check_id="ADV-001",
                        title=f"Hermes is {behind} update(s) behind (v{d.get('ver') or target.version or '?'}{age})",
                        severity=Severity.LOW if behind < 10 else Severity.MEDIUM,
                        position=Position.CONTENT,
                        asset=str(p),
                        why=(
                            "Per Hermes's own update check. Agent frameworks ship security fixes often "
                            "(gateway auth, injection guards, dependency advisories); running behind means running known bugs."
                        ),
                        fix="hermes update   # then restart the gateway",
                        verify_cmd="hermes doctor",
                        evidence=[f"behind={behind}"],
                    )
                )
        except (ValueError, TypeError):
            out.note(".update_check is not valid JSON")
    else:
        out.note(".update_check absent — Hermes has not run its update check")

    acked = settings.get("security.acked_advisories") or []
    if acked:
        out.findings.append(
            Finding(
                check_id="ADV-001",
                title=f"{len(acked)} security advisory(ies) have been dismissed",
                severity=Severity.INFO,
                position=Position.CONTENT,
                asset=str(target.home / "config.yaml"),
                why="`hermes doctor --ack` hides an advisory permanently. Make sure each one was resolved, not just silenced.",
                fix="Review: remove ids from security.acked_advisories in config.yaml to see them again.",
                verify_cmd="hermes doctor",
                evidence=[str(a) for a in acked[:10]],
            )
        )
    return out
