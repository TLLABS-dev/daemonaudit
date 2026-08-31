"""Framework adapters. `discover_all()` finds every supported daemon at its usual home,
or — with `--home` — recognises which framework a directory belongs to from its contents."""

from __future__ import annotations

from daemonaudit.discover.hermes import discover_hermes, looks_like_hermes
from daemonaudit.discover.openclaw import discover_openclaw, looks_like_openclaw
from daemonaudit.model import Target
from daemonaudit.platform import Platform

FRAMEWORKS = ("hermes", "openclaw")


def discover_all(plat: Platform, home_override=None) -> list[Target]:
    targets: list[Target] = []
    if home_override:
        from pathlib import Path

        given = Path(home_override).expanduser()
        if looks_like_openclaw(given):
            t = discover_openclaw(plat, home_override)
        elif looks_like_hermes(given):
            t = discover_hermes(plat, home_override)
        else:
            t = None  # an unrecognised directory is not a daemon home; never scan it as one
        return [t] if t else []
    for fn in (discover_hermes, discover_openclaw):
        t = fn(plat)
        if t:
            targets.append(t)
    return targets
