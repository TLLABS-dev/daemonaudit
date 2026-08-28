from daemonaudit.discover.hermes import discover_hermes
from daemonaudit.model import Target
from daemonaudit.platform import Platform


def discover_all(plat: Platform, home_override=None) -> list[Target]:
    targets: list[Target] = []
    t = discover_hermes(plat, home_override)
    if t:
        targets.append(t)
    return targets
