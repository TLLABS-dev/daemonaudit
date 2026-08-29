"""Check registry.

A check is `(target, platform) -> CheckOutput | list[Finding]` registered with
@check(...). Status mapping (never a false pass):
  findings                → fail   (coverage notes, if any, attached as note)
  no findings, no notes   → pass
  no findings, notes      → incomplete
  raises Skipped/NotSupported → skip
  raises anything else    → error
  red probe without --red → off   (deliberate; does not make the scan incomplete)
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from typing import Callable

from daemonaudit.model import CheckOutput, CheckResult, Finding, Position, Target
from daemonaudit.platform import Platform
from daemonaudit.platform.base import NotSupported

CheckFn = Callable[[Target, Platform], "CheckOutput | list[Finding]"]


class Skipped(Exception):
    pass


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    position: Position
    mode: str  # "blue" | "red"
    frameworks: tuple[str, ...]
    fn: CheckFn


CHECKS: list[Check] = []


def check(id: str, title: str, position: Position, mode: str = "blue", frameworks: tuple[str, ...] = ("hermes",)):
    def deco(fn: CheckFn) -> CheckFn:
        # One id means one class of weakness. A framework may carry its own implementation,
        # but two implementations must never both apply to the same framework.
        for c in CHECKS:
            if c.id == id and set(c.frameworks) & set(frameworks):
                raise RuntimeError(f"duplicate check id {id} for {sorted(set(c.frameworks) & set(frameworks))}")
        CHECKS.append(Check(id=id, title=title, position=position, mode=mode, frameworks=frameworks, fn=fn))
        return fn

    return deco


def _coerce(out: "CheckOutput | list[Finding]") -> CheckOutput:
    return out if isinstance(out, CheckOutput) else CheckOutput(findings=list(out))


def run_all(target: Target, plat: Platform, include_red: bool = False) -> list[CheckResult]:
    results: list[CheckResult] = []
    fw = target.framework
    for c in CHECKS:
        if fw not in c.frameworks:
            continue
        if c.mode == "red" and not include_red:
            results.append(CheckResult(c.id, c.title, "off", note="red-team probes are opt-in (--red)", framework=fw))
            continue
        try:
            out = _coerce(c.fn(target, plat))
        except (Skipped, NotSupported) as e:
            results.append(CheckResult(c.id, c.title, "skip", note=str(e), framework=fw))
            continue
        except Exception:  # noqa: BLE001 - an error must never look like a pass
            results.append(CheckResult(c.id, c.title, "error", note=traceback.format_exc(limit=3), framework=fw))
            continue
        note = "; ".join(out.coverage_notes) if out.coverage_notes else None
        if out.findings and all(f.severity.value == "info" for f in out.findings):
            status = "info"
        elif out.findings:
            status = "fail"
        elif out.coverage_notes:
            status = "incomplete"
        else:
            status = "pass"
        results.append(CheckResult(c.id, c.title, status, findings=out.findings, note=note, framework=fw))
    return results


def load_builtin_checks() -> None:
    import daemonaudit.checks.secrets  # noqa: F401
    import daemonaudit.checks.perms  # noqa: F401
    import daemonaudit.checks.network  # noqa: F401
    import daemonaudit.checks.policy  # noqa: F401
    import daemonaudit.checks.skills  # noqa: F401
    import daemonaudit.checks.advisories  # noqa: F401
    import daemonaudit.checks.policy_openclaw  # noqa: F401
    import daemonaudit.probes.red  # noqa: F401
