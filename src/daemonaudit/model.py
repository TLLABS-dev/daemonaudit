"""Core data model.

Design rules (see AGENTS.md):
- A RedactedSecret never holds the raw value. There is no field for it.
- Finding.evidence holds redacted strings only.
- Every Finding says why it matters, how to fix it, and how to verify the fix.
- A check that could not fully inspect its targets says so (CheckOutput.coverage_notes);
  it never quietly returns "clean".
"""

from __future__ import annotations

import platform as _platform
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Position(str, Enum):
    """Where the attacker is standing. Findings are grouped by this in the report."""

    REMOTE = "remote"
    CONTENT = "content"
    SUPPLY_CHAIN = "supply-chain"
    LOCAL = "local"

    @property
    def label(self) -> str:
        return {
            "remote": "Remote attacker (unauthenticated, on the network)",
            "content": "Injected content (the agent reads something hostile)",
            "supply-chain": "Malicious skill / MCP server / plugin",
            "local": "Local attacker (another user or process on this host)",
        }[self.value]


@dataclass(frozen=True)
class RedactedSecret:
    kind: str
    display: str
    fingerprint: str


@dataclass
class Remediation:
    description: str
    commands: list[str] = field(default_factory=list)
    reversible: bool = True

    def apply(self) -> None:  # pragma: no cover - v0.2
        raise NotImplementedError("Remediation.apply() lands in v0.2")


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    position: Position
    asset: str
    why: str
    fix: str
    verify_cmd: str | None = None
    evidence: list[str] = field(default_factory=list)
    secrets: list[RedactedSecret] = field(default_factory=list)
    remediation: Remediation | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["position"] = self.position.value
        return d


@dataclass
class CheckOutput:
    """What a check returns. `coverage_notes` lists anything it could not inspect."""

    findings: list[Finding] = field(default_factory=list)
    coverage_notes: list[str] = field(default_factory=list)

    def note(self, msg: str) -> None:
        self.coverage_notes.append(msg)


# Result statuses. "off" is a deliberate opt-out (red probes without --red) and does not
# make a scan incomplete; "skip", "error" and "incomplete" do.
STATUSES = ("pass", "fail", "skip", "off", "error", "incomplete")
INCOMPLETE_STATUSES = {"skip", "error", "incomplete"}


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status,
            "note": self.note,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Layout:
    """Where a framework keeps things. Filled by the discover/ adapter; checks read it
    and never hard-code paths themselves."""

    vault_files: list[str] = field(default_factory=list)  # hold credentials on purpose
    vault_dirs: list[str] = field(default_factory=list)
    private_files: list[str] = field(default_factory=list)  # transcripts/config/state
    private_dirs: list[str] = field(default_factory=list)
    sprawl_paths: list[str] = field(default_factory=list)  # secrets must NOT appear here
    exclude_dirs: set[str] = field(default_factory=set)  # never walk, at any depth (venv, node_modules...)
    exclude_root_dirs: set[str] = field(default_factory=set)  # never walk, only directly under home (framework source)
    data_extensions: set[str] = field(default_factory=set)  # an x-bit here is suspicious
    backup_markers: tuple[str, ...] = (".bak", "~", ".orig", ".old")
    transcript_hints: tuple[str, ...] = ()
    preferred_vault: str = ".env"  # where the fix text tells people to put credentials
    bundled_skills_dir: str | None = None  # relative to home: vendor copy of shipped skills, if any

    def is_backup(self, name: str) -> bool:
        return any(m in name if m.startswith(".") else name.endswith(m) for m in self.backup_markers)


@dataclass
class Target:
    framework: str
    home: Path
    version: str | None = None
    pids: list[int] = field(default_factory=list)
    layout: Layout = field(default_factory=Layout)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def vault_path(self) -> Path:
        return self.home / self.layout.preferred_vault

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "home": str(self.home),
            "version": self.version,
            "pids": self.pids,
            "meta": {k: v for k, v in self.meta.items() if not k.startswith("_")},
        }


# Exit codes. Precedence top to bottom.
EXIT_HIGH = 2  # any HIGH/CRITICAL finding
EXIT_FINDINGS = 1  # any finding at all
EXIT_INCOMPLETE = 4  # no findings, but at least one check skipped/errored/incomplete
EXIT_CLEAN = 0
EXIT_NO_TARGET = 3
EXIT_OPERATIONAL = 5  # the tool itself failed

EXIT_CODE_HELP = (
    "exit codes: 0 clean and complete · 1 findings · 2 high/critical findings · "
    "3 no supported daemon found · 4 no findings but scan incomplete (skipped/errored checks) · "
    "5 tool error. Precedence: 2 > 1 > 4 > 0."
)


@dataclass
class ScanReport:
    tool_version: str
    targets: list[Target] = field(default_factory=list)
    results: list[CheckResult] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    host: dict[str, str] = field(
        default_factory=lambda: {
            "hostname": socket.gethostname(),
            "os": _platform.system(),
            "release": _platform.release(),
        }
    )

    @property
    def findings(self) -> list[Finding]:
        out = [f for r in self.results for f in r.findings]
        return sorted(out, key=lambda f: (-f.severity.rank, f.position.value, f.asset))

    @property
    def incomplete_results(self) -> list[CheckResult]:
        return [r for r in self.results if r.status in INCOMPLETE_STATUSES]

    @property
    def is_complete(self) -> bool:
        return not self.incomplete_results

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def exit_code(self) -> int:
        if any(f.severity.rank >= Severity.HIGH.rank for f in self.findings):
            return EXIT_HIGH
        if self.findings:
            return EXIT_FINDINGS
        if not self.is_complete:
            return EXIT_INCOMPLETE
        return EXIT_CLEAN

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "daemonaudit",
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "host": self.host,
            "targets": [t.to_dict() for t in self.targets],
            "results": [r.to_dict() for r in self.results],
            "summary": {**self.counts(), "complete": self.is_complete, "exit_code": self.exit_code()},
        }
