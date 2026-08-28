from __future__ import annotations

import json

from daemonaudit.model import ScanReport
from daemonaudit.redact import scrub


def to_json(report: ScanReport) -> str:
    """Serialise, then scrub the serialised text: a secret cannot survive both."""
    return scrub(json.dumps(report.to_dict(), indent=2, default=str))
