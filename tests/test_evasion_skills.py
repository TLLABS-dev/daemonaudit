"""Adversarial and false-positive corpus for SKILL-001.

Originally a 15-row xfail matrix (Codex task C3, 2026-08-27); every row is now enforced.
Add new evasions as xfail and promote them when the detector catches up.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from daemonaudit.checks.skills import skills
from daemonaudit.discover.hermes import HERMES_LAYOUT
from daemonaudit.model import Severity, Target
from daemonaudit.platform import get_platform


FIXTURES = Path(__file__).parent / "fixtures" / "evasion-skills"
INVENTORY = "Inventory:"


def _scan(tmp_path: Path, skill_name: str, *, vendor: str | None = None, modify: bool = False):
    home = tmp_path / ".hermes"
    installed = home / "skills" / "fixture" / skill_name
    shutil.copytree(FIXTURES / skill_name, installed)
    if vendor:
        vendor_path = home / HERMES_LAYOUT.bundled_skills_dir / "fixture" / skill_name
        shutil.copytree(FIXTURES / skill_name, vendor_path)
        if modify:
            (installed / "SKILL.md").write_text((installed / "SKILL.md").read_text() + "\nModified locally.\n")
    target = Target("hermes", home, layout=HERMES_LAYOUT)
    return skills(target, get_platform()).findings


def _risk(findings):
    return [f for f in findings if not f.title.startswith(INVENTORY)]


@pytest.mark.parametrize(
    ("skill_name", "title_fragment"),
    [
        pytest.param(
            "pipe-line-continuation",
            "pipes a remote download",
        ),
        pytest.param(
            "pipe-variables",
            "pipes a remote download",
        ),
        pytest.param(
            "eval-substitution",
            "pipes a remote download",
        ),
        pytest.param(
            "python-subprocess",
            "pipes a remote download",
        ),
        pytest.param(
            "alternate-network",
            "reads credentials and talks",
        ),
        pytest.param(
            "obfuscated-secret-read",
            "reads credentials and talks",
        ),
        pytest.param(
            "injection-obfuscated",
            "Prompt-injection",
        ),
        pytest.param(
            "unicode-soft-hyphen",
            "Invisible Unicode",
        ),
        pytest.param(
            "python-c-network",
            "reads credentials and talks",
        ),
        pytest.param(
            "frontmatter-block",
            "requests provider credentials",
        ),
        pytest.param(
            "frontmatter-block",
            "requests the vault",
        ),
        pytest.param(
            "frontmatter-metadata",
            "requests provider credentials",
        ),
        pytest.param(
            "frontmatter-metadata",
            "requests the vault",
        ),
    ],
)
def test_skill_evasions(tmp_path: Path, skill_name: str, title_fragment: str) -> None:
    assert any(title_fragment in f.title for f in _risk(_scan(tmp_path, skill_name)))


def test_legitimate_api_client_is_quiet(tmp_path: Path) -> None:
    assert _risk(_scan(tmp_path, "legit-api-client")) == []


def test_legitimate_security_review_rubric_is_quiet(tmp_path: Path) -> None:
    assert _risk(_scan(tmp_path, "legit-documentation")) == []


@pytest.mark.parametrize("skill_name", ["legit-safe-patterns"])
def test_legitimate_patterns_are_quiet(tmp_path: Path, skill_name: str) -> None:
    assert _risk(_scan(tmp_path, skill_name)) == []


def test_inline_scoped_frontmatter_is_not_a_vault_request(tmp_path: Path) -> None:
    findings = _risk(_scan(tmp_path, "frontmatter-inline-safe"))
    assert not any("requests the vault" in f.title for f in findings)


def test_identical_vendor_finding_is_downgraded(tmp_path: Path) -> None:
    findings = _risk(_scan(tmp_path, "vendor-risk", vendor="same"))
    injection = next(f for f in findings if "Prompt-injection" in f.title)
    assert injection.severity == Severity.LOW
    assert "(bundled)" in " ".join(injection.evidence)


def test_modified_vendor_file_is_not_downgraded(tmp_path: Path) -> None:
    findings = _risk(_scan(tmp_path, "vendor-risk", vendor="same", modify=True))
    injection = next(f for f in findings if "Prompt-injection" in f.title)
    assert injection.severity == Severity.MEDIUM
    assert "(bundled)" not in " ".join(injection.evidence)
