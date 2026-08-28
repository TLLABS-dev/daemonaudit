"""Adversarial corpus for secret-detector transformations and provider shapes.

Originally an xfail matrix (Codex task C2, 2026-08-27). Every row is now enforced;
add new evasions as xfail and promote them when the detector catches up.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from daemonaudit.redact import find_secrets


FIXTURES = Path(__file__).parent / "fixtures" / "evasion"


def _hits(name: str, transform: str = "text") -> list[tuple[str, str]]:
    path = FIXTURES / name
    if transform == "sqlite-page":
        return find_secrets(base64.b64decode(path.read_text(encoding="utf-8").strip()))
    return find_secrets(path.read_text(encoding="utf-8"))


def _assert_hit(name: str, kind: str, raw: str, transform: str = "text") -> None:
    assert (kind, raw) in _hits(name, transform)


@pytest.mark.parametrize(
    ("name", "kind", "raw", "transform"),
    [
        pytest.param(
            "split-lines.env",
            "openai-api-key",
            "sk-proj-FAKEabcde12345FAKEabcde67890",
            "text",
        ),
        pytest.param(
            "wrapped-values.yaml",
            "openai-api-key",
            "sk-proj-FAKEabcde12345FAKEabcde67890",
            "text",
        ),
        pytest.param(
            "wrapped-values.yaml",
            "anthropic-api-key",
            "sk-ant-FAKEabcde12345FAKEabcde67890",
            "text",
        ),
        pytest.param(
            "yaml-block.yaml",
            "bearer-token",
            "FAKEabcde12345FAKEabcde67890",
            "text",
        ),
        pytest.param(
            "sqlite-null-page.b64",
            "github-token",
            "ghp_FAKEabcde12345FAKEabcde67890FAKE",
            "sqlite-page",
        ),
        pytest.param(
            "quoted-backslashes.env",
            "openai-api-key",
            "sk-proj-FAKEabcde12345FAKEabcde67890",
            "text",
        ),
        pytest.param(
            "unicode-lookalikes.env",
            "github-token",
            "ghp_FAKEabcde12345FAKEabcde67890FAKE",
            "text",
        ),
        pytest.param(
            "lowercase-token.env",
            "generic-credential",
            "fakeabcdefghijklmnopqrstuvwxyz12",
            "text",
        ),
        pytest.param(
            "providers.env",
            "azure-openai-api-key",
            "FAKEazure12345FAKEazure67890FAKE",
            "text",
        ),
        pytest.param(
            "providers.env",
            "google-oauth-client-secret",
            "FAKEgoogle12345-FAKEgoogle67890.apps",
            "text",
        ),
    ],
)
def test_current_evasions(name: str, kind: str, raw: str, transform: str) -> None:
    _assert_hit(name, kind, raw, transform)


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        ("anthropic-api-key", "sk-ant-FAKEabcde12345FAKEabcde67890"),
        ("url-embedded-credential", "FAKEpass12345FAKEpass67890"),
        ("bearer-token", "FAKEbearer12345FAKEbearer67890"),
    ],
)
def test_supported_env_and_url_forms(kind: str, raw: str) -> None:
    _assert_hit("url-and-export.env", kind, raw)


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        ("discord-bot-token", "MFAKEabcde12345FAKEabcde.abc123.FAKEabcde12345FAKEabcde67890"),
        ("openrouter-api-key", "sk-or-v1-0123456789abcdef0123456789abcdef01234567"),
        ("slack-app-token", "xapp-1-A1B2C3D4-1234567890-0123456789abcdef0123456789abcdef01234567"),
    ],
)
def test_supported_provider_shapes(kind: str, raw: str) -> None:
    _assert_hit("providers.env", kind, raw)


def test_documentation_and_secret_references_are_not_hits() -> None:
    assert _hits("non-secrets.txt") == []
