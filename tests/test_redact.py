from daemonaudit.redact import display, find_secrets, scrub
from conftest import FAKE_ANTHROPIC, FAKE_GITHUB, FAKE_TELEGRAM


def test_kinds_detected():
    text = f"a={FAKE_ANTHROPIC} b={FAKE_GITHUB} c={FAKE_TELEGRAM} d=xoxb-1234567890-abcdefghij e=AKIAABCDEFGHIJKLMNOP"
    kinds = {k for k, _ in find_secrets(text)}
    assert {"anthropic-api-key", "github-token", "telegram-bot-token", "slack-token", "aws-access-key-id"} <= kinds


def test_anthropic_not_double_reported_as_openai():
    hits = find_secrets(f"x {FAKE_ANTHROPIC} y")
    assert [k for k, _ in hits] == ["anthropic-api-key"]


def test_generic_credential_and_placeholders():
    assert find_secrets("OPENAI_API_KEY=abcdefghijklmnop1234")[0][0] == "generic-credential"
    assert find_secrets("OPENAI_API_KEY=${OPENAI_API_KEY}") == []
    assert find_secrets("SLACK_TOKEN=op://vault/item/field") == []
    assert find_secrets("PASSWORD=changeme") == []


def test_bytes_scanned_like_strings():
    blob = b"\x00\x01" + FAKE_GITHUB.encode() + b"\xff\xfe"
    assert find_secrets(blob)[0][1] == FAKE_GITHUB


def test_display_is_useless():
    d = display(FAKE_ANTHROPIC)
    assert d.startswith("sk-ant") and d.endswith("0000") and "…" in d and len(d) < 14


def test_scrub_removes_every_secret():
    text = f"log: key {FAKE_ANTHROPIC} and {FAKE_GITHUB}"
    out = scrub(text)
    assert FAKE_ANTHROPIC not in out and FAKE_GITHUB not in out
    assert "sk-ant" in out  # still recognisable
