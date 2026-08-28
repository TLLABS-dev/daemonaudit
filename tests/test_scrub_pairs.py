"""Scrub must be broader than detection (Codex C2 #4): values that are deliberately
NOT findings must still disappear from rendered output, and so must the encoded
carrier of anything found through a decoding stream."""
from daemonaudit.redact import find_hits, find_secrets, scrub

BLOB = "Zm9vYmFy0123456789QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123"  # opaque, no known shape
B64_KEY = "c2stcHJvai1GQUtFYWJjZGUxMjM0NUZBS0VhYmNkZTY3ODkw"     # base64 of a FAKE sk-proj key


def test_opaque_blob_is_not_a_finding_but_is_scrubbed():
    assert find_secrets(f"note: {BLOB}") == []
    out = scrub(f"note: {BLOB}")
    assert BLOB not in out and "…" in out


def test_base64_carrier_is_scrubbed_and_provenance_recorded():
    hits = find_hits(f"key_b64: {B64_KEY}")
    assert hits and hits[0].via == "base64" and hits[0].carrier == B64_KEY
    assert B64_KEY not in scrub(f"key_b64: {B64_KEY}")


def test_scrub_leaves_ordinary_report_text_alone():
    text = "6 file(s) in logs/ readable by any user on the host · config.yaml.bak.20260827_140944 (mode 644)"
    assert scrub(text) == text


def test_non_secret_names_are_not_generic_hits():
    assert find_secrets("HERMES_SESSION_KEY=telegram:12345:67890:abcdef") == []
    assert find_secrets("MAX_TOKENS=1234567890123456") == []
    assert find_secrets("SERVICE_TOKEN=fakeabcdefghijklmnopqrstuvwxyz12") != []
