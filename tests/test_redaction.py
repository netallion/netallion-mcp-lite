"""Redaction never leaks a full secret."""

from __future__ import annotations

from netallion_mcp_lite.redaction import redact


def test_empty():
    assert redact("") == ""
    assert redact("   ") == ""


def test_short_fully_masked():
    assert redact("abc") == "***"
    assert redact("12345678") == "*" * 8


def test_long_value_is_not_recoverable():
    secret = "AKIAIOSFODNN7EXAMPLE"
    out = redact(secret)
    assert out != secret
    assert secret not in out
    assert out.startswith("AKI")  # small prefix for correlation only
    assert out.endswith("LE")
    assert "*" in out


def test_full_secret_never_substring():
    for secret in ["ghp_" + "a" * 36, "sk-" + "b" * 40, "x" * 100]:
        assert secret not in redact(secret)


def test_borderline_length_reveals_little():
    # 9-11 char values reveal a short prefix only (no tail), most of it masked.
    out = redact("abcdefghi")  # 9 chars
    assert out.startswith("ab")
    assert out.count("*") >= 6
    assert "abcdefghi" not in out
