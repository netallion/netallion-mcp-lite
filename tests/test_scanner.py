"""Scanner behaviour: detection, redaction-in-output, locations, summary."""

from __future__ import annotations

from netallion_mcp_lite.scanner import scan_text, summarize


def test_finds_multiple_secrets_with_locations():
    text = "\n".join(
        [
            "config = {}",
            "aws = 'AKIAIOSFODNN7EXAMPLE'",
            "gh = 'ghp_" + "a" * 36 + "'",
        ]
    )
    findings = scan_text(text)
    ids = {f.rule_id for f in findings}
    assert "aws-access-key-id" in ids
    assert "github-pat-classic" in ids
    aws = next(f for f in findings if f.rule_id == "aws-access-key-id")
    assert aws.line == 2
    assert aws.column > 0


def test_output_never_contains_full_secret():
    secret = "ghp_" + "z" * 36
    findings = scan_text(f"token = '{secret}'")
    assert findings
    for f in findings:
        assert secret not in f.redacted_preview
        assert secret not in f.as_dict()["redacted_preview"]


def test_summary_counts_by_severity():
    text = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----"
    counts = summarize(scan_text(text))
    assert counts.get("high", 0) >= 1
    assert counts.get("critical", 0) >= 1


def test_empty_and_findings_are_ordered():
    assert scan_text("") == []
    text = "gh=ghp_" + "a" * 36 + "\naws=AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(text)
    lines = [f.line for f in findings]
    assert lines == sorted(lines)
