"""Local scanning engine for Netallion MCP Lite.

Runs entirely in-process. No network calls, no telemetry, no dependency on the
Netallion platform. Matched secrets are redacted before being returned.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from netallion_mcp_lite.redaction import redact
from netallion_mcp_lite.rules import RULES

# Cap how much text we scan per call to keep behaviour predictable and fast.
MAX_SCAN_CHARS = 5_000_000  # ~5M characters


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    line: int
    column: int
    redacted_preview: str
    remediation: str

    def as_dict(self) -> dict:
        return asdict(self)


def _secret_from_match(match, secret_group: int) -> str:
    if secret_group and match.lastindex and secret_group <= match.lastindex:
        value = match.group(secret_group)
        if value is not None:
            return value
    return match.group(0)


def scan_text(text: str, source: str = "text") -> list[Finding]:
    """Scan text line by line and return redacted findings, ordered by location."""
    if not text:
        return []
    if len(text) > MAX_SCAN_CHARS:
        text = text[:MAX_SCAN_CHARS]

    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                secret = _secret_from_match(match, rule.secret_group)
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        line=line_no,
                        column=match.start() + 1,
                        redacted_preview=redact(secret),
                        remediation=rule.remediation,
                    )
                )
    findings.sort(key=lambda f: (f.line, f.column, f.rule_id))
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
