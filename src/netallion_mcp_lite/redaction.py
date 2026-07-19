"""Redaction helpers.

CRITICAL: results from this package are intended to be handed back into an LLM
context (that is what an MCP tool result is). We therefore never return a full
secret value. Every detected secret is masked before it leaves the scanner.
"""

from __future__ import annotations


def redact(secret: str) -> str:
    """Mask a secret for safe display.

    Short values are fully masked; longer values keep a tiny prefix/suffix so a
    human can correlate the finding without the value ever being usable.
    """
    s = secret.strip()
    if not s:
        return ""
    n = len(s)
    if n <= 8:
        return "*" * n
    # Reveal only a small prefix/suffix — never more than ~1/3 of the value, and
    # for short values (9-11 chars) reveal a prefix only.
    head_len = 4 if n >= 16 else 2
    tail_len = 2 if n >= 12 else 0
    head = s[:head_len]
    tail = s[-tail_len:] if tail_len else ""
    stars = min(n - head_len - tail_len, 12)
    return f"{head}{'*' * stars}{tail}"
