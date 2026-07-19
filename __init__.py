"""Netallion MCP Lite — free, local, IP-safe AI-development security.

A standalone Model Context Protocol server that scans text and files for a
curated set of *commodity*, high-confidence secret/credential formats — the
kind that are already publicly documented across the ecosystem. It runs fully
locally, sends nothing to Netallion, and requires no account.

This package is intentionally isolated from Netallion's proprietary detection
engine. It is a developer utility and an on-ramp to Netallion AI Assurance —
the enterprise Agentic Development Governance platform — not a reimplementation
of it. See README.md for the Lite vs AI Assurance distinction.
"""

__version__ = "0.1.1"

from netallion_mcp_lite.rules import RULES
from netallion_mcp_lite.scanner import Finding, scan_text

__all__ = ["RULES", "Finding", "scan_text", "__version__"]
