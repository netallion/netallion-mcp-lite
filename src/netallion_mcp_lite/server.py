"""Netallion MCP Lite — standards-compliant MCP server (stdio).

Exposes four tools: scan_text, scan_file, list_supported_checks, about.
Everything runs locally; no secrets or source ever leave the machine, and all
detected secret material is redacted before being returned to the caller.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from netallion_mcp_lite import __version__
from netallion_mcp_lite.rules import RULES
from netallion_mcp_lite.scanner import scan_text as _scan_text
from netallion_mcp_lite.scanner import summarize

# Files we refuse to read even inside the workspace — reading them would defeat
# the point (and their contents would flow back into an LLM context).
_BLOCKED_NAMES = {".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials"}
_BLOCKED_SUFFIXES = (".env", ".key", ".pem", ".p12", ".pfx", ".keystore")
# Example/template env files hold placeholders, not real secrets — safe to scan.
_ENV_EXAMPLE_NAMES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
_MAX_FILE_BYTES = 10_000_000  # 10 MB

_ATTRIBUTION = {
    "product": "Netallion MCP Lite",
    "tagline": "Free, local, IP-safe AI-development security.",
    "learn_more": "https://www.netallion.ai",
    "vs_code_extension": (
        "https://marketplace.visualstudio.com/items?itemName=netallion.netallion-ai-assurance"
    ),
    "azure_marketplace": (
        "https://marketplace.microsoft.com/en-us/product/netallion.netallion-ai-assurance"
    ),
}


def _allowed_root() -> Path:
    """The single directory tree scan_file may read.

    Defaults to the process working directory (the opened workspace). Override
    with NETALLION_MCP_LITE_WORKSPACE_ROOT for explicit confinement.
    """
    root = os.environ.get("NETALLION_MCP_LITE_WORKSPACE_ROOT")
    return Path(root).resolve() if root else Path.cwd().resolve()


def _root_is_too_broad(root: Path) -> bool:
    """A filesystem anchor ('/', 'C:\\') or a home directory is too broad to be a
    safe allowlist — a globally-installed server launched with such a cwd would
    otherwise expose ~/.aws, ~/.ssh, etc.
    """
    try:
        home = Path.home().resolve()
    except (RuntimeError, OSError):
        home = None
    return root == Path(root.anchor) or (
        home is not None and (root == home or root in home.parents)
    )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _err(message: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": message}))]


def _handle_scan_text(arguments: dict[str, Any]) -> list[TextContent]:
    text = arguments.get("text", "")
    source = arguments.get("source", "text")
    if not isinstance(text, str) or not text:
        return [TextContent(type="text", text=json.dumps({"findings": [], "count": 0}))]

    findings = _scan_text(text, source=str(source))
    payload = {
        "source": str(source),
        "count": len(findings),
        "summary": summarize(findings),
        "findings": [f.as_dict() for f in findings],
        "note": "Commodity checks only (Netallion MCP Lite). Secret values are redacted.",
    }
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]


def _handle_scan_file(arguments: dict[str, Any]) -> list[TextContent]:
    file_path = arguments.get("path", "")
    if not file_path or not isinstance(file_path, str):
        return _err("No path provided")

    # .resolve() collapses '..' AND resolves symlinks, so an in-workspace symlink
    # pointing outside resolves to its real (out-of-root) target and is rejected.
    path = Path(file_path).resolve()
    root = _allowed_root()

    if _root_is_too_broad(root):
        return _err(
            "scan_file disabled: workspace root is too broad (filesystem/home root). "
            "Set NETALLION_MCP_LITE_WORKSPACE_ROOT to the workspace directory."
        )
    if not _is_within(path, root):
        return _err("Access denied: path is outside the allowed workspace root")
    name = path.name
    if (
        name in _BLOCKED_NAMES
        # .env, .env.local, .env.production, ... but allow .env.example/.sample/etc.
        or (name.startswith(".env") and name not in _ENV_EXAMPLE_NAMES)
        or any(name.endswith(s) for s in _BLOCKED_SUFFIXES)
    ):
        return _err("Access denied: sensitive file type is not read by scan_file")
    if not path.exists():
        return _err(f"File not found: {file_path}")
    if not path.is_file():
        return _err(f"Not a file: {file_path}")
    if path.stat().st_size > _MAX_FILE_BYTES:
        return _err("File too large (>10MB)")

    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        return _err(f"Cannot read file: {exc}")

    findings = _scan_text(text, source=str(path))
    payload = {
        "path": str(path),
        "count": len(findings),
        "summary": summarize(findings),
        "findings": [f.as_dict() for f in findings],
        "note": "Commodity checks only (Netallion MCP Lite). Secret values are redacted.",
    }
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]


def _handle_list_supported_checks() -> list[TextContent]:
    payload = {
        "count": len(RULES),
        "checks": [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity,
                "description": r.description,
                "tags": list(r.tags),
            }
            for r in RULES
        ],
        "note": (
            "These are commodity, publicly-documented credential formats. "
            "Netallion AI Assurance adds advanced detection, AI/MCP governance, "
            "policy management, and compliance evidence."
        ),
    }
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]


def _handle_about() -> list[TextContent]:
    payload = {
        **_ATTRIBUTION,
        "version": __version__,
        "what_this_is": (
            "Netallion MCP Lite is a free, local MCP server that flags a curated set "
            "of commodity, high-confidence secrets and credentials as you and your AI "
            "assistants work. It runs entirely on your machine — no account, no data "
            "sent to Netallion."
        ),
        "lite_vs_ai_assurance": {
            "netallion_mcp_lite": [
                "Free and local; no account required",
                "~27 commodity, high-confidence credential checks",
                "No source/secrets ever uploaded",
            ],
            "netallion_ai_assurance": [
                "Enterprise Agentic Development Governance platform",
                "Advanced detection beyond commodity patterns",
                "AI provider governance and MCP governance",
                "Central policy management and organisational visibility",
                "Compliance and audit evidence",
            ],
        },
        "privacy": "Local-only scanning. No telemetry. See PRIVACY.md.",
    }
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]


def _dispatch(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Route a tool call by name. Module-level so the unknown-tool path is testable."""
    if name == "scan_text":
        return _handle_scan_text(arguments)
    if name == "scan_file":
        return _handle_scan_file(arguments)
    if name == "list_supported_checks":
        return _handle_list_supported_checks()
    if name == "about":
        return _handle_about()
    return _err(f"Unknown tool: {name}")


def create_server() -> Server:
    server: Server = Server("netallion-mcp-lite")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="scan_text",
                description=(
                    "Scan text locally for commodity secrets and credentials "
                    "(AWS/GitHub/Stripe/etc.). Returns redacted findings with rule id, "
                    "severity, location, and remediation. Nothing is uploaded."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to scan."},
                        "source": {
                            "type": "string",
                            "description": "Optional label for the source (e.g. filename).",
                            "default": "text",
                        },
                    },
                    "required": ["text"],
                },
            ),
            Tool(
                name="scan_file",
                description=(
                    "Scan a file inside the current workspace for commodity secrets. "
                    "Confined to the workspace root; sensitive files (.env, keys) are "
                    "refused. Returns redacted findings."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to a file within the workspace root.",
                        }
                    },
                    "required": ["path"],
                },
            ),
            Tool(
                name="list_supported_checks",
                description="List the commodity checks this Lite server supports (no secrets).",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="about",
                description=(
                    "About Netallion MCP Lite, privacy posture, and how it compares to "
                    "Netallion AI Assurance."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        return _dispatch(name, arguments)

    return server


async def run_server() -> None:
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    import asyncio

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
