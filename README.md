# Netallion MCP Lite

[![PyPI](https://img.shields.io/pypi/v/netallion-mcp-lite.svg)](https://pypi.org/project/netallion-mcp-lite/)
[![Python](https://img.shields.io/pypi/pyversions/netallion-mcp-lite.svg)](https://pypi.org/project/netallion-mcp-lite/)
[![CI](https://github.com/netallion/netallion-mcp-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/netallion/netallion-mcp-lite/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Free, local, IP-safe AI-development security — an MCP server from Netallion.**

<!-- mcp-name: io.github.netallion/netallion-mcp-lite -->

Netallion MCP Lite is a small [Model Context Protocol](https://modelcontextprotocol.io) server that helps you and your AI coding assistants avoid the most common mistake in AI-assisted development: leaking a credential. It flags a curated set of **commodity, high-confidence** secrets and credentials (AWS, GitHub, Stripe, OpenAI, private keys, database URIs, and more) in text and files.

It runs **entirely on your machine**. No account. No data sent to Netallion. Detected secrets are **redacted** before results are returned, so they are safe to hand back into an AI assistant's context.

Part of Netallion's **Agentic Development Governance** approach — secret detection is one capability, not the whole story.

---

## What it is (and isn't)

| | **Netallion MCP Lite** (this package) | **Netallion AI Assurance** (the platform) |
|---|---|---|
| Price | Free | Commercial (free trial) |
| Runs | Locally, no account | SaaS + IDE + CI |
| Detection | ~27 commodity, high-confidence checks | Advanced detection well beyond commodity patterns |
| AI/MCP governance | — | AI provider governance, MCP governance |
| Policy & visibility | — | Central policy management, org-wide visibility |
| Compliance | — | Compliance and audit evidence |
| Data | Nothing leaves your machine | Enterprise controls |

MCP Lite is deliberately limited. It is a genuinely useful local utility **and** an on-ramp: if you want advanced detection, AI/MCP governance, central policy, and audit evidence across your organisation, that lives in **[Netallion AI Assurance](https://www.netallion.ai)**.

This package does **not** contain or depend on Netallion's proprietary detection engine.

---

## Install & run

Requires Python 3.10+.

```bash
pip install netallion-mcp-lite
# or, zero-install:
uvx netallion-mcp-lite
```

It speaks MCP over stdio. Add it to any MCP-compatible client (Claude, Cursor, Windsurf, VS Code, …):

```json
{
  "mcpServers": {
    "netallion-mcp-lite": {
      "command": "netallion-mcp-lite"
    }
  }
}
```

Optionally confine `scan_file` to a specific directory:

```json
{
  "mcpServers": {
    "netallion-mcp-lite": {
      "command": "netallion-mcp-lite",
      "env": { "NETALLION_MCP_LITE_WORKSPACE_ROOT": "/path/to/your/project" }
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `scan_text` | Scan a string for commodity secrets; returns redacted findings (rule, severity, line/column, remediation). |
| `scan_file` | Scan a file **inside the workspace root**; sensitive files (`.env`, keys) are refused; findings redacted. |
| `list_supported_checks` | List the commodity checks (no secrets). |
| `about` | About the tool, privacy posture, and Lite vs AI Assurance. |

Run `list_supported_checks` to see the full set. Findings never include the full secret value.

## Privacy

Local-only. No telemetry. No source, file contents, prompts, or secrets are sent anywhere. See [PRIVACY.md](PRIVACY.md).

## Scope & limitations

- Commodity, high-confidence formats only — it will not catch obfuscated, encoded, or org-specific secrets. That is by design; advanced detection is part of Netallion AI Assurance.
- `scan_file` reads only within a single workspace root and refuses obviously-sensitive files.
- No generic high-entropy scanning (it produces noise without advanced technique).

We make no claims about detection rates, false-positive rates, customer adoption, certifications, or regulatory compliance for this free utility.

## Links

- Netallion AI Assurance — https://www.netallion.ai
- VS Code / Cursor / Windsurf extension — [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=netallion.netallion-ai-assurance) · [Open VSX](https://open-vsx.org/extension/netallion/netallion-ai-assurance)
- Azure Marketplace — [Netallion AI Assurance](https://marketplace.microsoft.com/en-us/product/netallion.netallion-ai-assurance)

## License

MIT — see [LICENSE](LICENSE).
