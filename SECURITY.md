# Security Policy

Netallion MCP Lite runs **entirely locally** and transmits nothing to Netallion
(see [PRIVACY.md](PRIVACY.md)). We still take security seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for security reports.

- Preferred: GitHub's private
  [**Report a vulnerability**](https://github.com/netallion/netallion-mcp-lite/security/advisories/new)
  advisory flow.
- Alternatively, contact us via https://www.netallion.ai.

We aim to acknowledge reports within a few business days and will coordinate a
fix and disclosure timeline with you.

## Scope

**In scope** — the `netallion-mcp-lite` package in this repository, e.g.:
- path traversal or workspace-escape in `scan_file`,
- full/unredacted secret material appearing in tool output,
- supply-chain issues in the published artifact.

**Out of scope** — the commercial Netallion AI Assurance platform; report those
via https://www.netallion.ai.
