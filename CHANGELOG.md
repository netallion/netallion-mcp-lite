# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project hygiene: `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and README
  badges. No functional/detection changes.

## [0.1.0] - 2026-07-20

### Added
- First public release: a local MCP server with ~27 commodity, high-confidence
  secret/credential checks (AWS, GitHub, GitLab, OpenAI, Anthropic, Google,
  Slack, Stripe, Twilio, SendGrid, npm, PEM keys, JWT, DB URIs, Azure, Telegram,
  generic assignments).
- MCP tools: `scan_text`, `scan_file` (workspace-confined, sensitive files
  refused), `list_supported_checks`, `about`.
- Local-only scanning, no telemetry, and redacted secret output (safe for LLM
  context).

[Unreleased]: https://github.com/netallion/netallion-mcp-lite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/netallion/netallion-mcp-lite/releases/tag/v0.1.0
