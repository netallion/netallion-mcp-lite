# Privacy & Data Flow — Netallion MCP Lite

**Short version: everything runs locally. Nothing leaves your machine.**

## What happens when you use it

- `scan_text` and `scan_file` run entirely in-process using local regular
  expressions. The text/file you scan is **never transmitted anywhere**.
- No source code, file contents, prompts, secrets, or credentials are sent to
  Netallion or any third party.
- Detected secret values are **redacted** before results are returned, so even
  the tool's own output does not contain full credentials.

## Telemetry

- **None.** This package sends no usage analytics, no pings, no crash reports.
- There is no network client in the core scanner.

## Network

- Core scanning makes **no network calls**.
- The only time anything is fetched from the network is at *install* time, when
  your package manager downloads this package and its single public dependency
  (the MCP SDK) from your configured package index.

## Data retention

- The tool stores nothing. It holds the text you pass it in memory only for the
  duration of a scan.

## Future optional features

- If any optional outbound feature is ever added (for example, connecting to
  Netallion AI Assurance), it will be **explicitly opt-in**, off by default, and
  documented separately. The core Lite scanner will always work fully offline.

## Contact

Questions: https://www.netallion.ai
