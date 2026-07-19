# Contributing

Thanks for your interest in Netallion MCP Lite.

## Principles

- **Commodity only.** This package intentionally ships ~27 *publicly-documented*,
  high-confidence credential checks. It is **not** the place for advanced or
  proprietary detection — that lives in
  [Netallion AI Assurance](https://www.netallion.ai). A new rule must pass:
  *"would we be comfortable publishing this exact detection logic publicly for
  anyone to copy?"* If not, it doesn't belong here.
- **Local-first & private.** No network calls and no telemetry in the core
  scanner. Detected secrets must always be redacted before they are returned.
- **Dependency-light.** The only runtime dependency is the MCP SDK. The public
  firewall test (`tests/test_public_firewall.py`) enforces this — it fails if any
  `netallion_*` import other than `netallion_mcp_lite` appears, or if any runtime
  dependency other than `mcp` is declared.

## Dev setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e . pytest
pytest
```

## Pull requests

- Add or update tests for every change.
- Keep patterns simple and linear-time (no catastrophic backtracking).
- CI must pass across Python 3.10–3.12.

By contributing you agree that your contributions are licensed under the MIT
License.
