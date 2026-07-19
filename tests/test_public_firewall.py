"""Public dependency firewall (generic, names nothing private).

Additive to the strict, name-specific firewall in test_dependency_firewall.py —
this one is safe to ship in the public repo. Rule: ``netallion_mcp_lite`` is the
ONLY permitted ``netallion_*`` import anywhere in source or tests, and the only
runtime dependency is the MCP SDK.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

# Any `import netallion_x` / `from netallion_x ...` that is NOT netallion_mcp_lite.
FOREIGN_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+netallion_(?!mcp_lite\b)\w+", re.MULTILINE
)


def _py_files():
    yield from SRC.rglob("*.py")
    yield from (ROOT / "tests").rglob("*.py")


def test_no_foreign_netallion_imports():
    offenders = [
        p.name
        for p in _py_files()
        if FOREIGN_IMPORT.search(p.read_text(encoding="utf-8", errors="replace"))
    ]
    assert not offenders, f"foreign netallion_* import found in: {offenders}"


def test_only_runtime_dependency_is_mcp():
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - py<3.11
        pytest.skip("tomllib unavailable")
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    deps = data.get("project", {}).get("dependencies", [])
    names = {re.split(r"[><=!~ \[]", d.strip())[0].lower() for d in deps}
    assert names <= {"mcp"}, f"unexpected runtime dependency: {names - {'mcp'}}"
