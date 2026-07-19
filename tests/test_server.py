"""Integration: exercise every MCP tool handler + scan_file confinement."""

from __future__ import annotations

import json
from pathlib import Path

from netallion_mcp_lite import server


def _json(result):
    assert len(result) == 1
    return json.loads(result[0].text)


def test_scan_text_tool_redacts():
    secret = "ghp_" + "q" * 36
    out = _json(server._handle_scan_text({"text": f"token={secret}"}))
    assert out["count"] >= 1
    body = json.dumps(out)
    assert secret not in body
    assert out["note"]


def test_scan_text_empty():
    out = _json(server._handle_scan_text({"text": ""}))
    assert out["count"] == 0


def test_scan_file_within_workspace(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NETALLION_MCP_LITE_WORKSPACE_ROOT", str(tmp_path))
    f = tmp_path / "config.py"
    f.write_text("AWS = 'AKIAIOSFODNN7EXAMPLE'\n")
    out = _json(server._handle_scan_file({"path": str(f)}))
    assert out["count"] >= 1
    assert any(x["rule_id"] == "aws-access-key-id" for x in out["findings"])


def test_scan_file_rejects_outside_root(tmp_path: Path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("AKIAIOSFODNN7EXAMPLE\n")
    monkeypatch.setenv("NETALLION_MCP_LITE_WORKSPACE_ROOT", str(root))
    out = _json(server._handle_scan_file({"path": str(outside)}))
    assert "error" in out


def test_scan_file_refuses_sensitive_files(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NETALLION_MCP_LITE_WORKSPACE_ROOT", str(tmp_path))
    env = tmp_path / ".env"
    env.write_text("SECRET=AKIAIOSFODNN7EXAMPLE\n")
    out = _json(server._handle_scan_file({"path": str(env)}))
    assert "error" in out


def test_scan_file_rejects_too_broad_root(monkeypatch):
    monkeypatch.setenv("NETALLION_MCP_LITE_WORKSPACE_ROOT", str(Path.home()))
    out = _json(server._handle_scan_file({"path": str(Path.home() / "whatever.txt")}))
    assert "error" in out
    assert "too broad" in out["error"]


def test_list_supported_checks():
    out = _json(server._handle_list_supported_checks())
    assert out["count"] == len(server.RULES)
    assert all({"id", "name", "severity"} <= set(c) for c in out["checks"])


def test_about_has_links_and_positioning():
    out = _json(server._handle_about())
    assert out["learn_more"].startswith("https://www.netallion.ai")
    assert "netallion_mcp_lite" in out["lite_vs_ai_assurance"]
    assert "netallion_ai_assurance" in out["lite_vs_ai_assurance"]


def test_scan_file_refuses_env_variants(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NETALLION_MCP_LITE_WORKSPACE_ROOT", str(tmp_path))
    f = tmp_path / ".env.local"
    f.write_text("SECRET=AKIAIOSFODNN7EXAMPLE\n")
    out = _json(server._handle_scan_file({"path": str(f)}))
    assert "error" in out


def test_scan_file_allows_env_example(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NETALLION_MCP_LITE_WORKSPACE_ROOT", str(tmp_path))
    f = tmp_path / ".env.example"
    f.write_text("API_TOKEN=AKIAIOSFODNN7EXAMPLE\n")
    out = _json(server._handle_scan_file({"path": str(f)}))
    assert "error" not in out
    assert out["count"] >= 1


def test_scan_file_rejects_ancestor_of_home_root(monkeypatch):
    parent = Path.home().parent  # e.g. /Users or /home — an ancestor of home
    monkeypatch.setenv("NETALLION_MCP_LITE_WORKSPACE_ROOT", str(parent))
    out = _json(server._handle_scan_file({"path": str(parent / "x.txt")}))
    assert "error" in out
    assert "too broad" in out["error"]


def test_dispatch_unknown_tool_returns_error():
    out = _json(server._dispatch("does_not_exist", {}))
    assert out["error"].startswith("Unknown tool")


def test_dispatch_routes_known_tools():
    assert "count" in _json(server._dispatch("scan_text", {"text": "x"}))
    assert _json(server._dispatch("about", {}))["learn_more"].startswith("https://")


def test_create_server_builds():
    assert server.create_server() is not None
