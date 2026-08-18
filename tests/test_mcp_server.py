"""Host MCP server: no Docker, no LLM — skills + finding persistence."""

from __future__ import annotations

import json
from io import BytesIO
from typing import TYPE_CHECKING, Any

import pytest

import strix.report.state as report_state_mod
from strix.interface import mcp_server
from strix.interface.mcp_server import (
    bootstrap_mcp_run,
    handle_message,
    mcp_tool_descriptors,
    run_mcp,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def mcp_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    bootstrap_mcp_run("mcp-test")
    yield
    report_state_mod._global_report_state = None


def test_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as exc:
        run_mcp(["--help"])
    assert exc.value.code == 0


def _call(method: str, params: dict[str, Any] | None = None, *, msg_id: int = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        msg["params"] = params
    response = handle_message(msg)
    assert response is not None
    return response


def test_initialize_advertises_strix() -> None:
    result = _call("initialize")["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert result["serverInfo"]["name"] == "strix"
    assert "pentester" in result["instructions"]


def test_tools_list_includes_skill_and_report_tools() -> None:
    names = {tool["name"] for tool in mcp_tool_descriptors()}
    assert {
        "list_skills",
        "load_skill",
        "create_vulnerability_report",
        "list_reports",
        "get_report",
        "executive_summary",
    } <= names
    assert "create_agent" not in names
    assert "finish_scan" not in names


@pytest.mark.usefixtures("mcp_run")
def test_list_skills_returns_xss() -> None:
    text = _call("tools/call", {"name": "list_skills"})["result"]["content"][0]["text"]
    catalog = json.loads(text)
    vuln_names = {item["name"] for item in catalog.get("vulnerabilities", [])}
    assert "xss" in vuln_names


@pytest.mark.usefixtures("mcp_run")
def test_load_skill_returns_markdown() -> None:
    result = _call("tools/call", {"name": "load_skill", "arguments": {"skills": ["xss"]}})["result"]
    assert result["isError"] is False
    text = result["content"][0]["text"]
    assert "Skill: xss" in text
    assert "xss" in text.lower()


@pytest.mark.usefixtures("mcp_run")
def test_unknown_tool_is_error() -> None:
    result = _call("tools/call", {"name": "nuke_prod"})["result"]
    assert result["isError"] is True


@pytest.mark.usefixtures("mcp_run")
def test_file_and_list_vulnerability(tmp_path: Path) -> None:
    payload = {
        "title": "Reflected XSS in q",
        "description": "Search reflects unsanitized q.",
        "impact": "Session cookie theft in the victim browser.",
        "target": "https://app.example.com",
        "technical_analysis": "q is echoed into HTML without encoding.",
        "poc_description": "Open /search?q=<script>alert(1)</script> as the victim.",
        "poc_script_code": "curl 'https://app.example.com/search?q=<script>alert(1)</script>'",
        "remediation_steps": "HTML-encode q before render.",
        "evidence": (
            "```http\n"
            "GET /search?q=<script>alert(1)</script> HTTP/1.1\n"
            "Host: app.example.com\n\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n\n"
            "<div>Results for <script>alert(1)</script></div>\n"
            "```"
        ),
        "assumptions": "Victim is logged in and visits the crafted URL.",
        "verification": "Re-ran the curl PoC twice; both times HTTP 200, payload reflected.",
        "fix_effort": "low",
        "cvss_breakdown": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N",
        },
        "endpoint": "/search",
        "method": "GET",
        "cwe": "CWE-79",
    }
    filed = _call(
        "tools/call",
        {"name": "create_vulnerability_report", "arguments": payload},
    )["result"]
    assert filed["isError"] is False
    assert "created (not persisted)" not in filed["content"][0]["text"]

    listed = json.loads(
        _call("tools/call", {"name": "list_reports"})["result"]["content"][0]["text"]
    )
    assert listed["success"] is True
    assert listed["total_count"] == 1
    assert listed["reports"][0]["title"] == "Reflected XSS in q"
    assert (tmp_path / "strix_runs" / "mcp-test" / "vulnerabilities.json").is_file()


@pytest.mark.usefixtures("mcp_run")
def test_executive_summary_counts_by_severity() -> None:
    state = report_state_mod.get_global_report_state()
    assert state is not None
    state.add_vulnerability_report(title="Crit", severity="critical", target="t", cvss=9.8)
    state.add_vulnerability_report(title="Med", severity="medium", target="t", cvss=5.0)

    result = _call("tools/call", {"name": "executive_summary"})["result"]
    assert result["isError"] is False
    summary = json.loads(result["content"][0]["text"])
    assert summary["success"] is True
    assert summary["total_count"] == 2
    assert summary["severity_counts"] == {"critical": 1, "medium": 1}
    assert [f["severity"] for f in summary["findings"]] == ["critical", "medium"]
    assert "# Executive Summary" in summary["markdown"]


def test_notification_returns_none() -> None:
    assert handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_stdio_writes_newline_json(monkeypatch: pytest.MonkeyPatch) -> None:
    buf = BytesIO()

    class _Stdout:
        buffer = buf

    monkeypatch.setattr(mcp_server.sys, "stdout", _Stdout())
    mcp_server._write_message({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert buf.getvalue().startswith(b'{"jsonrpc":')
    assert buf.getvalue().endswith(b"\n")
    assert b"Content-Length" not in buf.getvalue()


def test_no_seed_skips_coverage_todos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    from strix.tools.todo.tools import _get_agent_todos

    bootstrap_mcp_run("no-seed", seed_coverage=False)
    todos = _get_agent_todos("mcp")
    assert todos == {}
    instructions = handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})["result"][
        "instructions"
    ]
    assert "coverage checklist" not in instructions
    assert "specialist" in instructions.lower()
    report_state_mod._global_report_state = None


def test_seed_still_creates_coverage_todos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    from strix.tools.todo.tools import _get_agent_todos

    bootstrap_mcp_run("seeded")
    titles = [t["title"] for t in _get_agent_todos("mcp").values()]
    assert any("[coverage]" in title for title in titles)
    report_state_mod._global_report_state = None
