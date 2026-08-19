"""Host MCP server: no Docker, no LLM — skills + finding persistence."""

from __future__ import annotations

import asyncio
import json
import time
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
from strix.tools.todo.tools import _get_agent_todos


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
    assert "DATA-LEAK PASS EARLY" in result["instructions"]
    assert "data_leakage" in result["instructions"]
    assert "do not redact" in result["instructions"]


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
    assert {"authz_probe", "dedupe_reports", "retest_findings"} <= names
    assert {"cors_probe", "rate_limit_probe", "graphql_introspection", "jwt_audit"} <= names
    assert {"backend_rules_probe", "frontend_secret_scan"} <= names
    assert {"oast_get_domain", "oast_poll", "mcp_tool_poisoning_audit"} <= names
    assert {"profile_target", "plan_tests", "endpoint_risk_rank"} <= names
    assert {"race_probe", "session_invalidation_probe"} <= names
    assert {"injection_fuzz", "prompt_injection_probe"} <= names
    assert "create_agent" not in names
    assert "finish_scan" not in names


@pytest.mark.usefixtures("mcp_run")
def test_list_skills_returns_xss() -> None:
    text = _call("tools/call", {"name": "list_skills"})["result"]["content"][0]["text"]
    catalog = json.loads(text)
    vuln_names = {item["name"] for item in catalog.get("vulnerabilities", [])}
    assert "xss" in vuln_names
    assert "data_leakage" in vuln_names


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

    bootstrap_mcp_run("seeded")
    titles = [t["title"] for t in _get_agent_todos("mcp").values()]
    assert any("[coverage]" in title for title in titles)
    assert any("[data-leak]" in title for title in titles)
    report_state_mod._global_report_state = None


def test_initialize_advertises_resources_and_prompts() -> None:
    caps = _call("initialize")["result"]["capabilities"]
    assert "resources" in caps
    assert "prompts" in caps


@pytest.mark.usefixtures("mcp_run")
def test_resources_list_includes_skills_and_reports() -> None:
    uris = {r["uri"] for r in _call("resources/list")["result"]["resources"]}
    assert "strix://skills" in uris
    assert "strix://reports" in uris
    assert "strix://skill/xss" in uris


@pytest.mark.usefixtures("mcp_run")
def test_resource_read_skill_returns_markdown() -> None:
    result = _call("resources/read", {"uri": "strix://skill/xss"})["result"]
    text = result["contents"][0]["text"]
    assert "Skill: xss" in text


@pytest.mark.usefixtures("mcp_run")
def test_resource_read_unknown_is_error() -> None:
    resp = _call("resources/read", {"uri": "strix://nope"})
    assert "error" in resp


@pytest.mark.usefixtures("mcp_run")
def test_prompts_list_has_pentest_target() -> None:
    names = {p["name"] for p in _call("prompts/list")["result"]["prompts"]}
    assert "pentest_target" in names


@pytest.mark.usefixtures("mcp_run")
def test_prompt_get_injects_target() -> None:
    result = _call(
        "prompts/get",
        {"name": "pentest_target", "arguments": {"target": "https://x.example", "focus": "idor"}},
    )["result"]
    text = result["messages"][0]["content"]["text"]
    assert "https://x.example" in text
    assert "idor" in text
    assert "PROFILE, THEN HARVEST" in text


@pytest.mark.usefixtures("mcp_run")
def test_prompt_get_requires_target() -> None:
    resp = _call("prompts/get", {"name": "pentest_target", "arguments": {}})
    assert "error" in resp


def test_progress_notification_shape() -> None:
    note = mcp_server._progress_notification("tok-1", 0.0, 1.0)
    assert note["method"] == "notifications/progress"
    assert note["params"]["progressToken"] == "tok-1"
    assert note["params"]["total"] == 1.0


def test_progress_token_extraction() -> None:
    assert mcp_server._progress_token({"_meta": {"progressToken": 7}}) == 7
    assert mcp_server._progress_token({}) is None


@pytest.mark.usefixtures("mcp_run")
def test_slow_tool_does_not_block_other_methods(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slow tools/call runs as a task; ping stays responsive and progress fires."""
    writes: list[dict[str, Any]] = []
    monkeypatch.setattr(mcp_server, "_write_message", writes.append)

    async def _fake_invoke(name: str, args: dict[str, Any]) -> dict[str, Any]:
        del name, args
        await asyncio.sleep(0.2)
        return mcp_server._tool_result("slow-done")

    monkeypatch.setattr(mcp_server, "_invoke_host_tool", _fake_invoke)

    async def _run() -> float:
        task = asyncio.create_task(
            mcp_server._dispatch_tool_call(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "slow", "arguments": {}, "_meta": {"progressToken": "p1"}},
                }
            )
        )
        await asyncio.sleep(0.01)
        t0 = time.monotonic()
        mcp_server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        ping_dt = time.monotonic() - t0
        await task
        return ping_dt

    ping_dt = asyncio.run(_run())
    assert ping_dt < 0.1, "ping was blocked by the slow tool call"
    progress = [w for w in writes if w.get("method") == "notifications/progress"]
    assert len(progress) == 2


@pytest.mark.usefixtures("mcp_run")
def test_audit_log_records_tool_call(tmp_path: Path) -> None:
    _call("tools/call", {"name": "list_skills"})
    audit = tmp_path / "strix_runs" / "mcp-test" / ".state" / "mcp_audit.jsonl"
    assert audit.is_file()
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any(r["tool"] == "list_skills" for r in rows)
    row = rows[-1]
    assert set(row) >= {"ts", "tool", "arg_keys", "elapsed_ms", "is_error", "result_chars"}


@pytest.mark.usefixtures("mcp_run")
def test_audit_log_never_logs_credential_values(tmp_path: Path) -> None:
    _call(
        "tools/call",
        {"name": "store_credential", "arguments": {"label": "owner", "value": "s3cr3t-token"}},
    )
    audit = tmp_path / "strix_runs" / "mcp-test" / ".state" / "mcp_audit.jsonl"
    text = audit.read_text()
    assert "s3cr3t-token" not in text  # values must never reach the audit log
    rows = [json.loads(line) for line in text.splitlines()]
    cred_row = next(r for r in rows if r["tool"] == "store_credential")
    assert cred_row["arg_keys"] == ["label", "value"]  # keys only


@pytest.mark.usefixtures("mcp_run")
def test_audit_resource_readable() -> None:
    _call("tools/call", {"name": "list_skills"})
    result = _call("resources/read", {"uri": "strix://audit"})["result"]
    assert result["contents"][0]["mimeType"] == "application/jsonl"
    assert "list_skills" in result["contents"][0]["text"]
