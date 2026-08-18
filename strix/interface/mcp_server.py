"""`strix mcp` — stdio MCP server. No Docker, no LLM key.

Cursor / Claude / Codex are the brain. This process only exposes Strix
knowledge packs and finding persistence so those agents can pentest
with their own shell/browser and file validated reports.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import threading
from typing import TYPE_CHECKING, Any

from agents.tool_context import ToolContext

from strix.core.paths import runtime_state_dir
from strix.interface.cli_args import get_version
from strix.report.state import ReportState, get_global_report_state, set_global_report_state
from strix.skills import get_available_skills
from strix.tools.attack_surface.tools import (
    auth_matrix,
    hydrate_attack_surface_from_disk,
    list_attack_surface,
    mark_matrix_cell,
    record_endpoint,
    record_role,
)
from strix.tools.chains.tools import (
    add_chain_step,
    chain_finding,
    delete_chain,
    hydrate_chains_from_disk,
    list_chains,
)
from strix.tools.coverage.tools import coverage_report, scope_coverage
from strix.tools.credentials.tools import (
    delete_credential,
    get_credential,
    hydrate_credentials_from_disk,
    list_credentials,
    store_credential,
)
from strix.tools.cve_lookup.tools import cve_lookup
from strix.tools.diff_response.tools import diff_response
from strix.tools.git_recon.tools import git_recon
from strix.tools.gitleaks_scan.tools import gitleaks_scan
from strix.tools.http_replay.tools import http_replay
from strix.tools.load_skill.tool import load_skill
from strix.tools.notes.tools import (
    create_note,
    delete_note,
    get_note,
    hydrate_notes_from_disk,
    list_notes,
    update_note,
)
from strix.tools.npm_audit.tools import npm_audit
from strix.tools.nuclei_scan.tools import nuclei_scan
from strix.tools.openapi_import.tools import import_openapi
from strix.tools.osv_scan.tools import osv_scan
from strix.tools.reporting.tool import (
    create_dependency_report,
    create_vulnerability_report,
    executive_summary,
    get_report,
    list_reports,
)
from strix.tools.run_scanner.tools import run_scanner
from strix.tools.scanner_deps.tools import (
    auto_update_if_stale,
    check_tools,
    install_tools,
    missing_tools,
    render_install_report,
)
from strix.tools.todo.tools import (
    create_todo,
    delete_todo,
    hydrate_todos_from_disk,
    list_todos,
    mark_todo_done,
    mark_todo_pending,
    seed_todos,
    update_todo,
)


if TYPE_CHECKING:
    from collections.abc import Mapping

    from agents.tool import FunctionTool


logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
DEFAULT_RUN_NAME = "mcp"
COVERAGE_MARKER = "[coverage]"
MCP_AGENT_ID = "mcp"

# Directive methodology handed to the client LLM on `initialize`. Thin guidance
# produces shallow, ad-hoc audits; this forces recon-first, per-surface-per-class
# coverage before the audit is called done.
MCP_INSTRUCTIONS = """\
You are the pentester. Drive this yourself with your own shell, browser, grep, \
and HTTP tooling. Only test targets you are authorized to test. Work the phases \
below in order and do not stop early.

1. RECON FIRST — map the full attack surface before testing anything. Enumerate \
every host, endpoint, parameter, form, header, cookie, auth flow, role, and \
object reference. load_skill the scan_modes pack for your depth (standard or \
deep) and the reconnaissance packs (e.g. asset_discovery) to guide this.

2. SYSTEMATIC PER-SURFACE x PER-CLASS TESTING — for each endpoint/parameter, \
test every relevant vulnerability class. Run list_skills to see the packs, and \
load_skill the specific pack (max 5 at a time) right before testing that class. \
Work through your coverage checklist in list_todos: mark each class done with \
mark_todo_done, or explicitly note why it does not apply. Do not stop after the \
first few bugs.

3. CHAIN AND GO DEEP — test access control (IDOR, horizontal/vertical privilege \
escalation), authentication/session flaws, business-logic abuse, and multi-step \
chains, not just single-request bugs. Treat each finding as a pivot: ask what it \
unlocks next and follow it to maximum impact.

4. PROVE BEFORE FILING — only call create_vulnerability_report with a working, \
reproduced PoC and concrete request/response or code-trace evidence. Use \
create_dependency_report for known-CVE dependencies. Track scope, hypotheses, \
and progress with the notes and todo tools.

5. DON'T DECLARE DONE — the audit is complete only when the coverage checklist \
in list_todos is fully worked through (or empty) and every filed finding is \
verified. State your coverage and any gaps honestly."""

# Host-safe tools only. Shell/browser stay with the coding agent; Caido/Kali
# tools stay in the Docker scan path.
_HOST_TOOLS: tuple[FunctionTool, ...] = (
    load_skill,
    create_vulnerability_report,
    create_dependency_report,
    list_reports,
    get_report,
    executive_summary,
    create_note,
    list_notes,
    get_note,
    update_note,
    delete_note,
    create_todo,
    list_todos,
    update_todo,
    mark_todo_done,
    mark_todo_pending,
    delete_todo,
    coverage_report,
    scope_coverage,
    record_endpoint,
    list_attack_surface,
    record_role,
    auth_matrix,
    mark_matrix_cell,
    import_openapi,
    http_replay,
    diff_response,
    store_credential,
    list_credentials,
    get_credential,
    delete_credential,
    chain_finding,
    list_chains,
    add_chain_step,
    delete_chain,
    osv_scan,
    npm_audit,
    gitleaks_scan,
    git_recon,
    nuclei_scan,
    run_scanner,
    cve_lookup,
    check_tools,
)

_LIST_SKILLS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}


def _tool_by_name() -> dict[str, FunctionTool]:
    return {tool.name: tool for tool in _HOST_TOOLS}


def mcp_tool_descriptors() -> list[dict[str, Any]]:
    tools = [
        {
            "name": "list_skills",
            "description": (
                "List Strix pentest knowledge packs (xss, sql_injection, idor, …) "
                "grouped by category. Call load_skill next to read a pack."
            ),
            "inputSchema": _LIST_SKILLS_SCHEMA,
        }
    ]
    tools.extend(
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.params_json_schema,
        }
        for tool in _HOST_TOOLS
    )
    return tools


def bootstrap_mcp_run(run_name: str = DEFAULT_RUN_NAME) -> ReportState:
    """Create (or reuse) the on-disk run so findings persist without a scan loop."""
    existing = get_global_report_state()
    if existing is not None:
        return existing
    state = ReportState(run_name=run_name)
    set_global_report_state(state)
    run_dir = state.get_run_dir()
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    hydrate_notes_from_disk(state_dir)
    hydrate_todos_from_disk(state_dir)
    hydrate_attack_surface_from_disk(state_dir)
    hydrate_credentials_from_disk(state_dir)
    hydrate_chains_from_disk(state_dir)
    _seed_coverage_todos()
    state.save_run_data()
    return state


def _seed_coverage_todos() -> None:
    """Seed one todo per vulnerability knowledge pack so the client can't
    silently skip vuln classes. Idempotent via title-dedup in seed_todos."""
    packs = get_available_skills().get("vulnerabilities", [])
    todos = [
        {
            "title": f"{COVERAGE_MARKER} Test for {pack['name']} (see load_skill '{pack['name']}')",
            "description": pack.get("description") or None,
        }
        for pack in packs
        if pack.get("name")
    ]
    if not todos:
        return
    created = seed_todos(MCP_AGENT_ID, todos)
    if created:
        logger.info("Seeded %d vuln-coverage todo(s) for MCP run", created)


def _rpc_result(msg: Mapping[str, Any], result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg.get("id"), "result": result}


def _rpc_error(msg: Mapping[str, Any], code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg.get("id"),
        "error": {"code": code, "message": message},
    }


def _initialize_result() -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "strix", "version": get_version()},
        "instructions": MCP_INSTRUCTIONS,
    }


def _tool_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


async def _invoke_host_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "list_skills":
        return _tool_result(json.dumps(get_available_skills(), indent=2))
    tool = _tool_by_name().get(name)
    if tool is None:
        return _tool_result(f"Unknown tool: {name}", is_error=True)
    raw_args = json.dumps(arguments)
    ctx = ToolContext(
        context={"agent_id": "mcp", "interactive": False},
        tool_name=name,
        tool_call_id=f"mcp-{name}",
        tool_arguments=raw_args,
    )
    raw = await tool.on_invoke_tool(ctx, raw_args)
    text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    return _tool_result(text)


def _call_tool_response(msg: Mapping[str, Any]) -> dict[str, Any]:
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    name = params.get("name")
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    if not isinstance(name, str) or not name:
        return _rpc_error(msg, -32602, "tools/call requires params.name")
    try:
        result = asyncio.run(_invoke_host_tool(name, arguments))
    except Exception as exc:
        logger.exception("MCP tool %s failed", name)
        result = _tool_result(f"{type(exc).__name__}: {exc}", is_error=True)
    return _rpc_result(msg, result)


def handle_message(msg: Mapping[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC MCP message. Notifications return None."""
    method = msg.get("method")
    if not isinstance(method, str):
        return _rpc_error(msg, -32600, "Invalid Request")
    if method.startswith("notifications/"):
        return None
    handlers: dict[str, Any] = {
        "initialize": lambda: _rpc_result(msg, _initialize_result()),
        "ping": lambda: _rpc_result(msg, {}),
        "tools/list": lambda: _rpc_result(msg, {"tools": mcp_tool_descriptors()}),
        "tools/call": lambda: _call_tool_response(msg),
    }
    handler = handlers.get(method)
    if handler is None:
        return _rpc_error(msg, -32601, f"Method not found: {method}")
    return handler()


def _write_message(payload: dict[str, Any]) -> None:
    # Official MCP stdio is one JSON-RPC object per line. Content-Length
    # framing breaks Cursor (it parses each line as JSON).
    sys.stdout.buffer.write(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


def _read_lsp_body(first_line: bytes) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    line = first_line
    while line not in {b"\r\n", b"\n", b""}:
        key, _, value = line.decode("utf-8", errors="replace").partition(":")
        if _:
            headers[key.strip().lower()] = value.strip()
        line = sys.stdin.buffer.readline()
        if not line:
            return None
    try:
        length = int(headers.get("content-length", "0"))
    except ValueError:
        length = 0
    raw = sys.stdin.buffer.read(length) if length > 0 else b""
    return json.loads(raw) if raw else None


def _read_message() -> dict[str, Any] | None:
    """Read one JSON-RPC message: newline JSON, or LSP Content-Length."""
    line = sys.stdin.buffer.readline()
    if not line:
        return None
    stripped = line.strip()
    if not stripped:
        return _read_message()
    if stripped[:1] in {b"{", b"["}:
        return json.loads(stripped)
    return _read_lsp_body(line)


def serve_stdio() -> int:
    """Block on stdin until the MCP client closes the pipe."""
    while True:
        try:
            msg = _read_message()
        except json.JSONDecodeError:
            logger.warning("MCP: skipping non-JSON payload")
            continue
        if msg is None:
            return 0
        if not isinstance(msg, dict):
            continue
        response = handle_message(msg)
        if response is not None:
            _write_message(response)


def run_mcp(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="strix mcp",
        description="Expose Strix skills and reporting over MCP stdio. No Docker, no API key.",
    )
    parser.add_argument(
        "--run-name",
        default=DEFAULT_RUN_NAME,
        help=f"Run directory under ./strix_runs (default: {DEFAULT_RUN_NAME}).",
    )
    parser.add_argument(
        "--install-tools",
        action="store_true",
        help="Install any missing external scanner binaries (nuclei, nmap, ffuf, "
        "gitleaks, httpx, sqlmap, nikto, wpscan) via the host package manager, then exit.",
    )
    parser.add_argument(
        "--update-tools",
        action="store_true",
        help="Install missing scanners AND upgrade already-installed ones to the "
        "latest version (also refreshes nuclei templates), then exit.",
    )
    args = parser.parse_args(argv)

    if args.install_tools or args.update_tools:
        # Not stdout: stdout is the JSON-RPC channel. Write to stderr so this
        # never corrupts an MCP session; these flags are the interactive path.
        upgrade = args.update_tools
        verb = "Updating" if upgrade else "Installing"
        sys.stderr.write(f"{verb} external scanner tools (this may prompt for sudo)…\n")
        results = install_tools(upgrade=upgrade)
        sys.stderr.write(render_install_report(results) + "\n")
        failed = [n for n, r in results.items() if r["status"] == "failed"]
        return 1 if failed else 0

    bootstrap_mcp_run(args.run_name)
    absent = missing_tools()
    if absent:
        logger.warning(
            "Scanner tools not installed: %s. Run `strix mcp --install-tools` to add them.",
            ", ".join(absent),
        )
    # Upgrade stale tools in the background so a long-idle client picks up latest
    # without blocking startup (STRIX_TOOL_AUTOUPDATE_DAYS=0 disables it).
    threading.Thread(target=auto_update_if_stale, name="strix-tool-autoupdate", daemon=True).start()
    logger.info("MCP server ready (run=%s)", args.run_name)
    return serve_stdio()
