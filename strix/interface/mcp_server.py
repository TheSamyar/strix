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
from strix.skills import get_available_skills, load_skills
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
from strix.tools.dep_confusion.tools import check_dependency_confusion
from strix.tools.diff_response.tools import diff_response
from strix.tools.git_recon.tools import git_recon
from strix.tools.gitleaks_scan.tools import gitleaks_scan
from strix.tools.harvest.tools import discover_assets, walk_unauth
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
from strix.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
from strix.tools.recon.tools import recon_chain
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
from strix.tools.validation.tools import hydrate_validations_from_disk, validate_finding
from strix.tools.web_search.tool import web_search
from strix.tools.ws_probe.tools import ws_probe


if TYPE_CHECKING:
    from collections.abc import Mapping

    from agents.tool import FunctionTool


logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
DEFAULT_RUN_NAME = "mcp"
COVERAGE_MARKER = "[coverage]"
DATA_LEAK_MARKER = "[data-leak]"
MCP_AGENT_ID = "mcp"

_runtime_options: dict[str, bool] = {"seed_coverage": True}

# Directive methodology handed to the client LLM on `initialize`. Thin guidance
# produces shallow, ad-hoc audits; this forces recon-first, per-surface-per-class
# coverage before the audit is called done.
MCP_INSTRUCTIONS = """\
You are the pentester. Drive this yourself with your own shell, browser, grep, \
and HTTP tooling. Only test targets you are authorized to test. Work the phases \
below in order and do not stop early.

1. HARVEST FIRST — call check_tools, then discover_assets on the seed URL, then \
walk_unauth, then coverage_report. If coverage_report.walk.incomplete, keep \
walking until every recorded endpoint and live host has a walk row. This is \
code-path inventory, not optional recon.

2. DATA-LEAK PASS EARLY — before lower-impact bug classes, hunt unauthorized \
data exposure. Map tenants, users, workspaces, projects, conversations, files, \
exports, logs, RAG/vector stores, prompts, job IDs, signed URLs, cache keys, \
and integration payloads. Use at least two identities/tenants when available; \
replay list/view/search/export/download/status endpoints across boundaries and \
diff status, fields, lengths, digests, and cache headers. load_skill \
data_leakage.

3. SYSTEMATIC PER-SURFACE x PER-CLASS TESTING — for each endpoint/parameter, \
test every relevant vulnerability class. Run list_skills to see the packs, and \
load_skill the specific pack (max 5 at a time) right before testing that class. \
Work through your coverage checklist in list_todos: mark each class done with \
mark_todo_done, or explicitly note why it does not apply. Do not stop after the \
first few bugs.

4. CHAIN AND GO DEEP — test access control (IDOR, horizontal/vertical privilege \
escalation), authentication/session flaws, business-logic abuse, and multi-step \
chains, not just single-request bugs. Treat each finding as a pivot: ask what it \
unlocks next and follow it to maximum impact.

5. PROVE BEFORE FILING — before create_vulnerability_report, call \
validate_finding to re-run the PoC and prove the claimed impact (for a data \
leak it must return the actual leaked data as proof); pass the resulting \
validation_id into create_vulnerability_report along with concrete \
request/response or code-trace evidence. Include the actual leaked values; \
do not redact. Use create_dependency_report for \
known-CVE dependencies. Track scope, hypotheses, and progress with the notes \
and todo tools.

6. DON'T DECLARE DONE — call coverage_report again. If walk.incomplete or the \
coverage checklist still has untested classes, keep going."""

SPECIALIST_MCP_INSTRUCTIONS = """\
You are a specialist on a Strix audit. Drive testing with your own shell, \
browser, grep, and HTTP tooling. Only test authorized targets. load_skill \
the packs named in your job prompt, prove exploits before filing, and call \
create_vulnerability_report only for validated findings. Include actual \
leaked values in evidence; do not redact findings. Operator-supplied scan \
auth stays secret. Coverage todos are not seeded — do not try to cover \
every vulnerability class. Do not spawn sub-agents. When the job is done, \
stop."""

# Host-safe tools only. Shell/browser stay with the coding agent. The Caido
# proxy tools self-connect to a caido-cli the host runs (STRIX_CAIDO_URL) and
# return a clear error when none is reachable.
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
    discover_assets,
    walk_unauth,
    record_endpoint,
    list_attack_surface,
    record_role,
    auth_matrix,
    mark_matrix_cell,
    import_openapi,
    http_replay,
    validate_finding,
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
    check_dependency_confusion,
    gitleaks_scan,
    git_recon,
    ws_probe,
    nuclei_scan,
    run_scanner,
    recon_chain,
    cve_lookup,
    check_tools,
    web_search,
    list_requests,
    view_request,
    repeat_request,
    list_sitemap,
    view_sitemap_entry,
    scope_rules,
)

_LIST_SKILLS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}


def _tool_by_name() -> dict[str, FunctionTool]:
    return {tool.name: tool for tool in _HOST_TOOLS}


_DESC_MAX = 280


def _clip_desc(text: str) -> str:
    text = (text or "").strip()
    if len(text) <= _DESC_MAX:
        return text
    return text[: _DESC_MAX - 1].rstrip() + "…"


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
            "description": _clip_desc(tool.description),
            "inputSchema": tool.params_json_schema,
        }
        for tool in _HOST_TOOLS
    )
    return tools


def bootstrap_mcp_run(
    run_name: str = DEFAULT_RUN_NAME,
    *,
    seed_coverage: bool = True,
) -> ReportState:
    """Create (or reuse) the on-disk run so findings persist without a scan loop."""
    _runtime_options["seed_coverage"] = seed_coverage
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
    hydrate_validations_from_disk(state_dir)
    if seed_coverage:
        _seed_data_leak_todos()
        _seed_coverage_todos()
    state.save_run_data()
    return state


def _seed_data_leak_todos() -> None:
    """Seed priority data-leak coverage so privacy-impact checks happen early."""
    todos = [
        {
            "title": (
                f"{DATA_LEAK_MARKER} Load data_leakage and map users, tenants, "
                "workspaces, objects, files, exports, prompts, logs, and caches"
            ),
            "description": (
                "Build a data-flow and identity-boundary map before broad "
                "vuln-class testing."
            ),
        },
        {
            "title": (
                f"{DATA_LEAK_MARKER} Replay read/list/search/export/download/job "
                "endpoints across wrong users or tenants"
            ),
            "description": (
                "Compare status, body digest, leaked fields, object IDs, "
                "and cache headers."
            ),
        },
        {
            "title": (
                f"{DATA_LEAK_MARKER} Inspect client bundles, source maps, hydration "
                "state, signed URLs, RAG/vector metadata, and integration logs"
            ),
            "description": (
                "File only validated restricted-data exposure; include the "
                "actual leaked values in evidence (no redaction)."
            ),
        },
    ]
    created = seed_todos(MCP_AGENT_ID, todos)
    if created:
        logger.info("Seeded %d data-leak todo(s) for MCP run", created)


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
        "capabilities": {
            "tools": {},
            "resources": {},
            "prompts": {},
        },
        "serverInfo": {"name": "strix", "version": get_version()},
        "instructions": (
            MCP_INSTRUCTIONS
            if _runtime_options["seed_coverage"]
            else SPECIALIST_MCP_INSTRUCTIONS
        ),
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


SKILLS_URI = "strix://skills"
REPORTS_URI = "strix://reports"
_SKILL_URI_PREFIX = "strix://skill/"


def mcp_resource_descriptors() -> list[dict[str, Any]]:
    """Skill catalog, current findings, and one resource per skill pack.

    Resources let clients that prefer attach-context over tool calls pull a
    pack or the live findings without a round-trip through load_skill."""
    resources: list[dict[str, Any]] = [
        {
            "uri": SKILLS_URI,
            "name": "Strix skill catalog",
            "description": "All pentest knowledge packs grouped by category (JSON).",
            "mimeType": "application/json",
        },
        {
            "uri": REPORTS_URI,
            "name": "Strix findings",
            "description": "Validated vulnerability reports filed this run (JSON).",
            "mimeType": "application/json",
        },
    ]
    for category, packs in get_available_skills().items():
        for pack in packs:
            name = pack.get("name")
            if not name:
                continue
            resources.append(
                {
                    "uri": f"{_SKILL_URI_PREFIX}{name}",
                    "name": f"skill: {name}",
                    "description": _clip_desc(pack.get("description") or category),
                    "mimeType": "text/markdown",
                }
            )
    return resources


def _resource_contents(uri: str) -> dict[str, Any] | None:
    if uri == SKILLS_URI:
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(get_available_skills(), indent=2),
        }
    if uri == REPORTS_URI:
        state = get_global_report_state()
        reports = state.get_existing_vulnerabilities() if state is not None else []
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(reports, indent=2, default=str),
        }
    if uri.startswith(_SKILL_URI_PREFIX):
        name = uri[len(_SKILL_URI_PREFIX) :]
        body = load_skills([name]).get(name)
        if body is None:
            return None
        return {"uri": uri, "mimeType": "text/markdown", "text": f"# Skill: {name}\n\n{body}"}
    return None


def _read_resource_response(msg: Mapping[str, Any]) -> dict[str, Any]:
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    uri = params.get("uri")
    if not isinstance(uri, str) or not uri:
        return _rpc_error(msg, -32602, "resources/read requires params.uri")
    contents = _resource_contents(uri)
    if contents is None:
        return _rpc_error(msg, -32602, f"Unknown resource: {uri}")
    return _rpc_result(msg, {"contents": [contents]})


PENTEST_PROMPT = "pentest_target"


def mcp_prompt_descriptors() -> list[dict[str, Any]]:
    return [
        {
            "name": PENTEST_PROMPT,
            "description": (
                "Seed the full Strix pentest methodology against a target. Injects "
                "the recon-first, per-surface-per-class playbook so the client can't "
                "run a shallow ad-hoc audit."
            ),
            "arguments": [
                {"name": "target", "description": "URL, host, or repo to test.", "required": True},
                {
                    "name": "focus",
                    "description": "Optional bug class or surface to prioritize.",
                    "required": False,
                },
            ],
        }
    ]


def _get_prompt_response(msg: Mapping[str, Any]) -> dict[str, Any]:
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    name = params.get("name")
    if name != PENTEST_PROMPT:
        return _rpc_error(msg, -32602, f"Unknown prompt: {name}")
    args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    target = args.get("target")
    if not isinstance(target, str) or not target:
        return _rpc_error(msg, -32602, "pentest_target requires arguments.target")
    focus = args.get("focus")
    text = f"{MCP_INSTRUCTIONS}\n\nTARGET: {target}"
    if isinstance(focus, str) and focus:
        text += f"\nPRIORITIZE: {focus}"
    return _rpc_result(
        msg,
        {
            "description": f"Strix pentest playbook for {target}",
            "messages": [
                {"role": "user", "content": {"type": "text", "text": text}},
            ],
        },
    )


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
        "resources/list": lambda: _rpc_result(msg, {"resources": mcp_resource_descriptors()}),
        "resources/read": lambda: _read_resource_response(msg),
        "prompts/list": lambda: _rpc_result(msg, {"prompts": mcp_prompt_descriptors()}),
        "prompts/get": lambda: _get_prompt_response(msg),
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


def _progress_token(params: Mapping[str, Any]) -> str | int | None:
    """Pull the client's progressToken from params._meta, if any (MCP spec)."""
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    token = meta.get("progressToken")
    return token if isinstance(token, (str, int)) else None


def _progress_notification(
    token: str | int, progress: float, total: float | None = None
) -> dict[str, Any]:
    params: dict[str, Any] = {"progressToken": token, "progress": progress}
    if total is not None:
        params["total"] = total
    return {"jsonrpc": "2.0", "method": "notifications/progress", "params": params}


async def _dispatch_tool_call(msg: Mapping[str, Any]) -> None:
    """Run one tools/call as its own task so slow scanners don't block the
    read loop, ping, or other tool calls. Emits start/done progress when the
    client passed a progressToken."""
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    token = _progress_token(params)
    name = params.get("name")
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    if not isinstance(name, str) or not name:
        _write_message(_rpc_error(msg, -32602, "tools/call requires params.name"))
        return
    if token is not None:
        _write_message(_progress_notification(token, 0.0, 1.0))
    try:
        result = await _invoke_host_tool(name, arguments)
    except Exception as exc:
        logger.exception("MCP tool %s failed", name)
        result = _tool_result(f"{type(exc).__name__}: {exc}", is_error=True)
    if token is not None:
        _write_message(_progress_notification(token, 1.0, 1.0))
    _write_message(_rpc_result(msg, result))


async def _serve_stdio_async() -> int:
    """Event loop: a stdin reader thread feeds messages onto a queue; fast
    methods answer inline, tools/call runs concurrently as tasks. All writes
    happen on this single loop thread, so stdout stays uncorrupted.

    # ponytail: tool calls share in-memory state (todos/notes/report); the one
    # client LLM issues calls serially in practice, and concurrency exists so
    # ping/tools-list stay live during a long scan. Add per-store locks only if
    # a client is observed firing overlapping state-mutating calls.
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    def _reader() -> None:
        while True:
            try:
                msg = _read_message()
            except json.JSONDecodeError:
                logger.warning("MCP: skipping non-JSON payload")
                continue
            loop.call_soon_threadsafe(queue.put_nowait, msg)
            if msg is None:
                return

    threading.Thread(target=_reader, name="strix-mcp-stdin", daemon=True).start()

    pending: set[asyncio.Task[None]] = set()
    while True:
        msg = await queue.get()
        if msg is None:
            break
        if not isinstance(msg, dict):
            continue
        if msg.get("method") == "tools/call":
            task = asyncio.create_task(_dispatch_tool_call(msg))
            pending.add(task)
            task.add_done_callback(pending.discard)
            continue
        response = handle_message(msg)
        if response is not None:
            _write_message(response)
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    return 0


def serve_stdio() -> int:
    """Block on stdin until the MCP client closes the pipe."""
    return asyncio.run(_serve_stdio_async())


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
    parser.add_argument(
        "--no-seed",
        action="store_true",
        help=(
            "Skip vuln-class coverage todos; specialist instructions "
            "(used by strix audit workers)."
        ),
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

    bootstrap_mcp_run(args.run_name, seed_coverage=not args.no_seed)
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
