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
import time
from datetime import UTC, datetime
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
from strix.tools.auth_crawl.tools import auth_crawl
from strix.tools.auth_probe.tools import session_invalidation_probe
from strix.tools.authz_matrix.tools import authz_matrix
from strix.tools.authz_probe.tools import authz_probe
from strix.tools.autopwn.tools import autopwn, verify_finding
from strix.tools.backend_rules_probe.tools import backend_rules_probe
from strix.tools.cache_privacy.tools import cache_privacy_probe
from strix.tools.chain_suggest.tools import suggest_chains
from strix.tools.chains.tools import (
    add_chain_step,
    chain_finding,
    delete_chain,
    hydrate_chains_from_disk,
    list_chains,
)
from strix.tools.cors_probe.tools import cors_probe
from strix.tools.coverage.tools import coverage_report, scope_coverage
from strix.tools.coverage_gaps.tools import coverage_gaps
from strix.tools.credentials.tools import (
    delete_credential,
    get_credential,
    hydrate_credentials_from_disk,
    list_credentials,
    store_credential,
)
from strix.tools.csrf_probe.tools import csrf_probe
from strix.tools.cve_lookup.tools import cve_lookup
from strix.tools.data_exposure.tools import data_exposure_probe
from strix.tools.dedupe.tools import dedupe_reports
from strix.tools.deep_fuzz.tools import deep_fuzz
from strix.tools.default_creds.tools import default_creds
from strix.tools.dep_confusion.tools import check_dependency_confusion
from strix.tools.desync.tools import cache_deception_probe, request_smuggling_probe
from strix.tools.diff_response.tools import diff_response
from strix.tools.discovery.tools import content_discover, param_discover
from strix.tools.dos_probe.tools import dos_probe
from strix.tools.endpoint_risk.tools import endpoint_risk_rank
from strix.tools.error_leak.tools import error_leak_probe
from strix.tools.frontend_secret_scan.tools import frontend_secret_scan
from strix.tools.git_recon.tools import git_recon
from strix.tools.gitleaks_scan.tools import gitleaks_scan
from strix.tools.graphql_abuse.tools import graphql_abuse
from strix.tools.graphql_deep.tools import graphql_dos, graphql_field_leak
from strix.tools.graphql_probe.tools import graphql_introspection
from strix.tools.harvest.tools import discover_assets, walk_unauth
from strix.tools.header_leak.tools import header_leak
from strix.tools.http_replay.tools import http_replay
from strix.tools.injection_fuzz.tools import injection_fuzz
from strix.tools.jwt_audit.tools import jwt_audit
from strix.tools.jwt_confusion.tools import jwt_confusion
from strix.tools.lfi_probe.tools import lfi_probe
from strix.tools.load_skill.tool import load_skill
from strix.tools.local_scan.tools import local_security_scan
from strix.tools.mass_assignment.tools import mass_assignment_probe
from strix.tools.mcp_audit.tools import mcp_tool_poisoning_audit
from strix.tools.mfa_bypass.tools import mfa_bypass
from strix.tools.nosql_probe.tools import nosql_probe
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
from strix.tools.oast.tools import oast_get_domain, oast_poll
from strix.tools.oauth_probe.tools import oauth_probe
from strix.tools.openapi_import.tools import import_openapi
from strix.tools.osv_scan.tools import osv_scan
from strix.tools.plan_tests.tools import plan_tests
from strix.tools.profile_target.tools import profile_target
from strix.tools.prompt_injection.tools import prompt_injection_probe
from strix.tools.proxy.tools import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
from strix.tools.race_probe.tools import race_probe
from strix.tools.rate_limit_probe.tools import rate_limit_probe
from strix.tools.recon.tools import recon_chain
from strix.tools.redirect_probe.tools import redirect_probe
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
from strix.tools.security_headers.tools import security_headers_probe
from strix.tools.session_fixation.tools import reset_token_probe, session_fixation_probe
from strix.tools.shell_session.tools import (
    close_shell,
    list_shells,
    loot,
    pivot_scan,
    privesc_scan,
    read_shell,
    shell_exec,
    start_listener,
    upgrade_pty,
)
from strix.tools.signed_url.tools import signed_url_probe
from strix.tools.sourcemap.tools import sourcemap_recover
from strix.tools.ssr_leak.tools import ssr_leak_scan
from strix.tools.ssrf_probe.tools import ssrf_probe
from strix.tools.storage_probe.tools import storage_probe
from strix.tools.stored_probe.tools import stored_probe
from strix.tools.subdomain_takeover.tools import subdomain_takeover
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
from strix.tools.upload_probe.tools import upload_probe
from strix.tools.user_enum.tools import user_enumeration_probe
from strix.tools.validation.tools import (
    hydrate_validations_from_disk,
    retest_findings,
    validate_finding,
)
from strix.tools.web_search.tool import web_search
from strix.tools.ws_leak.tools import ws_leak
from strix.tools.ws_probe.tools import ws_probe
from strix.tools.xxe_probe.tools import xxe_probe


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

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

1. PROFILE, THEN HARVEST — first call profile_target on the seed URL and pass \
its result to plan_tests: that fingerprints the stack (framework, Supabase/\
Firebase, GraphQL, JWT, WordPress, …) and seeds a tailored [plan] checklist so \
you test what THIS target actually needs, not a blanket list. Then check_tools, \
discover_assets, walk_unauth, and coverage_report; if coverage_report.walk.\
incomplete, keep walking until every recorded endpoint and live host has a walk \
row. Run endpoint_risk_rank on the discovered endpoints and test the highest-\
scoring ones first. This is code-path inventory, not optional recon.

2. DATA-LEAK PASS EARLY — before lower-impact bug classes, hunt unauthorized \
data exposure. Map tenants, users, workspaces, projects, conversations, files, \
exports, logs, RAG/vector stores, prompts, job IDs, signed URLs, cache keys, \
and integration payloads. Use at least two identities/tenants when available; \
store each as a credential and run authz_probe to replay list/view/search/\
export/download/status endpoints across boundaries and diff status, lengths, \
and body digests in one call. Also: ssr_leak_scan (data embedded in the SSR \
page), data_exposure_probe (API returns more fields than the UI), storage_probe \
(exposed .git/.env/backups), and cache_privacy_probe (private data cached / \
tokens in URLs). load_skill data_leakage.

3. SYSTEMATIC PER-SURFACE x PER-CLASS TESTING — for each endpoint/parameter, \
test every relevant vulnerability class. Run list_skills to see the packs, and \
load_skill the specific pack (max 5 at a time) right before testing that class. \
Work through your coverage checklist in list_todos: mark each class done with \
mark_todo_done, or explicitly note why it does not apply. Do not stop after the \
first few bugs.

4. CHAIN AND GO DEEP — test access control (IDOR, horizontal/vertical privilege \
escalation), authentication/session flaws, business-logic abuse, and multi-step \
chains, not just single-request bugs. Treat each finding as a pivot: ask what it \
unlocks next and follow it to maximum impact. For BLIND bugs (blind SSRF, blind \
XSS, DNS exfil, RCE) call oast_get_domain, plant the domain in the payload, then \
oast_poll — a callback is the proof. Confirmed RCE: start_listener, catch the \
shell, then loot / privesc_scan / pivot_scan so the report has identity, creds, \
and internal-reach proof rather than just "RCE confirmed". If the target is an \
AI/LLM app or exposes its own MCP tools, run mcp_tool_poisoning_audit on those \
tool descriptions and test direct/indirect prompt injection \
(load_skill llm_prompt_injection).

5. PROVE BEFORE FILING — before create_vulnerability_report, call \
validate_finding to re-run the PoC and prove the claimed impact (for a data \
leak it must return the actual leaked data as proof); pass the resulting \
validation_id into create_vulnerability_report along with concrete \
request/response or code-trace evidence. Include the actual leaked values; \
do not redact. Use create_dependency_report for \
known-CVE dependencies. Track scope, hypotheses, and progress with the notes \
and todo tools.

6. DON'T DECLARE DONE — call coverage_report and coverage_gaps. If \
coverage_gaps.thoroughness is not "looks_thorough" (pending classes, or key \
probes never run), keep going. When finished, call dedupe_reports to merge \
duplicate findings, suggest_chains to escalate them, and after a fix cycle \
retest_findings to prove which findings are now closed."""

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
    autopwn,
    verify_finding,
    profile_target,
    plan_tests,
    endpoint_risk_rank,
    auth_crawl,
    suggest_chains,
    cache_deception_probe,
    request_smuggling_probe,
    create_vulnerability_report,
    create_dependency_report,
    list_reports,
    get_report,
    executive_summary,
    dedupe_reports,
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
    authz_probe,
    authz_matrix,
    stored_probe,
    injection_fuzz,
    ssrf_probe,
    xxe_probe,
    lfi_probe,
    nosql_probe,
    start_listener,
    list_shells,
    shell_exec,
    read_shell,
    upgrade_pty,
    loot,
    privesc_scan,
    pivot_scan,
    close_shell,
    deep_fuzz,
    param_discover,
    content_discover,
    prompt_injection_probe,
    cors_probe,
    rate_limit_probe,
    graphql_introspection,
    graphql_abuse,
    graphql_field_leak,
    graphql_dos,
    subdomain_takeover,
    coverage_gaps,
    jwt_audit,
    jwt_confusion,
    session_fixation_probe,
    reset_token_probe,
    race_probe,
    session_invalidation_probe,
    user_enumeration_probe,
    oauth_probe,
    dos_probe,
    csrf_probe,
    default_creds,
    upload_probe,
    mfa_bypass,
    mass_assignment_probe,
    redirect_probe,
    security_headers_probe,
    backend_rules_probe,
    frontend_secret_scan,
    ssr_leak_scan,
    data_exposure_probe,
    storage_probe,
    cache_privacy_probe,
    error_leak_probe,
    sourcemap_recover,
    signed_url_probe,
    header_leak,
    ws_leak,
    oast_get_domain,
    oast_poll,
    mcp_tool_poisoning_audit,
    validate_finding,
    retest_findings,
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
    local_security_scan,
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
        _seed_plan_todo()
        _seed_data_leak_todos()
        _seed_coverage_todos()
    state.save_run_data()
    return state


def _seed_plan_todo() -> None:
    """Seed a first-step todo so the audit profiles the target and tailors itself
    before falling back to the blanket coverage checklist."""
    created = seed_todos(
        MCP_AGENT_ID,
        [
            {
                "title": (
                    "[plan] Profile the target first: call profile_target on the seed URL, "
                    "then plan_tests to seed a stack-tailored checklist"
                ),
                "description": (
                    "Run profile_target -> plan_tests before broad testing so tool/skill "
                    "selection fits this target. Then endpoint_risk_rank to test worst-first."
                ),
            }
        ],
    )
    if created:
        logger.info("Seeded target-profiling plan todo for MCP run")


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


AUDIT_LOG_NAME = "mcp_audit.jsonl"
_audit_lock = threading.Lock()


def _result_chars(result: dict[str, Any]) -> int:
    content = result.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        return len(str(content[0].get("text", "")))
    return 0


def _audit_log(
    tool: str, arg_keys: list[str], elapsed_ms: float, *, is_error: bool, result_chars: int
) -> None:
    """Append one secret-safe record per tool call. Logs argument KEYS only —
    never values — so credential secrets never reach disk."""
    state = get_global_report_state()
    if state is None:
        return
    record = {
        "ts": datetime.now(tz=UTC).isoformat(),
        "tool": tool,
        "arg_keys": arg_keys,
        "elapsed_ms": round(elapsed_ms, 1),
        "is_error": is_error,
        "result_chars": result_chars,
    }
    try:
        path = runtime_state_dir(state.get_run_dir()) / AUDIT_LOG_NAME
        with _audit_lock, path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        logger.debug("MCP audit write failed", exc_info=True)


async def _run_host_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
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


async def _invoke_host_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    result = await _run_host_tool(name, arguments)
    _audit_log(
        name,
        sorted(arguments),
        (time.monotonic() - started) * 1000,
        is_error=bool(result.get("isError")),
        result_chars=_result_chars(result),
    )
    return result


def _dict_field(container: Mapping[str, Any], key: str) -> dict[str, Any]:
    """Return container[key] if it's a dict, else {} — keeps mypy narrowing happy."""
    value = container.get(key)
    return value if isinstance(value, dict) else {}


def _call_tool_response(msg: Mapping[str, Any]) -> dict[str, Any]:
    params = _dict_field(msg, "params")
    name = params.get("name")
    arguments = _dict_field(params, "arguments")
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
AUDIT_URI = "strix://audit"
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
        {
            "uri": AUDIT_URI,
            "name": "Strix MCP audit trail",
            "description": "Every MCP tool call this run: tool, arg keys, timing, error (JSONL).",
            "mimeType": "application/jsonl",
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
    if uri == AUDIT_URI:
        return {"uri": uri, "mimeType": "application/jsonl", "text": _read_audit_log()}
    if uri.startswith(_SKILL_URI_PREFIX):
        name = uri[len(_SKILL_URI_PREFIX) :]
        body = load_skills([name]).get(name)
        if body is None:
            return None
        return {"uri": uri, "mimeType": "text/markdown", "text": f"# Skill: {name}\n\n{body}"}
    return None


def _read_audit_log(max_lines: int = 500) -> str:
    """Return the last ``max_lines`` audit records (JSONL), newest run dir."""
    state = get_global_report_state()
    if state is None:
        return ""
    path = runtime_state_dir(state.get_run_dir()) / AUDIT_LOG_NAME
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-max_lines:])


def _read_resource_response(msg: Mapping[str, Any]) -> dict[str, Any]:
    params = _dict_field(msg, "params")
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
    params = _dict_field(msg, "params")
    name = params.get("name")
    if name != PENTEST_PROMPT:
        return _rpc_error(msg, -32602, f"Unknown prompt: {name}")
    args = _dict_field(params, "arguments")
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
    handlers: dict[str, Callable[[], dict[str, Any]]] = {
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
    if not raw:
        return None
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else None


def _read_message() -> dict[str, Any] | None:
    """Read one JSON-RPC message: newline JSON, or LSP Content-Length."""
    line = sys.stdin.buffer.readline()
    if not line:
        return None
    stripped = line.strip()
    if not stripped:
        return _read_message()
    if stripped[:1] in {b"{", b"["}:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    return _read_lsp_body(line)


def _progress_token(params: Mapping[str, Any]) -> str | int | None:
    """Pull the client's progressToken from params._meta, if any (MCP spec)."""
    meta = _dict_field(params, "_meta")
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
    params = _dict_field(msg, "params")
    token = _progress_token(params)
    name = params.get("name")
    arguments = _dict_field(params, "arguments")
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
