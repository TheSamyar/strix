"""Audit-coverage tools for the MCP run.

``coverage_report`` cross-references the ``[coverage]`` checklist against the
filed reports so "done" is honest, not vibes. ``scope_coverage`` prunes the
checklist to a target type so the client isn't told to test SQLi on a static
site or DOM-XSS on a pure JSON API.

Both read the shared todo/report state — nothing new is persisted.
"""

from __future__ import annotations

import json
import logging
import re

from agents import RunContextWrapper, function_tool

from strix.report.state import get_global_report_state
from strix.skills import get_available_skills
from strix.tools.todo.tools import coverage_todos, delete_todos


logger = logging.getLogger(__name__)

# Kept in sync with mcp_server.COVERAGE_MARKER / MCP_AGENT_ID by value; not
# imported to avoid a mcp_server <- coverage import cycle.
COVERAGE_MARKER = "[coverage]"
MCP_AGENT_ID = "mcp"

# Coverage todo titles are seeded as
# "[coverage] Test for <pack_name> (see load_skill '<pack_name>')".
_PACK_RE = re.compile(r"Test for (\S+)")


def _pack_name(title: str) -> str | None:
    match = _PACK_RE.search(title)
    return match.group(1) if match else None


def _all_pack_names() -> set[str]:
    return {
        p["name"] for p in get_available_skills().get("vulnerabilities", []) if p.get("name")
    }


# Per-target-type relevance. Hardcoded sets of vuln-pack names (dynamically
# intersected with the packs that actually exist). Unknown / "all" keeps
# everything. Grouped so the intent is legible:
#   APP_CORE       — auth / access-control / logic; any app backend.
#   SERVER_INJECT  — server-side injection & exec; any backend.
#   CLIENT_WEB     — browser/client-side; needs rendered HTML + cookies.
_APP_CORE = {
    "authentication_jwt",
    "broken_function_level_authorization",
    "idor",
    "business_logic",
    "mass_assignment",
    "information_disclosure",
    "weak_password_detection",
    "race_conditions",
}
_SERVER_INJECT = {
    "sql_injection",
    "nosql_injection",
    "rce",
    "ssti",
    "ssrf",
    "path_traversal_lfi_rfi",
    "insecure_deserialization",
    "xxe",
    "insecure_file_uploads",
    "header_injection",
    "http_request_smuggling",
}
_CLIENT_WEB = {"xss", "csrf", "open_redirect", "prototype_pollution"}

# subdomain_takeover is a live-DNS/network concern, so it's the only pack a
# rendered web app / source audit drops.
_WEB_APP = _APP_CORE | _SERVER_INJECT | _CLIENT_WEB | {"llm_prompt_injection"}
_API = _APP_CORE | _SERVER_INJECT | {"llm_prompt_injection"}
_RELEVANCE: dict[str, set[str]] = {
    "web_app": _WEB_APP,
    "api": _API,
    "mobile_api": _API,
    "source": _WEB_APP,
    "repo": _WEB_APP,
    "network": {
        "subdomain_takeover",
        "ssrf",
        "information_disclosure",
        "header_injection",
        "http_request_smuggling",
        "rce",
        "weak_password_detection",
    },
}
_TARGET_TYPES = sorted({*_RELEVANCE, "all"})


def _do_coverage_report() -> dict[str, object]:
    todos = coverage_todos(MCP_AGENT_ID, COVERAGE_MARKER)
    tested: list[str] = []
    untested: list[str] = []
    for todo in todos:
        name = _pack_name(str(todo.get("title", ""))) or str(todo.get("title", ""))
        (tested if todo.get("status") == "done" else untested).append(name)
    tested.sort()
    untested.sort()

    findings_count = 0
    by_severity: dict[str, int] = {}
    by_class: dict[str, int] = {}
    report_state = get_global_report_state()
    if report_state is not None:
        reports = report_state.get_existing_vulnerabilities()
        findings_count = len(reports)
        for r in reports:
            sev = str(r.get("severity", "") or "none").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cls = str(r.get("finding_class", "") or "dynamic").lower()
            by_class[cls] = by_class.get(cls, 0) + 1

    return {
        "success": True,
        "total_classes": len(todos),
        "untested": untested,
        "untested_count": len(untested),
        "tested": tested,
        "tested_count": len(tested),
        "findings_count": findings_count,
        "findings_by_severity": by_severity,
        "findings_by_class": by_class,
    }


@function_tool(timeout=30)
async def coverage_report(ctx: RunContextWrapper) -> str:
    """Honest audit-coverage summary: which vuln classes are still untested.

    Cross-references the ``[coverage]`` checklist against the reports filed so
    far. The **untested** list is the headline — the audit is not done while it
    is non-empty (mark a class done with ``mark_todo_done`` once tested, or
    drop irrelevant classes with ``scope_coverage``).

    Returns JSON: ``total_classes``, ``untested`` (names) + ``untested_count``,
    ``tested`` (names) + ``tested_count``, ``findings_count``, and findings
    grouped by ``findings_by_severity`` / ``findings_by_class``.
    """
    del ctx  # coverage is a single fixed MCP checklist under agent_id="mcp"
    return json.dumps(_do_coverage_report(), ensure_ascii=False, default=str)


def _do_scope_coverage(target_type: str) -> dict[str, object]:
    normalized = (target_type or "").strip().lower()
    todos = coverage_todos(MCP_AGENT_ID, COVERAGE_MARKER)

    if normalized in ("", "all") or normalized not in _RELEVANCE:
        kept = sorted(_pack_name(str(t.get("title", ""))) or "" for t in todos)
        return {
            "success": True,
            "target_type": normalized or "all",
            "kept": [k for k in kept if k],
            "kept_count": len(kept),
            "removed": [],
            "removed_count": 0,
            "note": "unknown/all target type — kept all classes"
            if normalized not in _RELEVANCE and normalized not in ("", "all")
            else "kept all classes",
            "valid_target_types": _TARGET_TYPES,
        }

    relevant = _RELEVANCE[normalized] & _all_pack_names()
    remove_ids: list[str] = []
    removed: list[str] = []
    kept: list[str] = []
    for todo in todos:
        name = _pack_name(str(todo.get("title", "")))
        # Keep relevant classes, unparseable titles, and already-tested work.
        if name is None or name in relevant or todo.get("status") == "done":
            if name:
                kept.append(name)
            continue
        remove_ids.append(str(todo.get("todo_id")))
        removed.append(name)

    delete_todos(MCP_AGENT_ID, remove_ids)
    kept.sort()
    removed.sort()
    logger.info(
        "scope_coverage(%s): kept %d, removed %d coverage todo(s)",
        normalized,
        len(kept),
        len(removed),
    )
    return {
        "success": True,
        "target_type": normalized,
        "kept": kept,
        "kept_count": len(kept),
        "removed": removed,
        "removed_count": len(removed),
        "valid_target_types": _TARGET_TYPES,
    }


@function_tool(timeout=30)
async def scope_coverage(ctx: RunContextWrapper, target_type: str) -> str:
    """Scope the ``[coverage]`` checklist to a target type, pruning irrelevant
    vuln classes so you aren't told to test e.g. DOM-XSS on a pure JSON API.

    Deletes the pending coverage todos that don't apply (already-tested ones
    are kept). Returns JSON with ``kept`` / ``removed`` class names.

    Args:
        target_type: one of ``web_app``, ``api``, ``mobile_api``,
            ``source`` (alias ``repo``), ``network``, or ``all``. Unknown
            values and ``all`` keep every class.
    """
    del ctx  # coverage is a single fixed MCP checklist under agent_id="mcp"
    return json.dumps(_do_scope_coverage(target_type), ensure_ascii=False, default=str)
