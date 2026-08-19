"""Coverage critic — say what has NOT been tested yet, so 'done' means thorough.

A finding list shows what was found; it can't show what was skipped. This
cross-references the run's pending [plan]/[coverage]/[data-leak] todos, the
key probe tools that never ran (from the audit log), and the findings filed,
then gives a blunt thoroughness verdict — shallow vs looks-thorough.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.paths import runtime_state_dir
from strix.report.state import get_global_report_state
from strix.tools.todo.tools import _get_agent_todos


# Audit filename mirrors mcp_server.AUDIT_LOG_NAME (kept local to avoid importing
# the server module into a tool — that would be circular).
_AUDIT_LOG_NAME = "mcp_audit.jsonl"

# The probes a reasonably complete web audit should have exercised at least once.
_KEY_TOOLS = (
    "profile_target",
    "authz_probe",
    "injection_fuzz",
    "cors_probe",
    "rate_limit_probe",
    "frontend_secret_scan",
    "jwt_audit",
    "auth_crawl",
    "endpoint_risk_rank",
)


def _tools_run() -> set[str] | None:
    """Tool names seen in the audit log, or None if there's no log to read."""
    state = get_global_report_state()
    if state is None:
        return None
    path = runtime_state_dir(state.get_run_dir()) / _AUDIT_LOG_NAME
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    names: set[str] = set()
    for line in lines:
        try:
            names.add(str(json.loads(line).get("tool")))
        except (json.JSONDecodeError, ValueError):
            continue
    return names


def _coverage_gaps_impl(agent_id: str) -> dict[str, Any]:
    todos = _get_agent_todos(agent_id)
    pending: dict[str, list[str]] = {"plan": [], "coverage": [], "data_leak": [], "other": []}
    for todo in todos.values():
        if todo.get("status") == "done":
            continue
        title = str(todo.get("title", ""))
        if "[plan]" in title:
            pending["plan"].append(title)
        elif "[coverage]" in title:
            pending["coverage"].append(title)
        elif "[data-leak]" in title:
            pending["data_leak"].append(title)
        else:
            pending["other"].append(title)
    pending_count = sum(len(v) for v in pending.values())

    state = get_global_report_state()
    findings = len(state.get_existing_vulnerabilities()) if state is not None else 0

    ran = _tools_run()
    if ran is None:
        key_tools_not_run: list[str] | str = "unknown (no audit log yet)"
        unrun_count = 0
    else:
        missing = [t for t in _KEY_TOOLS if t not in ran]
        key_tools_not_run = missing
        unrun_count = len(missing)

    if pending_count == 0 and unrun_count <= 2:
        verdict = "looks_thorough"
        rec = "Coverage looks complete; dedupe_reports then wrap up."
    elif pending_count > 5 or unrun_count >= 5:
        verdict = "shallow"
        rec = "Many classes/tools untouched — keep testing before declaring done."
    else:
        verdict = "in_progress"
        rec = "Some gaps remain; clear the pending items and unrun key probes."

    return {
        "success": True,
        "findings_filed": findings,
        "pending_todo_count": pending_count,
        "pending_by_type": pending,
        "key_tools_not_run": key_tools_not_run,
        "thoroughness": verdict,
        "recommendation": rec,
    }


@function_tool(timeout=30, strict_mode=False)
async def coverage_gaps(ctx: RunContextWrapper) -> str:
    """Report what has NOT been tested yet — the coverage critic.

    Cross-references pending ``[plan]``/``[coverage]``/``[data-leak]`` todos, the
    key probe tools that never appear in the audit log, and the findings filed,
    then returns a blunt ``thoroughness`` verdict (shallow / in_progress /
    looks_thorough) so you know whether a scan is actually done or just shallow.

    Returns JSON with ``pending_by_type``, ``key_tools_not_run``,
    ``findings_filed``, ``thoroughness``, and a ``recommendation``.
    """
    agent_id = "mcp"
    if isinstance(ctx.context, dict):
        agent_id = str(ctx.context.get("agent_id") or "mcp")
    return json.dumps(
        await asyncio.to_thread(_coverage_gaps_impl, agent_id), ensure_ascii=False, default=str
    )
