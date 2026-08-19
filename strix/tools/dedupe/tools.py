"""Merge duplicate vulnerability reports so the findings list isn't N copies
of one bug. Two reports collide when they're the same finding class on the
same endpoint + method + target."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.report.state import get_global_report_state


def _dedupe_reports_impl() -> dict[str, Any]:
    state = get_global_report_state()
    if state is None:
        return {"success": False, "error": "no active run"}
    result = state.dedupe_vulnerability_reports()
    return {"success": True, **result}


@function_tool(timeout=30)
async def dedupe_reports(ctx: RunContextWrapper) -> str:
    """Merge duplicate vulnerability reports filed this run.

    Groups findings by (finding class, endpoint, method, target) and keeps the
    first of each group, recording how many duplicates it absorbed in the kept
    report's ``duplicates_merged`` field. Rewrites vulnerabilities.json / .csv /
    .sarif and drops the orphaned per-finding markdown files. Idempotent — a
    second call with no new dupes removes nothing.

    Returns JSON with ``removed_count``, ``removed_ids``, and ``kept_count``.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_dedupe_reports_impl), ensure_ascii=False, default=str
    )
