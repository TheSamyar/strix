"""MCP tools: expand hosts / ingest specs, then walk every recorded endpoint."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agents import RunContextWrapper, function_tool

from strix.core.paths import run_dir_for
from strix.harvest import (
    current_run_dir,
    file_harvest_findings,
    group_leak_candidates,
    load_hosts,
)
from strix.harvest import (
    discover_assets as discover_assets_impl,
)
from strix.harvest import (
    walk_unauth as walk_unauth_impl,
)
from strix.report.state import get_global_report_state
from strix.tools.attack_surface.tools import _list_attack_surface_impl


if TYPE_CHECKING:
    from pathlib import Path


def _parent_dir() -> Path:
    return current_run_dir() or run_dir_for(
        getattr(get_global_report_state(), "run_name", None) or "mcp"
    )


@function_tool(timeout=120)
async def discover_assets(ctx: RunContextWrapper, seed_url: str) -> str:
    """Expand one seed URL into live sibling hosts and ingest OpenAPI/tool catalogs.

    Writes hosts.json and fills attack_surface.json. Call walk_unauth next.
    """
    del ctx
    parent = _parent_dir()
    hosts, imported = discover_assets_impl([seed_url], parent)
    return json.dumps(
        {
            "success": True,
            "run_dir": str(parent),
            "imported": imported,
            "hosts": [host.to_dict() for host in hosts],
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=300)
async def walk_unauth(ctx: RunContextWrapper, base_url: str | None = None) -> str:
    """Unauth-probe every recorded endpoint (GET or empty JSON). Writes walk.jsonl.

    Files leak candidates (schema/2xx/traceback). Then call coverage_report.
    """
    del ctx
    parent = _parent_dir()
    if not base_url:
        live = next((host for host in load_hosts(parent / "hosts.json") if host.get("live")), None)
        base_url = str((live or {}).get("url") or "")
    results = walk_unauth_impl(
        _list_attack_surface_impl()["endpoints"],
        base_url=base_url or "",
        walk_path=parent / "walk.jsonl",
    )
    groups = group_leak_candidates(results)
    file_harvest_findings(parent, groups)
    return json.dumps(
        {
            "success": True,
            "walked": len(results),
            "candidates": len(groups),
            "walk_path": str(parent / "walk.jsonl"),
        },
        ensure_ascii=False,
        default=str,
    )
