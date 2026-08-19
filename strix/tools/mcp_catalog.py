"""On-demand MCP tool advertisement: search_tools + load_tool.

# ponytail: process-wide in-memory set (fine for one stdio MCP). Reset via
# ``reset_advertised_tools`` (tests / bootstrap). Upgrade: per-session set
# if the server ever multiplexes clients.
"""

from __future__ import annotations


SEARCH_LIMIT = 25
LOAD_EXTRA_CAP = 20

CORE_HOST_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "load_skill",
        "profile_target",
        "plan_tests",
        "endpoint_risk_rank",
        "check_tools",
        "create_vulnerability_report",
        "create_dependency_report",
        "list_reports",
        "get_report",
        "validate_finding",
        "coverage_gaps",
        "coverage_report",
        "create_todo",
        "list_todos",
        "update_todo",
        "mark_todo_done",
        "dedupe_reports",
        "retest_findings",
        "web_search",
    }
)

META_TOOL_NAMES: frozenset[str] = frozenset({"search_tools", "load_tool"})
_ALWAYS_ADVERTISED: frozenset[str] = (
    CORE_HOST_TOOL_NAMES | META_TOOL_NAMES | frozenset({"list_skills"})
)

_extra_loaded: set[str] = set()


def reset_advertised_tools() -> None:
    """Drop session extras so tools/list is the default core again."""
    _extra_loaded.clear()


def advertised_host_names() -> set[str]:
    """Host-tool names that should appear in tools/list (plus extras)."""
    return set(CORE_HOST_TOOL_NAMES) | set(META_TOOL_NAMES) | set(_extra_loaded)


def search_catalog(query: str, entries: list[tuple[str, str]]) -> list[dict[str, str]]:
    needle = query.casefold()
    hits: list[dict[str, str]] = []
    for name, description in entries:
        if needle in name.casefold() or needle in description.casefold():
            hits.append({"name": name, "description": description})
            if len(hits) >= SEARCH_LIMIT:
                break
    return hits


def apply_load_tool(names: list[str], known_names: set[str]) -> tuple[list[str], list[str]]:
    """Load known names into the advertised extra set. Returns (loaded, errors)."""
    loaded: list[str] = []
    errors: list[str] = []
    for name in names:
        if name not in known_names:
            errors.append(f"unknown tool: {name}")
            continue
        if name in _ALWAYS_ADVERTISED or name in _extra_loaded:
            loaded.append(name)
            continue
        if len(_extra_loaded) >= LOAD_EXTRA_CAP:
            errors.append(f"extra-tool cap ({LOAD_EXTRA_CAP}) reached; skipped {name}")
            continue
        _extra_loaded.add(name)
        loaded.append(name)
    return loaded, errors
