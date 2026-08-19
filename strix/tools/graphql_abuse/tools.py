"""GraphQL abuse beyond introspection: batching, aliasing, field-suggestion leak.

Query/array batching and aliasing let one HTTP request run many operations —
bypassing rate limits and enabling brute force (N login attempts in one POST).
Field suggestions ("Did you mean …") leak the schema even with introspection
off. All checks are schema-agnostic (use ``__typename``), so they work on any
GraphQL endpoint. Deterministic oracles.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


def _post_gql(url: str, payload: Any, headers: dict[str, str] | None, timeout: int) -> Any:
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    resp = _replay_impl(
        "POST", url, req_headers, json.dumps(payload), timeout, allow_redirects=False
    )
    if not resp.get("success"):
        return None
    try:
        return json.loads(resp.get("body") or "")
    except (json.JSONDecodeError, ValueError):
        return None


def _check_array_batching(url: str, headers: dict[str, str] | None, n: int, timeout: int) -> bool:
    # A batched array request; a server that supports it returns a list of N results.
    batch = [{"query": "{__typename}"} for _ in range(n)]
    result = _post_gql(url, batch, headers, timeout)
    return isinstance(result, list) and len(result) == n


def _check_alias_batching(url: str, headers: dict[str, str] | None, n: int, timeout: int) -> bool:
    # One query with N aliased fields; if all N resolve, aliasing is unbounded.
    aliases = " ".join(f"a{i}:__typename" for i in range(n))
    result = _post_gql(url, {"query": "{" + aliases + "}"}, headers, timeout)
    if not isinstance(result, dict):
        return False
    data = result.get("data")
    return isinstance(data, dict) and len([k for k in data if k.startswith("a")]) == n


def _check_field_suggestions(url: str, headers: dict[str, str] | None, timeout: int) -> bool:
    result = _post_gql(url, {"query": "{ thisFieldDoesNotExist917 }"}, headers, timeout)
    text = json.dumps(result) if result is not None else ""
    return "Did you mean" in text


def _graphql_abuse_impl(
    url: str, headers: dict[str, str] | None, alias_count: int, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    n = max(2, min(alias_count, 100))
    array_batching = _check_array_batching(url, headers, n, timeout)
    alias_batching = _check_alias_batching(url, headers, n, timeout)
    field_suggestions = _check_field_suggestions(url, headers, timeout)
    findings: list[str] = []
    if array_batching:
        findings.append(f"array batching: {n} operations run in one request (rate-limit bypass)")
    if alias_batching:
        findings.append(f"alias batching: {n} aliased fields resolved (brute-force amplifier)")
    if field_suggestions:
        findings.append(
            "field suggestions ('Did you mean') — schema leaks even with introspection off"
        )
    return {
        "success": True,
        "url": url,
        "array_batching": array_batching,
        "alias_batching": alias_batching,
        "field_suggestions_enabled": field_suggestions,
        "possible_abuse": bool(findings),
        "findings": findings,
    }


@function_tool(timeout=90, strict_mode=False)
async def graphql_abuse(
    ctx: RunContextWrapper,
    url: str,
    headers: dict[str, str] | None = None,
    alias_count: int = 50,
    timeout: int = 20,
) -> str:
    """Test a GraphQL endpoint for batching/aliasing abuse and schema leaks.

    Schema-agnostic checks (via ``__typename``): array batching (a list of N ops
    in one POST), alias batching (N aliased fields in one query) — both bypass
    rate limits and amplify brute force — and field suggestions ("Did you mean"),
    which leak the schema even when introspection is disabled. Pair with
    ``graphql_introspection``. Only test authorized targets.

    Returns JSON with ``array_batching`` / ``alias_batching`` /
    ``field_suggestions_enabled`` and an overall ``possible_abuse``.

    Args:
        url: GraphQL endpoint URL.
        headers: Optional headers (e.g. auth).
        alias_count: How many batched ops / aliases to send (default 50, max 100).
        timeout: Per-request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_graphql_abuse_impl, url, headers, alias_count, timeout),
        ensure_ascii=False,
        default=str,
    )
