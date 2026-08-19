"""Fire a GraphQL introspection query and flag it if the schema comes back.

Introspection left on in prod hands an attacker the full type/field map — the
starting point for every other GraphQL attack. AI codegen ships Apollo/Yoga
with introspection enabled by default.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


# Minimal introspection query — enough to prove the schema is exposed.
_INTROSPECTION_QUERY = (
    "query{__schema{queryType{name}mutationType{name}types{name kind fields{name}}}}"
)


def _graphql_introspection_impl(
    url: str, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    body = json.dumps({"query": _INTROSPECTION_QUERY})
    resp = _replay_impl("POST", url, req_headers, body, timeout, allow_redirects=False)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error")}
    text = resp.get("body") or ""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None

    schema = parsed.get("data", {}).get("__schema") if isinstance(parsed, dict) else None
    schema = schema if isinstance(schema, dict) else {}
    types = schema.get("types")
    types = types if isinstance(types, list) else []
    exposed = bool(types)
    type_names = [t.get("name") for t in types if isinstance(t, dict)][:50]
    query_type = schema.get("queryType") or {}
    return {
        "success": True,
        "url": url,
        "status_code": resp.get("status_code"),
        "introspection_enabled": exposed,
        "type_count": len(types),
        "types_sample": type_names,
        "query_type": query_type.get("name") if isinstance(query_type, dict) else None,
    }


@function_tool(timeout=60, strict_mode=False)
async def graphql_introspection(
    ctx: RunContextWrapper,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> str:
    """Test a GraphQL endpoint for enabled introspection.

    POSTs an ``__schema`` introspection query; if the schema (with types) comes
    back, introspection is exposed — flag it and use ``types_sample`` to plan
    deeper GraphQL testing. Only test authorized targets.

    Returns JSON with ``introspection_enabled``, ``type_count``,
    ``types_sample``, and ``query_type``.

    Args:
        url: GraphQL endpoint URL (e.g. ``https://x/graphql``).
        headers: Optional headers (e.g. auth, if the endpoint needs it).
        timeout: Request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_graphql_introspection_impl, url, headers, timeout),
        ensure_ascii=False,
        default=str,
    )
