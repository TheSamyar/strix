"""Probe Supabase / Firebase for open Backend-as-a-Service rules.

~60% of AI-built Supabase apps ship broken Row Level Security, and the anon key
is public by design — so an unauthenticated PostgREST read that returns rows is
a confirmed data leak. Firebase Realtime DB with public rules leaks the whole
tree at ``/<path>.json``. Both are the dominant vibe-code data-exposure bug.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_COMMON_TABLES = ("users", "profiles", "orders", "payments", "messages", "subscriptions")


def _supabase_read(base: str, table: str, anon_key: str, timeout: int) -> dict[str, Any]:
    url = f"{base.rstrip('/')}/rest/v1/{table}?select=*&limit=2"
    headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}
    resp = _replay_impl("GET", url, headers, None, timeout, allow_redirects=False)
    if not resp.get("success"):
        return {"table": table, "error": resp.get("error")}
    status = resp.get("status_code")
    rows: list[Any] = []
    try:
        parsed = json.loads(resp.get("body") or "")
        if isinstance(parsed, list):
            rows = parsed
    except (json.JSONDecodeError, ValueError):
        parsed = None
    # PostgREST returns 200 [] when RLS filters everything, 200 [rows] when a
    # policy exposes data, 401/permission error when the key/route is rejected.
    exposed = status == 200 and len(rows) > 0
    return {
        "table": table,
        "status_code": status,
        "rows_returned": len(rows),
        "exposed": exposed,
        "note": "rows readable with anon key = broken RLS" if exposed else None,
        "sample": rows[:2] if exposed else None,
    }


def _firebase_read(base: str, path: str, timeout: int) -> dict[str, Any]:
    url = f"{base.rstrip('/')}/{path.strip('/')}.json"
    resp = _replay_impl("GET", url, None, None, timeout, allow_redirects=False)
    if not resp.get("success"):
        return {"path": path, "error": resp.get("error")}
    status = resp.get("status_code")
    body = resp.get("body") or ""
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    # Public rules → 200 with data (non-null). Locked → 401 "Permission denied".
    exposed = status == 200 and parsed not in (None, {}, [])
    return {
        "path": path,
        "status_code": status,
        "exposed": exposed,
        "note": "readable without auth = open Firebase rules" if exposed else None,
        "sample": body[:500] if exposed else None,
    }


def _backend_rules_probe_impl(
    provider: str,
    base_url: str,
    anon_key: str | None,
    tables: list[str] | None,
    timeout: int,
) -> dict[str, Any]:
    if not base_url or not base_url.strip():
        return {"success": False, "error": "base_url cannot be empty"}
    provider = (provider or "auto").lower()
    if provider == "auto":
        provider = "firebase" if "firebase" in base_url else "supabase"

    targets = tables or list(_COMMON_TABLES)
    results: list[dict[str, Any]] = []
    if provider == "supabase":
        if not anon_key:
            return {"success": False, "error": "supabase probe needs anon_key (from the JS bundle)"}
        results = [_supabase_read(base_url, t, anon_key, timeout) for t in targets]
    elif provider == "firebase":
        results = [_firebase_read(base_url, p, timeout) for p in targets]
    else:
        return {
            "success": False,
            "error": f"unknown provider {provider!r} (supabase|firebase|auto)",
        }

    exposed = [r for r in results if r.get("exposed")]
    return {
        "success": True,
        "provider": provider,
        "base_url": base_url,
        "exposed_count": len(exposed),
        "possible_open_rules": bool(exposed),
        "results": results,
    }


@function_tool(timeout=120, strict_mode=False)
async def backend_rules_probe(
    ctx: RunContextWrapper,
    base_url: str,
    provider: str = "auto",
    anon_key: str | None = None,
    tables: list[str] | None = None,
    timeout: int = 15,
) -> str:
    """Probe Supabase RLS / Firebase rules for unauthenticated data exposure.

    Supabase: reads ``/rest/v1/<table>?select=*`` with the public anon key —
    rows returned = broken RLS (confirmed leak). Firebase: reads
    ``/<path>.json`` unauthenticated — non-null data = open rules. Pull the
    Supabase URL + anon key from the app's JS bundle first (see
    frontend_secret_scan). Only test authorized targets.

    Returns JSON with ``provider``, per-target ``exposed`` + ``sample``, and an
    overall ``possible_open_rules`` + ``exposed_count``.

    Args:
        base_url: Supabase project URL (``https://<ref>.supabase.co``) or
            Firebase RTDB URL (``https://<proj>.firebaseio.com``).
        provider: ``supabase`` / ``firebase`` / ``auto`` (default auto by URL).
        anon_key: Supabase anon (public) key — required for supabase.
        tables: Tables (supabase) or paths (firebase) to test; defaults to a
            common set (users, profiles, orders, payments, …).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _backend_rules_probe_impl, provider, base_url, anon_key, tables, timeout
        ),
        ensure_ascii=False,
        default=str,
    )
