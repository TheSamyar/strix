"""Detect excessive data exposure (OWASP API3) in a JSON response.

AI codegen does ``SELECT *`` then ``res.json(row)``, so an endpoint the UI uses
to show a name actually returns password hashes, tokens, internal flags, and
other users' PII. This fetches the endpoint (as whatever identity you pass) and
flags sensitive field names present in the response the client receives.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.batching import url_batch
from strix.tools.http_replay.tools import _replay_impl


# Field names that should almost never reach a client.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "hash",
        "password_hash",
        "salt",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "ssn",
        "is_admin",
        "isadmin",
        "admin",
        "role",
        "permissions",
        "internal",
        "stripe_id",
        "stripe_customer_id",
        "cvv",
        "card_number",
        "credit_card",
        "dob",
        "date_of_birth",
        "salary",
        "session",
        "otp",
        "reset_token",
        "verification_code",
    }
)
_MAX_DEPTH = 8


def _walk_keys(obj: Any, depth: int, path: str, found: dict[str, str]) -> None:
    if depth > _MAX_DEPTH:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).lower() in _SENSITIVE_KEYS:
                found.setdefault(str(key).lower(), here)
            _walk_keys(value, depth + 1, here, found)
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:20]):
            _walk_keys(item, depth + 1, f"{path}[{i}]", found)


def _data_exposure_impl(
    method: str, url: str, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    resp = _replay_impl(method, url, headers, None, timeout, allow_redirects=False)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error")}
    body = resp.get("body") or ""
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return {
            "success": True,
            "url": url,
            "possible_excessive_exposure": False,
            "note": "response is not JSON — inspect manually / use ssr_leak_scan for HTML",
        }
    found: dict[str, str] = {}
    _walk_keys(parsed, 0, "", found)
    return {
        "success": True,
        "url": url,
        "status_code": resp.get("status_code"),
        "possible_excessive_exposure": bool(found),
        "sensitive_fields": sorted(found),
        "field_paths": found,
    }


@function_tool(timeout=60, strict_mode=False)
async def data_exposure_probe(
    ctx: RunContextWrapper,
    url: str = "",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 15,
    urls: list[str] | None = None,
) -> str:
    """Flag excessive data exposure (OWASP API3) in an endpoint's JSON response.

    Fetches the endpoint (as whatever identity ``headers`` carry) and recursively
    scans the JSON for sensitive field names — ``password``/``hash``/``token``/
    ``is_admin``/``stripe_id``/``ssn``/… — that the client should never receive.
    Their presence means the API returns more than the UI shows. Only test
    authorized targets.

    Returns JSON with ``possible_excessive_exposure``, ``sensitive_fields``, and
    the ``field_paths`` where each was found. In batch mode returns ``results`` —
    one such object per URL (each with its ``url``) — plus ``count``; the same
    ``method`` and ``headers`` apply to every URL.

    Args:
        url: The endpoint to inspect (single-URL mode).
        method: HTTP method (default GET).
        headers: Session headers — test as a normal, low-privilege user.
        timeout: Request timeout in seconds (default 15).
        urls: Optional list of endpoints to inspect in one call (max 25) — same
            per-URL scan with the same method/headers, one call instead of one
            per endpoint. Overrides ``url``.
    """
    del ctx
    if urls:

        def _one(u: str, t: int) -> dict[str, Any]:
            return _data_exposure_impl(method, u, headers, t)

        return json.dumps(
            await asyncio.to_thread(url_batch, _one, urls, timeout),
            ensure_ascii=False,
            default=str,
        )
    return json.dumps(
        await asyncio.to_thread(_data_exposure_impl, method, url, headers, timeout),
        ensure_ascii=False,
        default=str,
    )
