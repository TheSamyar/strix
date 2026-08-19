"""Actively test a state-changing action for CSRF.

security_headers checks SameSite; this proves the bug: replay a state-changing
request (change email/password, transfer, delete) with the CSRF token removed and
with a forged cross-site Origin. If the server still accepts it, an attacker can
trigger the action from any site the victim visits — one-click account takeover.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_EVIL_ORIGIN = "https://evil-strix.example"
_CSRF_HEADER_NAMES = ("x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken")


def _authorized(resp: dict[str, Any]) -> bool:
    status = resp.get("status_code")
    return isinstance(status, int) and 200 <= status < 400


def _strip_csrf(
    headers: dict[str, str], body: str | None, csrf_field: str
) -> tuple[dict[str, str], str | None]:
    clean_headers = {k: v for k, v in headers.items() if k.lower() not in _CSRF_HEADER_NAMES}
    clean_body = body
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and csrf_field in parsed:
                parsed.pop(csrf_field)
                clean_body = json.dumps(parsed)
        except (json.JSONDecodeError, ValueError):
            clean_body = body
    return clean_headers, clean_body


def _csrf_probe_impl(
    method: str,
    url: str,
    body: str | None,
    headers: dict[str, str] | None,
    csrf_field: str,
    timeout: int,
) -> dict[str, Any]:
    if not url or method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return {"success": False, "error": "csrf_probe needs a state-changing method + url"}
    hdrs = dict(headers or {})
    base = _replay_impl(method, url, hdrs, body, timeout, allow_redirects=False)
    if not base.get("success"):
        return {"success": False, "error": base.get("error")}
    base_ok = _authorized(base)
    if not base_ok:
        return {
            "success": True,
            "inconclusive": True,
            "reason": "the baseline request did not succeed — supply a valid session + body",
            "base_status": base.get("status_code"),
        }

    findings: list[str] = []

    # 1. Forged cross-site Origin/Referer.
    forged = {**hdrs, "Origin": _EVIL_ORIGIN, "Referer": _EVIL_ORIGIN + "/"}
    o_resp = _replay_impl(method, url, forged, body, timeout, allow_redirects=False)
    if _authorized(o_resp):
        findings.append("accepts a forged cross-site Origin/Referer — no origin check")

    # 2. CSRF token removed.
    clean_headers, clean_body = _strip_csrf(hdrs, body, csrf_field)
    if clean_headers != hdrs or clean_body != body:
        t_resp = _replay_impl(
            method, url, clean_headers, clean_body, timeout, allow_redirects=False
        )
        if _authorized(t_resp):
            findings.append("accepts the request with the CSRF token removed — no CSRF enforcement")
    else:
        findings.append("no CSRF token was present to begin with — likely unprotected")

    return {
        "success": True,
        "url": url,
        "method": method.upper(),
        "base_status": base.get("status_code"),
        "possible_csrf": bool(findings),
        "findings": findings,
    }


@function_tool(timeout=90, strict_mode=False)
async def csrf_probe(
    ctx: RunContextWrapper,
    url: str,
    method: str = "POST",
    body: str | None = None,
    headers: dict[str, str] | None = None,
    csrf_field: str = "csrf_token",
    timeout: int = 15,
) -> str:
    """Actively test a state-changing action for CSRF.

    Sends the request three ways with the victim session: as-is (must succeed),
    with a forged cross-site ``Origin``/``Referer``, and with the CSRF token
    stripped (from the body ``csrf_field`` and common CSRF headers). If either
    tampered request still succeeds, the action is CSRF-able → one-click ATO.
    Only test authorized targets.

    Returns JSON with ``possible_csrf`` and the ``findings``.

    Args:
        url: The state-changing endpoint (change email/password, transfer, …).
        method: POST/PUT/PATCH/DELETE (default POST).
        body: The request body that performs the action (JSON).
        headers: Headers carrying the victim session (+ any CSRF token/header).
        csrf_field: The CSRF token field name in the body (default ``csrf_token``).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_csrf_probe_impl, method, url, body, headers, csrf_field, timeout),
        ensure_ascii=False,
        default=str,
    )
