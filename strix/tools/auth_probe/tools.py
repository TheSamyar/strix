"""Check whether logout actually invalidates a session/token (broken auth).

Generated auth often "logs out" client-side only — it drops the cookie in the
browser but the server keeps the session/JWT valid forever. Oracle: a token that
still reaches a protected endpoint AFTER logout is a broken-session-invalidation
finding (OWASP API2). Also covers reuse of a supplied old token.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


def _authorized(resp: dict[str, Any]) -> bool:
    status = resp.get("status_code")
    return isinstance(status, int) and 200 <= status < 300


def _session_invalidation_impl(
    protected_url: str,
    logout_url: str,
    headers: dict[str, str] | None,
    method: str,
    logout_method: str,
    timeout: int,
) -> dict[str, Any]:
    if not protected_url or not logout_url:
        return {"success": False, "error": "protected_url and logout_url are required"}
    if not headers:
        return {"success": False, "error": "headers must carry the session (cookie/bearer)"}

    before = _replay_impl(method, protected_url, headers, None, timeout, allow_redirects=False)
    if not before.get("success"):
        return {"success": False, "error": f"protected request failed: {before.get('error')}"}
    if not _authorized(before):
        return {
            "success": True,
            "inconclusive": True,
            "reason": "token was not authorized before logout — supply a valid session",
            "before_status": before.get("status_code"),
        }

    logout = _replay_impl(logout_method, logout_url, headers, None, timeout, allow_redirects=False)
    after = _replay_impl(method, protected_url, headers, None, timeout, allow_redirects=False)
    still_authorized = _authorized(after)
    return {
        "success": True,
        "before_status": before.get("status_code"),
        "logout_status": logout.get("status_code"),
        "after_status": after.get("status_code"),
        "still_authorized_after_logout": still_authorized,
        "broken_session_invalidation": still_authorized,
        "note": (
            "token still works after logout — server-side session not invalidated"
            if still_authorized
            else "token rejected after logout — invalidation works"
        ),
    }


@function_tool(timeout=90, strict_mode=False)
async def session_invalidation_probe(
    ctx: RunContextWrapper,
    protected_url: str,
    logout_url: str,
    headers: dict[str, str],
    method: str = "GET",
    logout_method: str = "POST",
    timeout: int = 15,
) -> str:
    """Test whether logout actually invalidates the session/token server-side.

    Hits ``protected_url`` with the session (must be 200), calls ``logout_url``,
    then hits ``protected_url`` again with the SAME session. Still authorized =
    ``broken_session_invalidation`` (client-side-only logout — the token lives
    forever). Only test authorized targets.

    Returns JSON with ``before_status`` / ``logout_status`` / ``after_status``
    and ``broken_session_invalidation``.

    Args:
        protected_url: An endpoint that requires auth (200 while logged in).
        logout_url: The logout endpoint.
        headers: Headers carrying the session (``Cookie`` or ``Authorization``).
        method: Method for the protected endpoint (default GET).
        logout_method: Method for logout (default POST).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _session_invalidation_impl,
            protected_url,
            logout_url,
            headers,
            method,
            logout_method,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
