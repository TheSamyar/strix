"""Session-fixation + reset-token weakness probes (account-takeover).

Session fixation: if the session id issued before login is still valid after
login (no rotation), an attacker who plants a known session id owns the victim's
authenticated session. Reset-token: a password-reset token echoed in the
response, or predictable across requests, is a direct account-takeover.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_TOKEN_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}"  # JWT
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # uuid
    r"|\b[0-9a-fA-F]{24,64}\b"  # long hex token
)


def _cookie_value(resp: dict[str, Any], name: str) -> str | None:
    headers = resp.get("response_headers") or {}
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            m = re.search(rf"{re.escape(name)}=([^;,\s]+)", str(value))
            if m:
                return m.group(1)
    return None


def _session_fixation_impl(
    login_url: str,
    login_body: dict[str, Any],
    session_cookie_name: str,
    headers: dict[str, str] | None,
    method: str,
    timeout: int,
) -> dict[str, Any]:
    if not login_url or not login_body:
        return {"success": False, "error": "login_url and login_body are required"}
    pre = _replay_impl("GET", login_url, headers, None, timeout, allow_redirects=False)
    pre_cookie = _cookie_value(pre, session_cookie_name) if pre.get("success") else None

    cookie_hdr = {"Cookie": f"{session_cookie_name}={pre_cookie}"} if pre_cookie else {}
    req_headers = {"Content-Type": "application/json", **(headers or {}), **cookie_hdr}
    post = _replay_impl(
        method, login_url, req_headers, json.dumps(login_body), timeout, allow_redirects=False
    )
    post_cookie = _cookie_value(post, session_cookie_name) if post.get("success") else None

    # Rotated if login issued a new, different session id.
    rotated = bool(post_cookie and post_cookie != pre_cookie)
    fixation = bool(pre_cookie) and not rotated
    return {
        "success": True,
        "pre_login_session": pre_cookie,
        "post_login_session": post_cookie,
        "session_rotated_on_login": rotated,
        "possible_session_fixation": fixation,
        "note": (
            "session id not rotated on login — confirm the login actually succeeded, "
            "then a planted session id survives authentication"
            if fixation
            else "session id rotated (or none issued) — fixation unlikely"
        ),
    }


def _reset_token_impl(
    reset_url: str,
    email_field: str,
    email: str,
    headers: dict[str, str] | None,
    method: str,
    timeout: int,
) -> dict[str, Any]:
    if not reset_url or not email:
        return {"success": False, "error": "reset_url and email are required"}
    req_headers = {"Content-Type": "application/json", **(headers or {})}

    def _request() -> tuple[Any, list[str]]:
        resp = _replay_impl(
            method,
            reset_url,
            req_headers,
            json.dumps({email_field: email}),
            timeout,
            allow_redirects=False,
        )
        blob = (
            (resp.get("body") or "")
            + " "
            + str((resp.get("response_headers") or {}).get("Location", ""))
        )
        return resp, _TOKEN_RE.findall(blob)

    r1, tokens1 = _request()
    if not r1.get("success"):
        return {"success": False, "error": r1.get("error")}
    _, tokens2 = _request()

    findings: list[str] = []
    if tokens1:
        findings.append("reset token exposed in the response/redirect — direct account takeover")
    if tokens1 and tokens2:
        a, b = tokens1[0], tokens2[0]
        common = 0
        for x, y in zip(a, b, strict=False):
            if x != y:
                break
            common += 1
        if a == b or common > len(a) // 2:
            findings.append("reset tokens are predictable (near-identical across requests)")
    return {
        "success": True,
        "tokens_seen_in_response": len(tokens1),
        "possible_reset_weakness": bool(findings),
        "findings": findings,
    }


@function_tool(timeout=90, strict_mode=False)
async def session_fixation_probe(
    ctx: RunContextWrapper,
    login_url: str,
    login_body: dict[str, Any],
    session_cookie_name: str = "session",
    headers: dict[str, str] | None = None,
    method: str = "POST",
    timeout: int = 15,
) -> str:
    """Test whether login rotates the session id (session fixation).

    Grabs the anonymous session cookie from the login page, logs in carrying that
    cookie, and checks whether a new session id is issued. Not rotated =
    ``possible_session_fixation`` (a planted session id survives authentication →
    ATO). Confirm the login actually succeeded. Only test authorized targets.

    Returns JSON with ``pre_login_session`` / ``post_login_session`` /
    ``session_rotated_on_login`` and ``possible_session_fixation``.

    Args:
        login_url: The login endpoint.
        login_body: Valid login credentials (JSON body).
        session_cookie_name: The session cookie name (default ``session``).
        headers: Extra request headers.
        method: Login method (default POST).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _session_fixation_impl,
            login_url,
            login_body,
            session_cookie_name,
            headers,
            method,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=90, strict_mode=False)
async def reset_token_probe(
    ctx: RunContextWrapper,
    reset_url: str,
    email: str,
    email_field: str = "email",
    headers: dict[str, str] | None = None,
    method: str = "POST",
    timeout: int = 15,
) -> str:
    """Test password-reset for token leakage / predictability (account takeover).

    Requests a reset for ``email`` twice and checks whether a reset token appears
    in the response/redirect (a direct ATO) or is predictable across requests. A
    correct flow returns nothing token-shaped (the token only goes to email).
    Only test authorized targets.

    Returns JSON with ``tokens_seen_in_response`` and ``possible_reset_weakness``.

    Args:
        reset_url: The password-reset request endpoint.
        email: A real account's email to request a reset for.
        email_field: The JSON field holding the email (default ``email``).
        headers: Extra request headers.
        method: HTTP method (default POST).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _reset_token_impl, reset_url, email_field, email, headers, method, timeout
        ),
        ensure_ascii=False,
        default=str,
    )
