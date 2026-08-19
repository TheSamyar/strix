"""Spray a small default-credential list at a login endpoint.

Vibe apps ship seeded demo/admin accounts and never change them. This tries a
short, high-signal list and detects a successful login by diffing against a
known-wrong baseline (a session cookie appears, the status/redirect changes, or
the 'invalid' message disappears).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_DEFAULT_PAIRS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "changeme"),
    ("admin", "[email protected]"),
    ("admin", "12345678"),
    ("administrator", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("demo", "demo"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin@example.com", "password"),
    ("admin@admin.com", "admin"),
)
_FAIL_MARKERS = ("invalid", "incorrect", "wrong", "failed", "denied", "not found", "try again")


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def _looks_success(resp: dict[str, Any], wrong: dict[str, Any]) -> bool:
    status = resp.get("status_code")
    if not isinstance(status, int):
        return False
    headers = {k.lower(): str(v) for k, v in (resp.get("response_headers") or {}).items()}
    set_cookie = headers.get("set-cookie", "").lower()
    body = (resp.get("body") or "").lower()
    got_session = any(t in set_cookie for t in ("session", "token", "auth", "sid", "jwt"))
    # Differs from the known-wrong response AND shows a success signal.
    differs = status != wrong.get("status") or _digest(resp.get("body") or "") != wrong.get(
        "digest"
    )
    success_signal = got_session or (
        status in (200, 302) and not any(m in body for m in _FAIL_MARKERS)
    )
    return differs and success_signal


def _default_creds_impl(
    login_url: str,
    username_field: str,
    password_field: str,
    method: str,
    headers: dict[str, str] | None,
    extra_pairs: list[list[str]] | None,
    timeout: int,
) -> dict[str, Any]:
    if not login_url:
        return {"success": False, "error": "login_url is required"}
    req_headers = {"Content-Type": "application/json", **(headers or {})}

    def _login(user: str, pw: str) -> dict[str, Any]:
        body = json.dumps({username_field: user, password_field: pw})
        return _replay_impl(method, login_url, req_headers, body, timeout, allow_redirects=False)

    wrong_resp = _login("strixnope-8f3a", "strixnope-wrongpw-921")
    wrong = {
        "status": wrong_resp.get("status_code"),
        "digest": _digest(wrong_resp.get("body") or ""),
    }

    pairs = list(_DEFAULT_PAIRS) + [(p[0], p[1]) for p in (extra_pairs or []) if len(p) == 2]
    hits: list[dict[str, str]] = []
    for user, pw in pairs:
        resp = _login(user, pw)
        if resp.get("success") and _looks_success(resp, wrong):
            hits.append({"username": user, "password": pw})
    return {
        "success": True,
        "login_url": login_url,
        "tried": len(pairs),
        "valid_credentials": hits,
        "possible_default_creds": bool(hits),
    }


@function_tool(timeout=180, strict_mode=False)
async def default_creds(
    ctx: RunContextWrapper,
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",  # noqa: S107 (field name, not a secret)
    method: str = "POST",
    headers: dict[str, str] | None = None,
    extra_pairs: list[list[str]] | None = None,
    timeout: int = 15,
) -> str:
    """Spray a small default-credential list at a login endpoint.

    Baselines a known-wrong login, then tries common defaults (``admin/admin``,
    ``admin/password``, seeded demo accounts…). A response that differs from the
    wrong baseline and shows a success signal (session cookie / 200 / 302 with no
    'invalid' message) is flagged as valid. Add ``extra_pairs`` for app-specific
    guesses. Only test authorized targets.

    Returns JSON with ``valid_credentials`` and ``possible_default_creds``.

    Args:
        login_url: The login endpoint.
        username_field: JSON field for the username/email (default ``username``).
        password_field: JSON field for the password (default ``password``).
        method: HTTP method (default POST).
        headers: Extra request headers.
        extra_pairs: More ``[username, password]`` pairs to try.
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _default_creds_impl,
            login_url,
            username_field,
            password_field,
            method,
            headers,
            extra_pairs,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
