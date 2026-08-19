"""Detect user/email enumeration on login / reset / signup.

If the app answers differently for an account that exists vs one that doesn't —
a different message, status, response length, or timing — an attacker can
harvest valid emails (and confirm who has an account). AI codegen leaks this
constantly ("No account with that email" vs "Wrong password", or hashing a
password only for real users = slower). Send known-invalid values, plus an
optional known-valid one, and diff the responses.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_LEAK_PHRASES = (
    "no account",
    "not found",
    "does not exist",
    "doesn't exist",
    "not registered",
    "no user",
    "unknown email",
    "email is not",
    "isn't registered",
    "no such user",
)
_LEN_DELTA = 40
_TIMING_DELTA_MS = 400


def _rand_email() -> str:
    return f"strix-{secrets.token_hex(6)}@example.com"


def _inject(
    method: str,
    url: str,
    field: str,
    value: str,
    headers: dict[str, str] | None,
    extra_body: dict[str, Any] | None,
    point: str,
    timeout: int,
) -> dict[str, Any]:
    if point == "query":
        parsed = urlparse(url)
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        query[field] = value
        new_url = urlunparse(parsed._replace(query=urlencode(query)))
        return _replay_impl(method, new_url, headers, None, timeout, allow_redirects=False)
    body = {**(extra_body or {}), field: value}
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    return _replay_impl(method, url, req_headers, json.dumps(body), timeout, allow_redirects=False)


def _normalized(resp: dict[str, Any], value: str) -> tuple[Any, str, int, float]:
    """(status, body-digest with the injected value blanked, length, elapsed)."""
    body = (resp.get("body") or "").replace(value, "<VAL>")
    digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
    return resp.get("status_code"), digest, len(body), resp.get("elapsed_ms") or 0.0


def _user_enum_impl(
    method: str,
    url: str,
    field: str,
    valid_value: str | None,
    headers: dict[str, str] | None,
    extra_body: dict[str, Any] | None,
    injection_point: str,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    point = "query" if injection_point == "query" else "body"

    inv1_val, inv2_val = _rand_email(), _rand_email()
    inv1 = _inject(method, url, field, inv1_val, headers, extra_body, point, timeout)
    inv2 = _inject(method, url, field, inv2_val, headers, extra_body, point, timeout)
    if not inv1.get("success") or not inv2.get("success"):
        return {"success": False, "error": "requests failed — check url/field"}

    n1, n2 = _normalized(inv1, inv1_val), _normalized(inv2, inv2_val)
    baseline_stable = n1[0] == n2[0] and n1[1] == n2[1]

    signals: list[str] = []
    body_lower = (inv1.get("body") or "").lower()
    phrase = next((p for p in _LEAK_PHRASES if p in body_lower), None)
    if phrase:
        signals.append(f"response for a nonexistent account says {phrase!r} (message-based enum)")

    valid_result: dict[str, Any] | None = None
    if valid_value:
        vresp = _inject(method, url, field, valid_value, headers, extra_body, point, timeout)
        if vresp.get("success"):
            nv = _normalized(vresp, valid_value)
            valid_result = {"status": nv[0], "length": nv[2], "elapsed_ms": nv[3]}
            if baseline_stable:
                if nv[0] != n1[0]:
                    signals.append(f"status differs: valid={nv[0]} vs invalid={n1[0]}")
                if nv[1] != n1[1]:
                    signals.append("normalized response body differs for valid vs invalid")
                elif abs(nv[2] - n1[2]) > _LEN_DELTA:
                    signals.append(f"response length differs by {abs(nv[2] - n1[2])} bytes")
            inv_avg_ms = (n1[3] + n2[3]) / 2
            if nv[3] - inv_avg_ms > _TIMING_DELTA_MS:
                signals.append(
                    f"valid account is ~{round(nv[3] - inv_avg_ms)}ms slower (timing enum)"
                )

    return {
        "success": True,
        "url": url,
        "field": field,
        "baseline_stable": baseline_stable,
        "invalid_status": n1[0],
        "valid_result": valid_result,
        "possible_user_enumeration": bool(signals),
        "signals": signals,
        "note": (
            None
            if valid_value
            else "pass valid_value (a known real account) for the strongest status/body/timing diff"
        ),
    }


@function_tool(timeout=120, strict_mode=False)
async def user_enumeration_probe(
    ctx: RunContextWrapper,
    url: str,
    field: str = "email",
    valid_value: str | None = None,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    extra_body: dict[str, Any] | None = None,
    injection_point: str = "body",
    timeout: int = 15,
) -> str:
    """Detect user/email enumeration on login / reset / signup endpoints.

    Sends two known-invalid values (and, if given, a known-valid ``valid_value``)
    and diffs the responses — status, normalized body, length, and timing. A
    stable invalid baseline plus a different response for the valid account =
    enumeration (an attacker can harvest valid emails). Also flags message-based
    leaks ("no account with that email"). Only test authorized targets.

    Returns JSON with ``possible_user_enumeration``, the ``signals`` found, and
    ``baseline_stable``.

    Args:
        url: The endpoint (login, password-reset, or signup).
        field: JSON field / query param holding the email or username.
        valid_value: A known real account, for the strongest diff (optional).
        method: HTTP method (default POST).
        headers: Request headers (e.g. content type, CSRF token).
        extra_body: Other required body fields (e.g. a dummy ``password``).
        injection_point: ``body`` (default) or ``query``.
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _user_enum_impl,
            method,
            url,
            field,
            valid_value,
            headers,
            extra_body,
            injection_point,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
