"""Fire N rapid requests at an endpoint and check for rate limiting.

Rate limiting is never in the default codegen prompt, so login / OTP /
password-reset / expensive endpoints ship unthrottled — brute-force and
billing-abuse waiting to happen. Signal: no 429 and no RateLimit-*/Retry-After
across a burst.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_MAX_REQUESTS = 100
_THROTTLE_HEADERS = ("retry-after", "ratelimit-limit", "ratelimit-remaining", "x-ratelimit-limit")


def _has_throttle_header(headers: dict[str, str]) -> bool:
    lower = {k.lower() for k in headers}
    return any(h in lower for h in _THROTTLE_HEADERS)


def _rate_limit_probe_impl(
    method: str,
    url: str,
    count: int,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    count = max(1, min(count, _MAX_REQUESTS))
    statuses: list[int] = []
    saw_429 = False
    saw_header = False
    errors = 0
    for _ in range(count):
        resp = _replay_impl(method, url, headers, body, timeout, allow_redirects=False)
        if not resp.get("success"):
            errors += 1
            continue
        status = resp.get("status_code")
        if isinstance(status, int):
            statuses.append(status)
            if status == 429:
                saw_429 = True
        if _has_throttle_header(resp.get("response_headers") or {}):
            saw_header = True
    throttled = saw_429 or saw_header
    return {
        "success": True,
        "url": url,
        "sent": count,
        "errors": errors,
        "saw_429": saw_429,
        "saw_ratelimit_header": saw_header,
        "throttled": throttled,
        # ponytail: a burst with zero 429 and no RateLimit headers is the signal;
        # the agent confirms the endpoint is sensitive (login/OTP/expensive).
        "possible_missing_rate_limit": not throttled,
        "status_sample": statuses[:20],
    }


@function_tool(timeout=180, strict_mode=False)
async def rate_limit_probe(
    ctx: RunContextWrapper,
    url: str,
    method: str = "GET",
    count: int = 30,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 10,
) -> str:
    """Send a burst of identical requests and report whether the endpoint throttles.

    Fires ``count`` requests and flags ``possible_missing_rate_limit`` when none
    return 429 and no RateLimit-*/Retry-After header appears — the vibe-code
    default on login / OTP / reset / expensive routes. Point it at a sensitive
    endpoint; only test authorized targets.

    Returns JSON with ``sent``, ``saw_429``, ``saw_ratelimit_header``,
    ``throttled``, and ``possible_missing_rate_limit``.

    Args:
        url: Full URL to hammer.
        method: HTTP method (default GET; use POST for login/OTP).
        count: Number of requests to send (default 30, max 100).
        headers: Optional request headers (e.g. a session or content type).
        body: Optional raw request body (e.g. login JSON).
        timeout: Per-request timeout in seconds (default 10).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_rate_limit_probe_impl, method, url, count, headers, body, timeout),
        ensure_ascii=False,
        default=str,
    )
