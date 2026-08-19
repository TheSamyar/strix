"""Fire N identical requests concurrently to trigger race conditions (TOCTOU).

Single-use actions — redeem a coupon, withdraw funds, accept an invite, consume
a one-time token — often check-then-act without a lock. Hammering the endpoint
in parallel can slip several through the gap: double-spend, coupon reuse,
credit-limit bypass. The tell is more successful outcomes than the operation
should allow.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_MAX_REQUESTS = 50
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


async def _race_probe_impl(
    method: str,
    url: str,
    count: int,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    count = max(2, min(count, _MAX_REQUESTS))
    method = (method or "POST").upper()

    # Fire all requests concurrently so they contend on the same critical section.
    responses = await asyncio.gather(
        *(
            asyncio.to_thread(
                _replay_impl, method, url, headers, body, timeout, allow_redirects=False
            )
            for _ in range(count)
        )
    )

    statuses: list[int] = []
    success_digests: list[str] = []
    errors = 0
    for resp in responses:
        if not resp.get("success"):
            errors += 1
            continue
        status = resp.get("status_code")
        if isinstance(status, int):
            statuses.append(status)
            if 200 <= status < 300:
                success_digests.append(_digest(resp.get("body") or ""))

    success_count = len(success_digests)
    # A write action that "succeeds" more than once under contention is the
    # race signal; GETs are usually idempotent, so don't flag those.
    possible_race = method in _WRITE_METHODS and success_count > 1
    return {
        "success": True,
        "url": url,
        "method": method,
        "sent": count,
        "errors": errors,
        "success_count": success_count,
        "unique_success_bodies": len(set(success_digests)),
        "status_distribution": dict(Counter(statuses)),
        "possible_race": possible_race,
        "note": (
            "multiple concurrent successes on a state-changing request — confirm "
            "the action should be single-use (double-spend/reuse)"
            if possible_race
            else "no multi-success signal (GETs are expected to all succeed)"
        ),
    }


@function_tool(timeout=180, strict_mode=False)
async def race_probe(
    ctx: RunContextWrapper,
    url: str,
    method: str = "POST",
    count: int = 20,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 15,
) -> str:
    """Fire N identical requests at once to detect a race condition (TOCTOU).

    Sends ``count`` concurrent copies of the request so they contend on the same
    check-then-act path. For a state-changing action (POST/PUT/PATCH/DELETE),
    more than one 2xx = ``possible_race`` — the action likely lacks a lock
    (double-spend, coupon reuse, limit bypass). Confirm the action is meant to be
    single-use. Only test authorized targets.

    Returns JSON with ``success_count``, ``unique_success_bodies``,
    ``status_distribution``, and ``possible_race``.

    Args:
        url: The endpoint to hammer (a single-use action).
        method: HTTP method (default POST).
        count: Concurrent requests to fire (default 20, max 50).
        headers: Request headers (e.g. the auth needed to perform the action).
        body: Raw request body (e.g. the redeem/withdraw payload).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await _race_probe_impl(method, url, count, headers, body, timeout),
        ensure_ascii=False,
        default=str,
    )
