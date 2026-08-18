"""Send a raw HTTP request and return the response — stateless PoC replay."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import requests
from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_BODY_CAP_CHARS = 20_000


def _replay_impl(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
    allow_redirects: bool,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        resp = requests.request(
            method.upper(),
            url,
            headers=headers or None,
            data=body.encode("utf-8") if body is not None else None,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
    except requests.RequestException as e:
        return {
            "success": False,
            "error": f"{type(e).__name__}: {e}",
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        }
    text = resp.text
    truncated = len(text) > _BODY_CAP_CHARS
    return {
        "success": True,
        "status_code": resp.status_code,
        "response_headers": dict(resp.headers),
        "body": text[:_BODY_CAP_CHARS],
        "truncated": truncated,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
        "final_url": resp.url,
    }


@function_tool(timeout=120, strict_mode=False)
async def http_replay(
    ctx: RunContextWrapper,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 15,
    allow_redirects: bool = False,
) -> str:
    """Send a raw HTTP request and return the response verbatim.

    Use this to reproduce a proof-of-concept yourself instead of trusting a
    reported request/response. Only send requests to targets you are
    authorized to test — there are no scope guardrails; the operator owns
    scope.

    Returns JSON with ``status_code``, ``response_headers``, ``body``
    (truncated to 20k chars with a ``truncated`` flag), ``elapsed_ms``, and
    ``final_url``. On a timeout or connection error it returns
    ``{"success": false, "error": ...}`` instead of raising.

    Args:
        method: HTTP method, e.g. ``"GET"`` or ``"POST"``.
        url: Full request URL.
        headers: Optional request headers.
        body: Optional raw request body.
        timeout: Request timeout in seconds (default 15).
        allow_redirects: Follow redirects (default False).
    """
    return json.dumps(
        await asyncio.to_thread(
            _replay_impl, method, url, headers, body, timeout, allow_redirects
        ),
        ensure_ascii=False,
        default=str,
    )
