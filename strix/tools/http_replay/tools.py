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
_VARIANT_BODY_CAP_CHARS = 4_000
_MAX_VARIANTS = 50


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


def _summarize_variant(
    label: str,
    req: dict[str, Any],
    resp: dict[str, Any],
    baseline: dict[str, Any],
) -> dict[str, Any]:
    """Compact per-variant result: enough signal to spot the interesting one."""
    out: dict[str, Any] = {
        "label": label,
        "request": {"method": req["method"], "url": req["url"]},
    }
    if not resp.get("success"):
        out["error"] = resp.get("error")
        out["elapsed_ms"] = resp.get("elapsed_ms")
        return out
    body = resp.get("body", "")
    base_len = len(baseline.get("body", "")) if baseline.get("success") else 0
    out.update(
        {
            "status_code": resp["status_code"],
            "elapsed_ms": resp["elapsed_ms"],
            "body_len": len(body),
            "len_delta": len(body) - base_len,
            "status_changed": (
                baseline.get("success") and resp["status_code"] != baseline["status_code"]
            ),
            "body": body[:_VARIANT_BODY_CAP_CHARS],
            "truncated": len(body) > _VARIANT_BODY_CAP_CHARS,
        }
    )
    return out


def _batch_impl(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
    allow_redirects: bool,
    variants: list[dict[str, Any]],
) -> dict[str, Any]:
    """Send the base request as baseline, then each variant, and diff each."""
    dropped = max(0, len(variants) - _MAX_VARIANTS)
    variants = variants[:_MAX_VARIANTS]

    def build(v: dict[str, Any]) -> dict[str, Any]:
        merged_headers = {**(headers or {}), **(v.get("headers") or {})} or None
        return {
            "method": str(v.get("method", method)),
            "url": str(v.get("url", url)),
            "headers": merged_headers,
            "body": v.get("body", body),
            "allow_redirects": bool(v.get("allow_redirects", allow_redirects)),
        }

    baseline = _replay_impl(method, url, headers, body, timeout, allow_redirects)
    summaries: list[dict[str, Any]] = []
    for i, v in enumerate(variants):
        req = build(v)
        resp = _replay_impl(
            req["method"], req["url"], req["headers"], req["body"],
            timeout, req["allow_redirects"],
        )
        label = str(v.get("label", f"variant-{i}"))
        summaries.append(_summarize_variant(label, req, resp, baseline))

    result: dict[str, Any] = {
        "success": True,
        "baseline": baseline,
        "variants": summaries,
        "count": len(summaries),
    }
    if dropped:
        result["dropped"] = dropped
        result["note"] = f"{dropped} variant(s) over the {_MAX_VARIANTS} cap were not sent"
    return result


@function_tool(timeout=120, strict_mode=False)
async def http_replay(
    ctx: RunContextWrapper,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 15,
    allow_redirects: bool = False,
    variants: list[dict[str, Any]] | None = None,
) -> str:
    """Send a raw HTTP request (or a batch of them) and return the response(s).

    Use this to reproduce a proof-of-concept yourself instead of trusting a
    reported request/response. Only send requests to targets you are
    authorized to test — there are no scope guardrails; the operator owns
    scope.

    Single request (``variants`` omitted): returns JSON with ``status_code``,
    ``response_headers``, ``body`` (truncated to 20k chars with a ``truncated``
    flag), ``elapsed_ms``, and ``final_url``. On a timeout or connection error
    it returns ``{"success": false, "error": ...}`` instead of raising.

    Batch mode (``variants`` given): send the base request once as the
    baseline, then every variant, and get them all back in ONE call — each
    diffed against the baseline (``status_changed``, ``len_delta``). Use this
    to collapse a sweep into a single tool call instead of one replay per
    case: IDOR across object IDs, auth checks across tokens/cookies, method
    tampering, or verifying a PoC across payload variations. The interesting
    variant is the one whose status or length diverges from the baseline;
    re-run it alone for the full 20k body if you need more than the 4k
    per-variant slice. Up to 50 variants per call.

    Args:
        method: HTTP method, e.g. ``"GET"`` or ``"POST"``.
        url: Full request URL.
        headers: Optional request headers.
        body: Optional raw request body.
        timeout: Request timeout in seconds (default 15).
        allow_redirects: Follow redirects (default False).
        variants: Optional list of request overrides to batch. Each item is a
            dict that may set ``label``, ``method``, ``url``, ``headers``
            (merged onto the base headers, per-key), ``body``, and
            ``allow_redirects``; anything omitted inherits from the base
            request. Example: ``[{"label": "id=2", "url": ".../api/users/2"},
            {"label": "id=3", "url": ".../api/users/3"}]``.
    """
    if variants:
        return json.dumps(
            await asyncio.to_thread(
                _batch_impl, method, url, headers, body, timeout, allow_redirects, variants
            ),
            ensure_ascii=False,
            default=str,
        )
    return json.dumps(
        await asyncio.to_thread(
            _replay_impl, method, url, headers, body, timeout, allow_redirects
        ),
        ensure_ascii=False,
        default=str,
    )
