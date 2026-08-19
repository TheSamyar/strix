"""Second-order / stored injection detection via a unique canary.

One-shot probes miss bugs where input is stored in one place and rendered in
another (stored XSS, second-order SQLi, cross-user injection). This plants a
unique canary — carrying an XSS payload — through one endpoint, then sweeps a
list of other endpoints for where it resurfaces: raw/unescaped = stored XSS;
anywhere at all = second-order data flow worth chasing.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


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
        sep = "&" if "?" in url else "?"
        # Value is a marker + HTML; url-encoding isn't needed for the marker match.
        return _replay_impl(
            method, f"{url}{sep}{field}={value}", headers, None, timeout, allow_redirects=False
        )
    body = {**(extra_body or {}), field: value}
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    return _replay_impl(method, url, req_headers, json.dumps(body), timeout, allow_redirects=False)


def _stored_probe_impl(
    inject_url: str,
    inject_field: str,
    sweep_urls: list[str],
    inject_method: str,
    injection_point: str,
    headers: dict[str, str] | None,
    extra_body: dict[str, Any] | None,
    timeout: int,
) -> dict[str, Any]:
    if not inject_url or not sweep_urls:
        return {"success": False, "error": "inject_url and sweep_urls are required"}
    token = secrets.token_hex(5)
    marker = f"strixSO{token}"
    # Second-order SSTI: unique factors whose product is distinctive and does NOT
    # appear in the raw expression, so seeing the product on a sink means the
    # template engine EVALUATED our stored input elsewhere (stored SSTI → RCE).
    factor_a = 1000 + int(token[:3], 16) % 9000
    factor_b = 1000 + int(token[3:6], 16) % 9000
    ssti_product = str(factor_a * factor_b)
    ssti = f"{{{{{factor_a}*{factor_b}}}}}${{{factor_a}*{factor_b}}}#{{{factor_a}*{factor_b}}}"
    xss_payload = f'<img src=x onerror="s{token}()">'
    canary_value = f"{marker} {ssti} {xss_payload}"
    point = "query" if injection_point == "query" else "body"

    planted = _inject(
        inject_method, inject_url, inject_field, canary_value, headers, extra_body, point, timeout
    )
    if not planted.get("success"):
        return {"success": False, "error": f"inject failed: {planted.get('error')}"}

    surfaced: list[dict[str, Any]] = []
    for url in sweep_urls:
        resp = _replay_impl("GET", url, headers, None, timeout, allow_redirects=False)
        if not resp.get("success"):
            continue
        body = resp.get("body") or ""
        # SSTI can evaluate the expression away, leaving the product but not the
        # marker — so check the product independently of the marker.
        stored_ssti = ssti_product in body and ssti_product not in ssti
        if marker not in body and not stored_ssti:
            continue
        raw_xss = xss_payload in body  # unescaped = the payload rendered as HTML
        if stored_ssti:
            kind = "stored/second-order SSTI (template evaluated → likely RCE)"
        elif raw_xss:
            kind = "stored XSS (unescaped)"
        else:
            kind = "second-order data flow"
        surfaced.append(
            {
                "url": url,
                "stored_xss": raw_xss,
                "stored_ssti": stored_ssti,
                "kind": kind,
            }
        )

    stored_xss = any(s["stored_xss"] for s in surfaced)
    stored_ssti_hit = any(s["stored_ssti"] for s in surfaced)
    if stored_ssti_hit:
        note = (
            f"stored input was template-evaluated on another endpoint "
            f"({factor_a}*{factor_b}={ssti_product}) — second-order SSTI, chase to RCE"
        )
    elif stored_xss:
        note = "canary rendered unescaped on another endpoint — confirm JS exec in a browser"
    elif surfaced:
        note = "canary surfaced on another endpoint (second-order flow); check every sink"
    else:
        note = "canary not seen on the swept endpoints; try more sweep_urls / an authed view"
    return {
        "success": True,
        "inject_url": inject_url,
        "canary": marker,
        "surfaced_on": surfaced,
        "possible_stored_xss": stored_xss,
        "possible_stored_ssti": stored_ssti_hit,
        "possible_second_order": bool(surfaced),
        "note": note,
    }


@function_tool(timeout=300, strict_mode=False)
async def stored_probe(
    ctx: RunContextWrapper,
    inject_url: str,
    inject_field: str,
    sweep_urls: list[str],
    inject_method: str = "POST",
    injection_point: str = "body",
    headers: dict[str, str] | None = None,
    extra_body: dict[str, Any] | None = None,
    timeout: int = 15,
) -> str:
    """Detect stored / second-order injection with a unique multi-class canary.

    Plants a unique canary through ``inject_url`` carrying an XSS payload **and**
    a multi-engine SSTI expression with unique math, then fetches each
    ``sweep_urls`` looking for where it resurfaces. Raw/unescaped payload =
    stored XSS; the SSTI math product appearing (the expression got
    template-evaluated on another endpoint) = second-order SSTI → likely RCE;
    the marker present anywhere = a second-order data flow to chase. Use the same
    session ``headers`` so authed views (dashboards, admin lists, other users'
    pages) are swept. Only test authorized targets.

    Returns JSON with ``surfaced_on`` (url + stored_xss + stored_ssti),
    ``possible_stored_xss``, ``possible_stored_ssti``, and
    ``possible_second_order``.

    Args:
        inject_url: Endpoint that stores the input (comment, profile, name, note).
        inject_field: The field/param the input goes in.
        sweep_urls: Endpoints to check afterwards for the canary (lists, admin,
            other users' views, the same object re-fetched).
        inject_method: Method for the inject request (default POST).
        injection_point: ``body`` (default) or ``query``.
        headers: Session headers, applied to inject and sweep.
        extra_body: Other required fields on the inject request.
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _stored_probe_impl,
            inject_url,
            inject_field,
            sweep_urls,
            inject_method,
            injection_point,
            headers,
            extra_body,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
