"""Detect resource-exhaustion / downtime risk with single amplified requests.

This flags DoS risk WITHOUT flooding: one crafted request per class — a huge
pagination limit, a deeply nested JSON body, an oversized value, and a ReDoS
pattern — each measured against a baseline. A response that is far slower, times
out, or 500s under one cheap request is an availability risk (the endpoint scales
work with attacker-controlled input).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_AMPLIFY = 5.0  # slower-than-baseline factor that counts as amplification
_FLOOR_MS = 2000  # ...but at least this much slower, to ignore jitter


def _set_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    query[name] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _nested_json(depth: int) -> str:
    obj: Any = "x"
    for _ in range(depth):
        obj = {"a": obj}
    return json.dumps(obj)


def _dos_probe_impl(
    method: str,
    url: str,
    param: str,
    headers: dict[str, str] | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    base = _replay_impl(method, url, headers, None, timeout, allow_redirects=False)
    base_ms = base.get("elapsed_ms") or 0 if base.get("success") else 0

    # (name, how, value). how: query | rawbody.
    redos = "a" * 40000 + "!"
    tests: tuple[tuple[str, str, str], ...] = (
        ("huge_pagination", "query", "99999999"),
        ("oversized_value", "query", "A" * 100000),
        ("redos_input", "query", redos),
        ("deep_json_body", "rawbody", _nested_json(200)),
        ("huge_json_array", "rawbody", "[" + ",".join(["0"] * 100000) + "]"),
    )

    findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for name, how, value in tests:
        if how == "query":
            resp = _replay_impl(
                method, _set_query(url, param, value), headers, None, timeout, allow_redirects=False
            )
        else:
            req_headers = {"Content-Type": "application/json", **(headers or {})}
            resp = _replay_impl(method, url, req_headers, value, timeout, allow_redirects=False)
        elapsed = resp.get("elapsed_ms") or 0
        timed_out = bool(resp.get("timed_out"))
        status = resp.get("status_code")
        amplified = timed_out or (
            elapsed >= max(_FLOOR_MS, base_ms * _AMPLIFY)
            or (isinstance(status, int) and status >= 500)
        )
        entry = {
            "test": name,
            "elapsed_ms": round(elapsed) if isinstance(elapsed, (int, float)) else None,
            "status": status,
            "timed_out": timed_out,
            "amplified": bool(amplified),
        }
        results.append(entry)
        if amplified:
            findings.append(entry)

    return {
        "success": True,
        "url": url,
        "baseline_ms": round(base_ms) if isinstance(base_ms, (int, float)) else None,
        "possible_dos": bool(findings),
        "amplified_tests": [f["test"] for f in findings],
        "results": results,
    }


@function_tool(timeout=300, strict_mode=False)
async def dos_probe(
    ctx: RunContextWrapper,
    url: str,
    param: str = "limit",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> str:
    """Flag resource-exhaustion / downtime risk with single amplified requests.

    Sends one crafted request per class — huge pagination value, oversized value,
    a ReDoS pattern, a deeply nested JSON body, and a huge JSON array — and flags
    any that is far slower than baseline, times out, or 500s. This detects the
    RISK (input-scaled work) without flooding the target. Only test authorized
    targets.

    Returns JSON with ``amplified_tests``, per-test ``elapsed_ms``/``status``, and
    ``possible_dos``.

    Args:
        url: The endpoint to test.
        param: The query parameter to amplify (default ``limit``).
        method: HTTP method (default GET).
        headers: Request headers (e.g. a session).
        timeout: Per-request timeout in seconds — the hang ceiling (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_dos_probe_impl, method, url, param, headers, timeout),
        ensure_ascii=False,
        default=str,
    )
