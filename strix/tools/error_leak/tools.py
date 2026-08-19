"""Trigger errors and harvest what the app leaks in them.

Vibe deploys ship debug on and default framework error pages, so a malformed
request spills stack traces, file paths, SQL, framework/version banners, internal
hostnames, and sometimes PII. This sends a set of malformations and scans the
responses for those leak signatures.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.batching import url_batch
from strix.tools.http_replay.tools import _replay_impl


_LEAK_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("stack_trace", r"Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.(?:java|kt):\d+\)"),
    ("stack_trace", r"\bline \d+, in \b|\.py\", line|System\.\w+Exception|org\.springframework"),
    ("stack_trace", r"werkzeug|Rails\.root|node_modules[\\/]|goroutine \d+ \[|panic:"),
    ("sql_error", r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3::|SQLSTATE\["),
    ("file_path", r"/(?:home|var/www|usr/local|app|srv)/[\w./-]+|[A-Za-z]:\\\\[\w\\.-]+"),
    ("framework_banner", r"X-Powered-By|Werkzeug/[\d.]+|Express|Django Version|Rails [\d.]+"),
    (
        "internal_host",
        r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    ),
    ("debug_marker", r"DEBUG = True|Whoops!|debug mode|__debug__|Application Trace|Full Trace"),
)
_COMPILED = tuple((label, re.compile(pat)) for label, pat in _LEAK_SIGNATURES)

# (name, how) — how in query|body|rawbody.
_MALFORMATIONS: tuple[tuple[str, str, Any], ...] = (
    ("huge_int", "query", "99999999999999999999999"),
    ("negative_id", "query", "-1"),
    ("quote", "query", "'"),
    ("type_string", "query", "notanumber"),
    ("array_bracket", "query", "[]"),
    ("null_byte", "query", "a%00b"),
    ("broken_json", "rawbody", "{ not : valid json,,, "),
    ("array_body", "body", []),
    ("object_body", "body", {"nested": {"a": [1, 2, 3]}}),
)


def _set_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    query[name] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _scan(body: str, base_body: str) -> list[str]:
    hits: list[str] = []
    for label, rx in _COMPILED:
        if rx.search(body) and not rx.search(base_body):
            hits.append(label)
    return sorted(set(hits))


def _error_leak_impl(
    method: str,
    url: str,
    param: str,
    headers: dict[str, str] | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    base = _replay_impl(method, url, headers, None, timeout, allow_redirects=False)
    base_body = base.get("body") or "" if base.get("success") else ""

    findings: list[dict[str, Any]] = []
    for name, how, value in _MALFORMATIONS:
        if how == "query":
            resp = _replay_impl(
                method,
                _set_query(url, param, str(value)),
                headers,
                None,
                timeout,
                allow_redirects=False,
            )
        elif how == "rawbody":
            resp = _replay_impl(method, url, headers, str(value), timeout, allow_redirects=False)
        else:  # body
            req_headers = {"Content-Type": "application/json", **(headers or {})}
            resp = _replay_impl(
                method, url, req_headers, json.dumps({param: value}), timeout, allow_redirects=False
            )
        if not resp.get("success"):
            continue
        leaks = _scan(resp.get("body") or "", base_body)
        if leaks:
            findings.append(
                {
                    "malformation": name,
                    "status": resp.get("status_code"),
                    "leaked": leaks,
                    "sample": (resp.get("body") or "")[:300],
                }
            )
    return {
        "success": True,
        "url": url,
        "possible_error_leak": bool(findings),
        "findings": findings,
    }


def _error_leak_run(
    method: str,
    url: str,
    param: str,
    headers: dict[str, str] | None,
    timeout: int,
    urls: list[str] | None = None,
) -> dict[str, Any]:
    if urls:

        def _one(u: str, t: int) -> dict[str, Any]:
            return _error_leak_impl(method, u, param, headers, t)

        return url_batch(_one, urls, timeout)
    return _error_leak_impl(method, url, param, headers, timeout)


@function_tool(timeout=120, strict_mode=False)
async def error_leak_probe(
    ctx: RunContextWrapper,
    url: str = "",
    param: str = "id",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 15,
    urls: list[str] | None = None,
) -> str:
    """Trigger error conditions and flag what the app leaks in the response.

    Sends malformed inputs (huge/negative ints, a bare quote, wrong types, array/
    object bodies, broken JSON, null bytes) and scans the responses for stack
    traces, SQL errors, filesystem paths, framework/version banners, internal
    IPs, and debug markers not present in the baseline. Only test authorized
    targets.

    Returns JSON with ``possible_error_leak`` and per-malformation ``leaked``
    categories + a sample. In batch mode returns ``results`` — one such object
    per URL (each with its ``url``) — plus ``count``.

    Args:
        url: The endpoint to stress (single-URL mode).
        param: The parameter/field to malform (default ``id``).
        method: HTTP method (default GET).
        headers: Request headers (e.g. a session).
        timeout: Per-request timeout in seconds (default 15).
        urls: Optional list of endpoints to stress in one call (max 25) — same
            per-URL scan, one call instead of one per endpoint. Overrides ``url``.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_error_leak_run, method, url, param, headers, timeout, urls),
        ensure_ascii=False,
        default=str,
    )
