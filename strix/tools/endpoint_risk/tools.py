"""Rank discovered endpoints by attack surface so testing goes worst-first.

Top-down endpoint testing wastes budget on static/low-value routes. This scores
each endpoint by the signals that predict real bugs — ID params (IDOR), write
methods, auth/admin paths, URL/file params (SSRF/traversal), money/PII nouns —
so the agent hits the dangerous ones first.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urlparse

from agents import RunContextWrapper, function_tool


_WRITE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
_ID_RE = re.compile(r"/\d+(?:/|$)|/[0-9a-f]{8}-[0-9a-f]{4}-|\{[^}]*id[^}]*\}|:id\b", re.IGNORECASE)
_ID_PARAM_RE = re.compile(r"\b(?:id|uid|uuid|user_?id|account_?id|order_?id|pid)\b", re.IGNORECASE)
_SSRF_PARAM_RE = re.compile(
    r"\b(?:url|uri|file|path|redirect|next|callback|webhook|feed|dest|image)\b", re.IGNORECASE
)
_AUTH_PATH_RE = re.compile(
    r"/(?:admin|login|logout|register|account|settings|password|reset|token|oauth|auth)\b",
    re.IGNORECASE,
)
_SENSITIVE_RE = re.compile(
    r"\b(?:payment|invoice|order|export|download|card|ssn|billing|user|profile|secret|key)\b",
    re.IGNORECASE,
)
_UPLOAD_RE = re.compile(r"\b(?:upload|file|attachment|import|avatar)\b", re.IGNORECASE)
_SEARCH_RE = re.compile(r"\b(?:search|query|filter|q|sort|order_?by)\b", re.IGNORECASE)


def _score_endpoint(method: str, url_or_path: str, params: list[str]) -> dict[str, Any]:
    method = (method or "GET").upper()
    parsed = urlparse(url_or_path)
    path = parsed.path or url_or_path
    query = parsed.query
    haystack = f"{path}?{query} {' '.join(params)}"

    score = 0
    reasons: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(reason)

    if _ID_RE.search(path) or _ID_PARAM_RE.search(haystack):
        add(3, "takes an object id (IDOR/BOLA)")
    if method in _WRITE_METHODS:
        add(2, f"write method {method} (state change / mass assignment)")
    if _AUTH_PATH_RE.search(path):
        add(3, "auth/admin surface")
    if _SSRF_PARAM_RE.search(haystack):
        add(3, "URL/file param (SSRF / path traversal)")
    if _UPLOAD_RE.search(haystack):
        add(2, "file upload (upload bypass / traversal)")
    if _SENSITIVE_RE.search(haystack):
        add(2, "money/PII noun (high-impact data)")
    if _SEARCH_RE.search(haystack):
        add(1, "search/query param (injection)")

    return {
        "endpoint": url_or_path,
        "method": method,
        "score": score,
        "reasons": reasons or ["no strong signal"],
    }


def _normalize(item: Any) -> tuple[str, str, list[str]]:
    if isinstance(item, dict):
        method = str(item.get("method") or "GET")
        url = str(item.get("url") or item.get("path") or item.get("endpoint") or "")
        raw_params = item.get("params")
        params = [str(p) for p in raw_params] if isinstance(raw_params, list) else []
        return method, url, params
    return "GET", str(item), []


def _endpoint_risk_rank_impl(endpoints: list[Any]) -> dict[str, Any]:
    if not endpoints:
        return {"success": False, "error": "endpoints cannot be empty"}
    scored = [_score_endpoint(*_normalize(item)) for item in endpoints]
    scored.sort(key=lambda r: r["score"], reverse=True)
    return {
        "success": True,
        "count": len(scored),
        "ranked": scored,
        "top": scored[0]["endpoint"] if scored else None,
    }


@function_tool(timeout=30, strict_mode=False)
async def endpoint_risk_rank(ctx: RunContextWrapper, endpoints: list[Any]) -> str:
    """Rank endpoints by attack surface so the agent tests the riskiest first.

    Scores each endpoint on the signals that predict bugs — object-id params
    (IDOR), write methods, auth/admin paths, URL/file params (SSRF/traversal),
    upload, money/PII nouns, search params (injection) — and returns them sorted
    worst-first with the reasons. Feed it the endpoints from ``list_attack_surface``
    or your crawl.

    Returns JSON with ``ranked`` (endpoint/method/score/reasons) and the ``top``
    endpoint.

    Args:
        endpoints: List of endpoints — plain path/URL strings, or objects like
            ``{"method", "url"|"path", "params": [...]}``.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_endpoint_risk_rank_impl, endpoints),
        ensure_ascii=False,
        default=str,
    )
