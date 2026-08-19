"""Check private responses for cacheability and tokens leaking in URLs.

Two quiet vibe-code data leaks: (1) an authenticated, per-user response marked
``Cache-Control: public`` (or cacheable with no ``no-store``/``private``) gets
stored by a shared CDN and served to other users; (2) session tokens / API keys
carried in the URL query string leak via referer headers, proxy logs, and
browser history.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_TOKEN_PARAMS = (
    "token",
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "key",
    "sig",
    "signature",
    "jwt",
)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.")


def _header(headers: dict[str, str], name: str) -> str:
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return ""


def _token_in_url(url: str) -> list[str]:
    hits: list[str] = []
    query = parse_qs(urlparse(url).query)
    for name, values in query.items():
        if name.lower() in _TOKEN_PARAMS or any(_JWT_RE.search(v) for v in values):
            hits.append(name)
    return sorted(set(hits))


def _cacheable_private(cache_control: str) -> bool:
    cc = cache_control.lower()
    if not cc:
        return False  # absent header is ambiguous; don't flag
    if "no-store" in cc or "private" in cc or "no-cache" in cc:
        return False
    return "public" in cc or "max-age" in cc or "s-maxage" in cc


def _cache_privacy_impl(
    url: str, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    token_params = _token_in_url(url)

    resp = _replay_impl("GET", url, headers, None, timeout, allow_redirects=False)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error")}
    resp_headers = resp.get("response_headers") or {}
    cache_control = _header(resp_headers, "Cache-Control")
    cacheable = _cacheable_private(cache_control)
    sets_cookie = bool(_header(resp_headers, "Set-Cookie"))
    authed = bool(headers)

    findings: list[str] = []
    if authed and cacheable:
        findings.append(f"authenticated response is cacheable (Cache-Control: {cache_control!r})")
    if cacheable and sets_cookie:
        findings.append("cacheable response also sets a cookie — a shared cache leaks sessions")
    if token_params:
        findings.append(
            f"token/secret in URL query: {', '.join(token_params)} (leaks via referer/logs)"
        )

    return {
        "success": True,
        "url": url,
        "cache_control": cache_control,
        "token_params_in_url": token_params,
        "authenticated_response_cacheable": bool(authed and cacheable),
        "possible_privacy_leak": bool(findings),
        "findings": findings,
    }


@function_tool(timeout=60, strict_mode=False)
async def cache_privacy_probe(
    ctx: RunContextWrapper,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> str:
    """Check a private URL for cacheability and tokens leaking in the URL.

    Flags (1) an authenticated response marked cacheable (``Cache-Control:
    public`` / ``max-age`` without ``no-store``/``private``) — a shared CDN would
    serve one user's data to another; and (2) session tokens / API keys in the
    URL query string, which leak via referer, proxy logs, and history. Pass the
    session ``headers`` so the cacheability check reflects the authed response.
    Only test authorized targets.

    Returns JSON with ``authenticated_response_cacheable``,
    ``token_params_in_url``, and ``possible_privacy_leak``.

    Args:
        url: The private/authenticated URL to check.
        headers: Session headers (Cookie/Authorization).
        timeout: Request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_cache_privacy_impl, url, headers, timeout),
        ensure_ascii=False,
        default=str,
    )
