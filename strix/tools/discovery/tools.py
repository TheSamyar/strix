"""Discover hidden parameters and undocumented endpoints.

The highest-value bugs live on surfaces the crawler never linked. param_discover
finds request parameters the app secretly honours (reflection or response-change
oracle); content_discover brute-forces common sensitive paths, baselining a junk
path so SPA catch-alls don't false-positive.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_CANARY = "strixp4ram9z"
_LEN_DELTA = 30
_MAX_PARAMS = 120
_MAX_PATHS = 200

_COMMON_PARAMS = (
    "id",
    "user_id",
    "userid",
    "account_id",
    "admin",
    "is_admin",
    "debug",
    "test",
    "page",
    "limit",
    "offset",
    "sort",
    "order",
    "q",
    "search",
    "filter",
    "callback",
    "redirect",
    "url",
    "file",
    "path",
    "format",
    "lang",
    "token",
    "key",
    "api_key",
    "role",
    "action",
    "cmd",
    "exec",
    "include",
    "template",
    "view",
    "next",
    "ref",
    "source",
    "mode",
    "type",
    "category",
    "status",
    "fields",
    "expand",
    "preview",
    "draft",
    "internal",
    "show_all",
    "include_deleted",
    "impersonate",
    "as_user",
)
_PARAM_MINE_RE = re.compile(r'["\'\?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']?\s*[=:]')

_COMMON_PATHS = (
    "admin",
    "administrator",
    "admin/login",
    "api",
    "api/v1",
    "api/v2",
    "graphql",
    "graphiql",
    "swagger",
    "swagger.json",
    "swagger-ui",
    "openapi.json",
    "api-docs",
    "docs",
    "debug",
    "test",
    "dev",
    "staging",
    "backup",
    "old",
    "tmp",
    "config",
    "config.json",
    ".git/HEAD",
    ".env",
    "health",
    "healthz",
    "metrics",
    "actuator",
    "actuator/health",
    "actuator/env",
    "status",
    "server-status",
    "phpinfo.php",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "console",
    "dashboard",
    "internal",
    "private",
    "users",
    "api/users",
    "api/admin",
    "wp-login.php",
    "wp-admin",
    ".DS_Store",
    "trace",
    "info",
)


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def _set_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    query[name] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _param_discover_impl(
    url: str, headers: dict[str, str] | None, wordlist: list[str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    base = _replay_impl("GET", url, headers, None, timeout, allow_redirects=False)
    if not base.get("success"):
        return {"success": False, "error": base.get("error")}
    base_body = base.get("body") or ""
    base_len = len(base_body)

    mined = {m for m in _PARAM_MINE_RE.findall(base_body) if len(m) <= 30}
    candidates = list(dict.fromkeys([*_COMMON_PARAMS, *sorted(mined), *(wordlist or [])]))[
        :_MAX_PARAMS
    ]

    found: list[dict[str, Any]] = []
    for name in candidates:
        resp = _replay_impl(
            "GET", _set_param(url, name, _CANARY), headers, None, timeout, allow_redirects=False
        )
        if not resp.get("success"):
            continue
        body = resp.get("body") or ""
        if _CANARY in body:
            found.append({"param": name, "signal": "reflected"})
        elif abs(len(body) - base_len) > _LEN_DELTA and _digest(body) != _digest(base_body):
            found.append({"param": name, "signal": "response changed"})
    return {
        "success": True,
        "url": url,
        "candidates_tested": len(candidates),
        "mined_from_page": sorted(mined)[:30],
        "hidden_params": found,
        "found_count": len(found),
    }


def _content_discover_impl(
    base_url: str, wordlist: list[str] | None, timeout: int
) -> dict[str, Any]:
    if not base_url or not base_url.strip():
        return {"success": False, "error": "base_url cannot be empty"}
    junk = _replay_impl(
        "GET", urljoin(base_url, "/strix-x8k2p-nope"), None, None, timeout, allow_redirects=False
    )
    junk_status = junk.get("status_code") if junk.get("success") else None
    junk_digest = _digest(junk.get("body") or "") if junk.get("success") else ""

    paths = list(dict.fromkeys([*_COMMON_PATHS, *(wordlist or [])]))[:_MAX_PATHS]
    found: list[dict[str, Any]] = []
    for path in paths:
        resp = _replay_impl(
            "GET",
            urljoin(base_url, "/" + path.lstrip("/")),
            None,
            None,
            timeout,
            allow_redirects=False,
        )
        if not resp.get("success"):
            continue
        status = resp.get("status_code")
        body = resp.get("body") or ""
        if not isinstance(status, int) or status == 404:
            continue
        if status == junk_status and _digest(body) == junk_digest:
            continue
        if (200 <= status < 400) or status in (401, 403):
            found.append({"path": "/" + path.lstrip("/"), "status": status, "bytes": len(body)})
    return {
        "success": True,
        "base_url": base_url,
        "paths_tested": len(paths),
        "spa_catch_all": junk_status == 200,
        "found": found,
        "found_count": len(found),
    }


@function_tool(timeout=300, strict_mode=False)
async def param_discover(
    ctx: RunContextWrapper,
    url: str,
    headers: dict[str, str] | None = None,
    wordlist: list[str] | None = None,
    timeout: int = 12,
) -> str:
    """Find hidden request parameters the app secretly honours.

    Mines param names from the page/JS, then tests a built-in list (+ your
    ``wordlist``) by sending each with a canary value: the canary reflected in
    the response, or a response that changes vs baseline, means the param is
    processed — often an undocumented, unprotected input (``debug``, ``admin``,
    ``impersonate``, ``as_user``). Only test authorized targets.

    Returns JSON with ``hidden_params`` (param + signal) and ``mined_from_page``.

    Args:
        url: The endpoint to probe for hidden params.
        headers: Request headers (e.g. a session).
        wordlist: Extra parameter names to try.
        timeout: Per-request timeout in seconds (default 12).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_param_discover_impl, url, headers, wordlist, timeout),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=300, strict_mode=False)
async def content_discover(
    ctx: RunContextWrapper,
    base_url: str,
    wordlist: list[str] | None = None,
    timeout: int = 12,
) -> str:
    """Brute-force common sensitive paths / undocumented endpoints.

    Requests a built-in list of high-value paths (``admin``, ``api``, ``graphql``,
    ``swagger.json``, ``actuator``, ``debug``, ``.git``, …) plus your
    ``wordlist``, baselining a junk path so SPA catch-alls don't false-positive.
    Reports paths that respond differently — including 401/403 (exists but
    protected). Only test authorized targets.

    Returns JSON with ``found`` (path/status/bytes) and ``spa_catch_all``.

    Args:
        base_url: Site root (``https://app.example.com``).
        wordlist: Extra paths to try.
        timeout: Per-request timeout in seconds (default 12).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_content_discover_impl, base_url, wordlist, timeout),
        ensure_ascii=False,
        default=str,
    )
