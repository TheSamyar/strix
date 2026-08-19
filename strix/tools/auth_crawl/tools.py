"""Authenticated deep crawl — discover the endpoints behind the login.

walk_unauth only sees the public surface, but most real bugs live behind auth.
Given a session (cookie/bearer), this BFS-crawls in scope, pulling links, form
actions, and API paths embedded in JS (fetch/axios/url literals), and returns a
deduped endpoint list ready for endpoint_risk_rank and injection_fuzz.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_MAX_PAGES = 40
_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_JS_URL_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?)\(\s*["'`]([^"'`]+)["'`]|["'`](/api/[^"'`\s?]+)""",
    re.IGNORECASE,
)
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".ico", ".map")


def _extract(base: str, body: str) -> tuple[set[str], set[str]]:
    """Return (page_links, endpoints) — both absolute, keyed off base."""
    pages: set[str] = set()
    endpoints: set[str] = set()
    for match in _LINK_RE.findall(body):
        url = urljoin(base, match)
        endpoints.add(url)
        if not url.lower().split("?")[0].endswith(_STATIC_EXT):
            pages.add(url)
    for grp in _JS_URL_RE.findall(body):
        raw = grp[0] or grp[1]
        if raw:
            endpoints.add(urljoin(base, raw))
    return pages, endpoints


def _crawl(
    seed: str, headers: dict[str, str] | None, max_pages: int, timeout: int
) -> dict[str, Any]:
    host = urlparse(seed).netloc
    queue: deque[str] = deque([seed])
    seen_pages: set[str] = set()
    endpoints: set[str] = set()
    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        page = queue.popleft()
        if page in seen_pages:
            continue
        seen_pages.add(page)
        resp = _replay_impl("GET", page, headers, None, timeout, allow_redirects=True)
        if not resp.get("success"):
            continue
        pages_crawled += 1
        body = resp.get("body") or ""
        new_pages, new_endpoints = _extract(resp.get("final_url") or page, body)
        endpoints |= new_endpoints
        for link in new_pages:
            if urlparse(link).netloc == host and link not in seen_pages:
                queue.append(link)
    # In-scope endpoints only.
    scoped = sorted(e for e in endpoints if urlparse(e).netloc == host)
    return {
        "success": True,
        "seed": seed,
        "pages_crawled": pages_crawled,
        "endpoint_count": len(scoped),
        "endpoints": scoped,
        "truncated": bool(queue),
    }


@function_tool(timeout=300, strict_mode=False)
async def auth_crawl(
    ctx: RunContextWrapper,
    seed_url: str,
    headers: dict[str, str] | None = None,
    max_pages: int = 40,
    timeout: int = 15,
) -> str:
    """Crawl a site behind authentication and return in-scope endpoints.

    BFS from ``seed_url`` using the supplied session ``headers`` (Cookie/Bearer),
    pulling links, form actions, and API paths embedded in JS. Stays on the seed
    host. Feed the returned ``endpoints`` to ``endpoint_risk_rank`` then
    ``injection_fuzz`` / ``authz_probe``. Only crawl authorized targets.

    Returns JSON with ``pages_crawled``, ``endpoint_count``, ``endpoints``, and
    ``truncated`` (true if the page cap was hit).

    Args:
        seed_url: Where to start (a logged-in page).
        headers: Session headers to send on every request (Cookie/Authorization).
        max_pages: Page cap (default 40, hard-capped at 40).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    capped = max(1, min(max_pages, _MAX_PAGES))
    return json.dumps(
        await asyncio.to_thread(_crawl, seed_url, headers, capped, timeout),
        ensure_ascii=False,
        default=str,
    )
