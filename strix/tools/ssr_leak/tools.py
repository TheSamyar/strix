"""Scan server-rendered state (SSR hydration) for leaked data.

Next.js/Nuxt/RSC apps embed serialized props in the HTML — __NEXT_DATA__, the
RSC flight stream (self.__next_f), window.__NUXT__, __APOLLO_STATE__. AI codegen
over-fetches and dumps whole objects there, so other users' records, emails,
internal fields, and secrets ride down in the page source. This extracts those
blobs and flags PII, secrets, and sensitive field names.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.frontend_secret_scan.tools import _scan_text
from strix.tools.http_replay.tools import _replay_impl


_NEXT_DATA_RE = re.compile(
    r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL
)
_STATE_RE = re.compile(
    r"(?:window\.__NUXT__|window\.__INITIAL_STATE__|self\.__next_f\.push|__APOLLO_STATE__)"
    r"\s*=?\s*(\{.*?\}|\[.*?\])",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_FIELD_RE = re.compile(
    r'"(password|passwd|pwd|hash|salt|token|secret|api[_-]?key|ssn|is_admin|isadmin|'
    r"role|internal|private|stripe|cvv|card|credit|dob|salary|access[_-]?token|"
    r'refresh[_-]?token|session)"\s*:',
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _scan_blob(source: str, text: str) -> dict[str, Any]:
    secrets = _scan_text(source, text)
    fields = sorted({m.lower() for m in _SENSITIVE_FIELD_RE.findall(text)})
    emails = sorted(set(_EMAIL_RE.findall(text)))[:20]
    return {
        "source": source,
        "sensitive_fields": fields,
        "emails_found": len(emails),
        "email_sample": emails[:5],
        "secrets": [{"type": s["type"], "severity": s["severity"]} for s in secrets],
        "leak": bool(fields or emails or secrets),
    }


def _ssr_leak_impl(url: str, timeout: int) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    page = _replay_impl("GET", url, None, None, timeout, allow_redirects=True)
    if not page.get("success"):
        return {"success": False, "error": page.get("error")}
    html = page.get("body") or ""

    blobs: list[tuple[str, str]] = [("__NEXT_DATA__", m) for m in _NEXT_DATA_RE.findall(html)]
    blobs.extend(("client-state", m) for m in _STATE_RE.findall(html))
    # RSC flight chunks and inline JSON props aren't always in a named var; also
    # scan the whole HTML as a fallback so nothing embedded is missed.
    blobs.append(("page-html", html))

    results = [_scan_blob(src, text) for src, text in blobs]
    leaking = [r for r in results if r["leak"]]
    return {
        "success": True,
        "url": url,
        "possible_ssr_leak": bool(leaking),
        "blobs_scanned": len(blobs),
        "results": results,
    }


@function_tool(timeout=90, strict_mode=False)
async def ssr_leak_scan(ctx: RunContextWrapper, url: str, timeout: int = 20) -> str:
    """Scan a page's server-rendered state for leaked data.

    Extracts ``__NEXT_DATA__`` / RSC flight / ``__NUXT__`` / ``__APOLLO_STATE__``
    (and the raw HTML as a fallback) and flags embedded secrets, PII (emails),
    and sensitive field names (``password``, ``token``, ``is_admin``,
    ``stripe``, …) — data the client should never receive. Only scan authorized
    targets.

    Returns JSON with ``possible_ssr_leak`` and per-blob ``sensitive_fields`` /
    ``emails_found`` / ``secrets``.

    Args:
        url: Page URL to scan (an SSR page, ideally one showing user data).
        timeout: Request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_ssr_leak_impl, url, timeout), ensure_ascii=False, default=str
    )
