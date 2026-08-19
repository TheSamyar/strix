"""Test file / signed object URLs for weak protection and IDOR.

Vibe apps hand out object URLs that (1) still work with the signature stripped,
(2) never expire, or (3) carry a sequential ID you can increment to reach another
user's file. Each is a direct data leak.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_SIG_PARAMS = ("signature", "x-amz-signature", "sig", "token", "sp", "st", "key")
_EXPIRY_PARAMS = ("expires", "x-amz-expires", "se", "expiry", "exp", "e")
_ID_IN_PATH = re.compile(r"/(\d{1,12})(?=[/.]|$)")


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def _authorized(resp: dict[str, Any]) -> bool:
    status = resp.get("status_code")
    return isinstance(status, int) and 200 <= status < 300


def _strip_query(url: str) -> str:
    return urlunparse(urlparse(url)._replace(query=""))


def _bump_id(url: str, delta: int) -> str | None:
    parsed = urlparse(url)
    m = _ID_IN_PATH.search(parsed.path)
    if not m:
        return None
    new_val = int(m.group(1)) + delta
    if new_val < 0:
        return None
    new_path = parsed.path[: m.start(1)] + str(new_val) + parsed.path[m.end(1) :]
    return urlunparse(parsed._replace(path=new_path))


def _probe_one(url: str, timeout: int) -> dict[str, Any]:
    query = {k.lower() for k in parse_qs(urlparse(url).query)}
    base = _replay_impl("GET", url, None, None, timeout, allow_redirects=False)
    if not base.get("success"):
        return {"url": url, "error": base.get("error")}
    base_ok = _authorized(base)
    base_digest = _digest(base.get("body") or "")
    findings: list[str] = []

    has_sig = any(p in query for p in _SIG_PARAMS)
    if has_sig and base_ok:
        stripped = _replay_impl(
            "GET", _strip_query(url), None, None, timeout, allow_redirects=False
        )
        if _authorized(stripped) and _digest(stripped.get("body") or "") == base_digest:
            findings.append("signature not enforced — same content served without the signature")
    if base_ok and not any(p in query for p in _EXPIRY_PARAMS):
        findings.append("no expiry parameter — the URL likely never expires")

    for delta in (1, -1):
        neighbor = _bump_id(url, delta)
        if not neighbor:
            break
        resp = _replay_impl("GET", neighbor, None, None, timeout, allow_redirects=False)
        if _authorized(resp) and _digest(resp.get("body") or "") != base_digest:
            findings.append(f"sequential object id reachable ({neighbor}) — enumerate all files")
            break

    return {
        "url": url,
        "base_status": base.get("status_code"),
        "findings": findings,
        "possible_leak": bool(findings),
    }


def _signed_url_impl(urls: list[str], timeout: int) -> dict[str, Any]:
    if not urls:
        return {"success": False, "error": "urls cannot be empty"}
    results = [_probe_one(u, timeout) for u in urls[:20]]
    return {
        "success": True,
        "tested": len(results),
        "possible_leak": any(r.get("possible_leak") for r in results),
        "results": results,
    }


@function_tool(timeout=120, strict_mode=False)
async def signed_url_probe(ctx: RunContextWrapper, urls: list[str], timeout: int = 15) -> str:
    """Test file / signed object URLs for weak protection and IDOR.

    For each URL: fetches it, then (1) strips the signature query and checks the
    file still serves, (2) flags the absence of any expiry param, and (3)
    increments a numeric path id to reach a neighbouring object. Any hit is a
    direct file/data leak. Only test authorized targets.

    Returns JSON with per-URL ``findings`` and an overall ``possible_leak``.

    Args:
        urls: File / object / signed URLs to test (max 20).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_signed_url_impl, urls, timeout), ensure_ascii=False, default=str
    )
