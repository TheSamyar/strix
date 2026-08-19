"""Recover original source from exposed .map files and mine it.

Production builds that ship source maps hand an attacker the original,
un-minified source — internal API routes, comments, and often hardcoded secrets.
This fetches a page's bundles, follows their sourceMappingURL / <bundle>.map,
reconstructs sourcesContent, and scans it for secrets and internal routes.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urljoin

from agents import RunContextWrapper, function_tool

from strix.tools.frontend_secret_scan.tools import _scan_text
from strix.tools.http_replay.tools import _replay_impl


_MAX_BUNDLES = 15
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_MAP_URL_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_ROUTE_RE = re.compile(r"""["'`](/(?:api|v\d|internal|admin|graphql)/[\w./{}:-]{1,60})["'`]""")


def _fetch_map_urls(bundle_url: str, bundle_body: str) -> list[str]:
    urls = [
        urljoin(bundle_url, m)
        for m in _MAP_URL_RE.findall(bundle_body)
        if not m.startswith("data:")
    ]
    urls.append(bundle_url + ".map")  # convention fallback
    return list(dict.fromkeys(urls))


def _mine(source_url: str, content: str) -> dict[str, Any]:
    secrets = _scan_text(source_url, content)
    routes = sorted(set(_ROUTE_RE.findall(content)))[:40]
    return {
        "secrets": [
            {"type": s["type"], "severity": s["severity"], "value": s["value"]} for s in secrets
        ],
        "internal_routes": routes,
    }


def _sourcemap_impl(url: str, timeout: int) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    page = _replay_impl("GET", url, None, None, timeout, allow_redirects=True)
    if not page.get("success"):
        return {"success": False, "error": page.get("error")}
    final_url = page.get("final_url") or url
    body = page.get("body") or ""

    # A .map passed directly, or bundles referenced by the page.
    bundle_urls = (
        [final_url]
        if final_url.endswith(".map")
        else [urljoin(final_url, s) for s in _SCRIPT_SRC_RE.findall(body)][:_MAX_BUNDLES]
    )

    recovered: list[dict[str, Any]] = []
    all_secrets: list[dict[str, Any]] = []
    all_routes: set[str] = set()
    for bundle in bundle_urls:
        if bundle.endswith(".map"):
            map_urls = [bundle]
        else:
            resp = _replay_impl("GET", bundle, None, None, timeout, allow_redirects=True)
            map_urls = (
                _fetch_map_urls(bundle, resp.get("body") or "") if resp.get("success") else []
            )
        for map_url in map_urls:
            mresp = _replay_impl("GET", map_url, None, None, timeout, allow_redirects=True)
            if not mresp.get("success"):
                continue
            try:
                parsed = json.loads(mresp.get("body") or "")
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(parsed, dict) or "sources" not in parsed:
                continue
            contents = parsed.get("sourcesContent") or []
            joined = "\n".join(c for c in contents if isinstance(c, str))
            mined = _mine(map_url, joined) if joined else {"secrets": [], "internal_routes": []}
            all_secrets.extend(mined["secrets"])
            all_routes.update(mined["internal_routes"])
            recovered.append(
                {
                    "map_url": map_url,
                    "source_files": len(parsed.get("sources") or []),
                    "has_content": bool(joined),
                    "secrets_found": len(mined["secrets"]),
                }
            )
            break  # one working map per bundle is enough
    return {
        "success": True,
        "url": url,
        "sourcemaps_recovered": len(recovered),
        "recovered": recovered,
        "secrets": all_secrets,
        "internal_routes": sorted(all_routes)[:60],
        "possible_source_exposure": bool(recovered),
    }


@function_tool(timeout=180, strict_mode=False)
async def sourcemap_recover(ctx: RunContextWrapper, url: str, timeout: int = 20) -> str:
    """Recover original source from exposed .map files and mine it.

    Fetches the page's JS bundles, follows their ``sourceMappingURL`` /
    ``<bundle>.map``, reconstructs ``sourcesContent``, and scans it for secrets
    and internal API routes. A recovered map is itself a finding (source-code
    disclosure) and often carries hardcoded keys the minified bundle hid. Pass a
    ``.map`` URL directly to just mine it. Only test authorized targets.

    Returns JSON with ``recovered`` (map/source-file count), ``secrets``,
    ``internal_routes``, and ``possible_source_exposure``.

    Args:
        url: A page URL (bundles are followed) or a ``.map`` URL directly.
        timeout: Per-request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_sourcemap_impl, url, timeout), ensure_ascii=False, default=str
    )
