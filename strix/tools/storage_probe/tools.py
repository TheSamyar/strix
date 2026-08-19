"""Probe for exposed backup/dump files and open storage.

Vibe deploys leave the whole repo and database reachable: /.git, /.env,
backup.sql, db.sqlite, dump.json, *.bak. This requests a curated set of
sensitive paths and — crucially — baselines against a random junk path first,
so an SPA that returns index.html for everything doesn't produce false hits.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any
from urllib.parse import urljoin

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_SENSITIVE_PATHS = (
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
    "/dump.json",
    "/db.sqlite",
    "/db.sqlite3",
    "/database.sqlite",
    "/config.json",
    "/.DS_Store",
    "/.aws/credentials",
    "/id_rsa",
    "/phpinfo.php",
    "/server.js.map",
)


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def _storage_probe_impl(
    base_url: str, extra_paths: list[str] | None, timeout: int
) -> dict[str, Any]:
    if not base_url or not base_url.strip():
        return {"success": False, "error": "base_url cannot be empty"}
    # Baseline a junk path: if the app 200s a random path (SPA catch-all), only
    # responses that DIFFER from this baseline count as real exposures.
    junk = _replay_impl(
        "GET",
        urljoin(base_url, "/strix-nope-8f3a1c9e2b"),
        None,
        None,
        timeout,
        allow_redirects=False,
    )
    junk_status = junk.get("status_code") if junk.get("success") else None
    junk_digest = _digest(junk.get("body") or "") if junk.get("success") else ""

    paths = list(_SENSITIVE_PATHS) + list(extra_paths or [])
    exposed: list[dict[str, Any]] = []
    for path in paths:
        resp = _replay_impl(
            "GET", urljoin(base_url, path), None, None, timeout, allow_redirects=False
        )
        if not resp.get("success"):
            continue
        status = resp.get("status_code")
        body = resp.get("body") or ""
        is_exposed = (
            isinstance(status, int)
            and 200 <= status < 300
            and body.strip() != ""
            and not (status == junk_status and _digest(body) == junk_digest)
        )
        if is_exposed:
            exposed.append(
                {
                    "path": path,
                    "status": status,
                    "bytes": len(body),
                    "sample": body[:200],
                }
            )
    return {
        "success": True,
        "base_url": base_url,
        "paths_tested": len(paths),
        "spa_catch_all": junk_status == 200,
        "exposed_count": len(exposed),
        "possible_exposure": bool(exposed),
        "exposed": exposed,
    }


@function_tool(timeout=120, strict_mode=False)
async def storage_probe(
    ctx: RunContextWrapper,
    base_url: str,
    extra_paths: list[str] | None = None,
    timeout: int = 12,
) -> str:
    """Probe for exposed backup/dump files and repo/config leaks.

    Requests a curated set of sensitive paths (``/.git``, ``/.env``,
    ``backup.sql``, ``db.sqlite``, ``dump.json``, ``*.bak``, …). Baselines a
    random junk path first, so an SPA that returns index.html for everything
    doesn't false-positive — only differing 2xx responses count. For public
    Supabase Storage / S3 buckets, pass their listing URLs in ``extra_paths``.
    Only test authorized targets.

    Returns JSON with ``possible_exposure``, ``exposed`` (path/status/sample),
    and ``spa_catch_all``.

    Args:
        base_url: Site root (``https://app.example.com``).
        extra_paths: Extra paths/URLs to test (e.g. a Supabase Storage list URL).
        timeout: Per-request timeout in seconds (default 12).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_storage_probe_impl, base_url, extra_paths, timeout),
        ensure_ascii=False,
        default=str,
    )
