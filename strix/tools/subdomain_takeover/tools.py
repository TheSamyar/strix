"""Fingerprint dangling subdomains for takeover.

A subdomain whose CNAME points at a cloud service that no longer hosts anything
(deleted S3 bucket, unclaimed Heroku/Vercel/GitHub-Pages app) can be claimed by
an attacker, who then serves content on your domain — cookie theft, OAuth
redirect abuse, phishing. This matches the tell-tale "unclaimed" error page each
provider returns.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


# service -> substrings that appear when the backing resource is unclaimed.
_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "aws_s3": ("NoSuchBucket", "The specified bucket does not exist"),
    "github_pages": (
        "There isn't a GitHub Pages site here",
        "For root URLs (like http://example.com/) you must provide an index.html file",
    ),
    "heroku": ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
    "vercel": ("DEPLOYMENT_NOT_FOUND", "The deployment could not be found"),
    "netlify": ("Not Found - Request ID", "Not found &middot; GitHub Pages"),
    "shopify": ("Sorry, this shop is currently unavailable",),
    "fastly": ("Fastly error: unknown domain",),
    "zendesk": ("Help Center Closed",),
    "bitbucket": ("Repository not found",),
    "surge": ("project not found",),
    "pantheon": ("The gods are wise, but do not know of the site which you seek",),
    "readthedocs": ("The requested resource could not be found",),
    "cargo": ("<title>404 &mdash; File not found</title>",),
    "tumblr": ("Whatever you were looking for doesn't currently exist at this address",),
    "wordpress": ("Do you want to register",),
    "azure": ("404 Web Site not found",),
}


def _match(body: str) -> tuple[str, str] | None:
    for service, needles in _FINGERPRINTS.items():
        for needle in needles:
            if needle in body:
                return service, needle
    return None


def _normalize(host: str) -> str:
    host = host.strip()
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host}"


def _subdomain_takeover_impl(hosts: list[str], timeout: int) -> dict[str, Any]:
    if not hosts:
        return {"success": False, "error": "hosts cannot be empty"}
    results: list[dict[str, Any]] = []
    for host in hosts[:50]:
        url = _normalize(host)
        resp = _replay_impl("GET", url, None, None, timeout, allow_redirects=True)
        if not resp.get("success"):
            results.append({"host": host, "error": resp.get("error")})
            continue
        hit = _match(resp.get("body") or "")
        results.append(
            {
                "host": host,
                "status": resp.get("status_code"),
                "vulnerable": hit is not None,
                "service": hit[0] if hit else None,
                "signature": hit[1] if hit else None,
            }
        )
    vulnerable = [r for r in results if r.get("vulnerable")]
    return {
        "success": True,
        "tested": len(results),
        "possible_takeover": bool(vulnerable),
        "vulnerable": vulnerable,
        "results": results,
    }


@function_tool(timeout=180, strict_mode=False)
async def subdomain_takeover(ctx: RunContextWrapper, hosts: list[str], timeout: int = 15) -> str:
    """Fingerprint dangling subdomains for takeover.

    Fetches each host and matches the unclaimed-resource error page of common
    providers (S3, GitHub Pages, Heroku, Vercel, Netlify, Shopify, Fastly,
    Azure, …). A match means the CNAME points at a service you can register and
    serve content on — full control of that subdomain. Feed subdomains from
    ``subfinder``/recon. Only test authorized targets.

    Returns JSON with ``vulnerable`` (host + service + signature) and
    ``possible_takeover``.

    Args:
        hosts: Subdomains or URLs to check (max 50).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_subdomain_takeover_impl, hosts, timeout),
        ensure_ascii=False,
        default=str,
    )
