"""Fingerprint a target's stack so testing can be tailored to it.

Blind, top-down testing wastes budget. This reads the page, its JS bundles, and
a couple of well-known paths, then infers framework / BaaS / API style / auth /
CDN-WAF / cloud / CMS. It also extracts the Supabase URL + anon key when present
so ``backend_rules_probe`` can run immediately. Feed the result to ``plan_tests``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Any
from urllib.parse import urljoin

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_MAX_BUNDLES = 10
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]{16,}\.supabase\.co")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")

# category -> label -> list of ("header"|"body", needle). Header needles match
# "name: value" case-insensitively; body needles match page + bundle text.
_SIGNATURES: dict[str, dict[str, tuple[tuple[str, str], ...]]] = {
    "framework": {
        "nextjs": (
            ("header", "x-powered-by: next"),
            ("body", "__NEXT_DATA__"),
            ("body", "/_next/"),
        ),
        "nuxt": (("body", "__NUXT__"), ("body", "/_nuxt/")),
        "django": (("body", "csrfmiddlewaretoken"), ("body", "Django administration")),
        "rails": (("header", "x-runtime"), ("body", "csrf-param")),
        "laravel": (("header", "set-cookie: laravel_session"), ("body", "XSRF-TOKEN")),
        "express": (("header", "x-powered-by: express"),),
        "fastapi": (("header", "server: uvicorn"), ("body", '"openapi"')),
        "flask": (("header", "server: werkzeug"),),
        "aspnet": (("header", "x-aspnet-version"), ("header", "x-powered-by: asp.net")),
        "spring": (("header", "x-application-context"),),
    },
    "baas": {
        "supabase": (("body", ".supabase.co"), ("body", "supabase")),
        "firebase": (("body", "firebaseio.com"), ("body", "firebaseapp.com"), ("body", "AIzaSy")),
        "amplify": (("body", "aws-amplify"), ("body", "amazonaws.com/graphql")),
    },
    "api": {
        "graphql": (("body", "/graphql"), ("body", "__typename")),
        "rest": (("body", "/api/"),),
    },
    "auth": {
        "jwt": (("header", "authorization: bearer"), ("body", "Bearer "), ("body", "eyJ")),
        "session_cookie": (
            ("header", "set-cookie: connect.sid"),
            ("header", "set-cookie: session"),
            ("header", "set-cookie: _session"),
        ),
        "oauth": (("body", "/oauth/"), ("body", "client_id="), ("body", "/auth/callback")),
    },
    "cdn_waf": {
        "cloudflare": (("header", "server: cloudflare"), ("header", "cf-ray")),
        "vercel": (("header", "x-vercel-id"), ("header", "server: vercel")),
        "netlify": (("header", "x-nf-request-id"), ("header", "server: netlify")),
        "fastly": (("header", "x-served-by: cache"), ("header", "via: varnish")),
        "akamai": (("header", "x-akamai"),),
        "sucuri": (("header", "x-sucuri-id"),),
    },
    "cloud": {
        "aws": (("header", "x-amz-"), ("header", "server: amazons3")),
        "gcp": (("header", "x-goog-"), ("header", "server: google frontend")),
        "azure": (("header", "x-azure-ref"), ("header", "x-ms-")),
    },
    "cms": {
        "wordpress": (("body", "/wp-content/"), ("body", "/wp-json/"), ("body", "wp-includes")),
        "drupal": (("header", "x-generator: drupal"), ("body", "/sites/default/")),
        "shopify": (("header", "x-shopify"), ("body", "cdn.shopify.com")),
    },
}
_MULTI = frozenset({"baas", "api", "auth", "cdn_waf", "cloud"})  # can have several
_SINGLE = frozenset({"framework", "cms"})  # first match wins


def _headers_blob(headers: dict[str, str]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()


def _match(category: str, label: str, header_blob: str, body: str) -> list[str]:
    hits: list[str] = []
    for kind, needle in _SIGNATURES[category][label]:
        if kind == "header" and needle.lower() in header_blob:
            hits.append(f"header~{needle}")
        elif kind == "body" and needle in body:
            hits.append(f"body~{needle}")
    return hits


def _extract_supabase(body: str) -> tuple[str | None, str | None]:
    url_match = _SUPABASE_URL_RE.search(body)
    anon = None
    for token in _JWT_RE.findall(body):
        try:
            parts = token.split(".")
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
        except (ValueError, json.JSONDecodeError, IndexError):
            continue
        if isinstance(payload, dict) and payload.get("role") == "anon":
            anon = token
            break
    return (url_match.group(0) if url_match else None), anon


def _profile_target_impl(url: str, timeout: int) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    page = _replay_impl("GET", url, None, None, timeout, allow_redirects=True)
    if not page.get("success"):
        return {"success": False, "error": page.get("error")}
    final_url = page.get("final_url") or url
    header_blob = _headers_blob(page.get("response_headers") or {})
    body = page.get("body") or ""

    bundle_urls = [urljoin(final_url, s) for s in _SCRIPT_SRC_RE.findall(body)][:_MAX_BUNDLES]
    for bundle in bundle_urls:
        resp = _replay_impl("GET", bundle, None, None, timeout, allow_redirects=True)
        if resp.get("success"):
            body += "\n" + (resp.get("body") or "")

    profile: dict[str, Any] = {cat: ([] if cat in _MULTI else None) for cat in _SIGNATURES}
    evidence: dict[str, list[str]] = {}
    for category, labels in _SIGNATURES.items():
        for label in labels:
            hits = _match(category, label, header_blob, body)
            if not hits:
                continue
            evidence[f"{category}:{label}"] = hits
            if category in _SINGLE:
                if profile[category] is None:
                    profile[category] = label
            else:
                profile[category].append(label)

    supabase_url, supabase_anon = _extract_supabase(body)
    return {
        "success": True,
        "url": url,
        "final_url": final_url,
        "bundles_scanned": len(bundle_urls),
        **profile,
        "supabase_url": supabase_url,
        "supabase_anon_key": supabase_anon,
        "evidence": evidence,
    }


@function_tool(timeout=120, strict_mode=False)
async def profile_target(ctx: RunContextWrapper, url: str, timeout: int = 20) -> str:
    """Fingerprint a target's tech stack to drive tailored testing.

    Reads the page + its JS bundles and infers ``framework`` (Next/Nuxt/Django/
    Rails/Laravel/Express/FastAPI/…), ``baas`` (Supabase/Firebase/Amplify),
    ``api`` (rest/graphql), ``auth`` (jwt/session/oauth), ``cdn_waf``, ``cloud``,
    and ``cms``. Extracts ``supabase_url`` + ``supabase_anon_key`` when present so
    ``backend_rules_probe`` can run right away. Pass the result to ``plan_tests``.

    Returns JSON with each category, an ``evidence`` map, and the Supabase creds.

    Args:
        url: The target URL to fingerprint.
        timeout: Per-request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_profile_target_impl, url, timeout),
        ensure_ascii=False,
        default=str,
    )
