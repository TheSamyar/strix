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
from urllib.parse import urljoin, urlsplit

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_MAX_BUNDLES = 10
_MAX_ENDPOINTS = 60
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]{16,}\.supabase\.co")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")

# API-ish paths worth handing straight to plan_tests / injection_fuzz without a
# separate discovery pass. Matches quoted route/URL literals in page + bundles.
_ENDPOINT_MARKER = re.compile(
    r"(?:/graphql|/api/|/rest/|/v[0-9]+/|/oauth/|/auth/|/admin/|/internal/|/webhook)",
    re.IGNORECASE,
)
_QUOTED_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./:{}$]{2,120})["'`]""")
_ABS_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9_\-./:%]{6,160})["'`]""")

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
    "ai": {
        "llm": (
            ("body", "openai"),
            ("body", "anthropic"),
            ("body", "/chat/completions"),
            ("body", "langchain"),
            ("body", "assistant"),
            ("body", "/v1/messages"),
        ),
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
_MULTI = frozenset({"baas", "api", "auth", "cdn_waf", "cloud", "ai"})  # can have several
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


def _extract_endpoints(body: str, final_url: str) -> list[str]:
    """Pull API-ish routes/URLs already visible in the page + bundle text.

    Passive extraction from bytes profile_target already downloaded — candidate
    endpoints, not confirmed live. Saves a separate discovery/sourcemap pass for
    the obvious surface at intake.
    """

    host = urlsplit(final_url).netloc
    found: set[str] = set()
    for m in _QUOTED_PATH_RE.findall(body):
        if _ENDPOINT_MARKER.search(m):
            found.add(m)
    for m in _ABS_URL_RE.findall(body):
        # keep only same-host absolute URLs that look like API routes
        if _ENDPOINT_MARKER.search(m) and (not host or host in m):
            found.add(m)
    # /graphql alone is high-signal even without a trailing slash
    if "/graphql" in body.lower():
        found.add("/graphql")
    return sorted(found)[:_MAX_ENDPOINTS]


# MCP tool names that actually exist in this tree. Skip anything not listed.
_EXISTING_PROBES = frozenset(
    {
        "graphql_introspection",
        "graphql_abuse",
        "jwt_audit",
        "jwt_confusion",
        "oauth_probe",
        "backend_rules_probe",
        "storage_probe",
        "injection_fuzz",
        "param_discover",
        "security_headers_probe",
        "header_leak",
        "frontend_secret_scan",
        "cors_probe",
    }
)
_ALWAYS_PROBES = (
    "security_headers_probe",
    "header_leak",
    "frontend_secret_scan",
    "cors_probe",
)


def _blob(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, dict):
        return " ".join(f"{k} {v}" for k, v in value.items()).lower()
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(v) for v in value).lower()
    return str(value).lower()


def _recommended_probes(profile: dict[str, Any]) -> list[str]:
    """Map a fingerprint dict to de-duplicated MCP tool names. No HTTP."""
    out: list[str] = []

    def add(*names: str) -> None:
        for name in names:
            if name in _EXISTING_PROBES and name not in out:
                out.append(name)

    add(*_ALWAYS_PROBES)
    api = _blob(profile.get("api"))
    auth = _blob(profile.get("auth"))
    baas = _blob(profile.get("baas"))
    if "graphql" in api:
        add("graphql_introspection", "graphql_abuse")
    if "jwt" in auth:
        add("jwt_audit", "jwt_confusion")
    if "oauth" in auth:
        add("oauth_probe")
    if "supabase" in baas:
        add("backend_rules_probe", "jwt_audit")
    if "firebase" in baas:
        add("storage_probe")
    # cms/wordpress: no dedicated MCP probe exists in this tree
    if profile.get("endpoints"):
        add("injection_fuzz", "param_discover")
    return out


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
    endpoints = _extract_endpoints(body, final_url)
    result: dict[str, Any] = {
        "success": True,
        "url": url,
        "final_url": final_url,
        "bundles_scanned": len(bundle_urls),
        **profile,
        "supabase_url": supabase_url,
        "supabase_anon_key": supabase_anon,
        "endpoints": endpoints,
        "evidence": evidence,
    }
    result["recommended_probes"] = _recommended_probes(result)
    return result


@function_tool(timeout=120, strict_mode=False)
async def profile_target(ctx: RunContextWrapper, url: str, timeout: int = 20) -> str:
    """Fingerprint a target's tech stack to drive tailored testing.

    Reads the page + its JS bundles and infers ``framework`` (Next/Nuxt/Django/
    Rails/Laravel/Express/FastAPI/…), ``baas`` (Supabase/Firebase/Amplify),
    ``api`` (rest/graphql), ``auth`` (jwt/session/oauth), ``cdn_waf``, ``cloud``,
    and ``cms``. Extracts ``supabase_url`` + ``supabase_anon_key`` when present so
    ``backend_rules_probe`` can run right away. Pass the result to ``plan_tests``.

    Also returns ``endpoints`` — API-ish routes/URLs (``/api/…``, ``/graphql``,
    ``/v1/…``, ``/oauth/…``, same-host absolute URLs) passively extracted from
    the page + bundles it already downloaded, so you can hand the obvious attack
    surface straight to ``plan_tests``/``injection_fuzz`` without a separate
    discovery pass. They are candidates, not confirmed live — verify before use.

    Returns JSON with each category, ``endpoints``, ``recommended_probes`` (MCP
    tool names implied by the fingerprint), an ``evidence`` map, and the
    Supabase creds.

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
