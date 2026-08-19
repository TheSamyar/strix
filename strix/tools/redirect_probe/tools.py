"""Open-redirect and Host-header (password-reset) poisoning probe.

Open redirect: a ``redirect``/``next``/``url`` param reflected into the Location
header (or a JS/meta redirect) lets an attacker bounce victims to a phishing
site — and steal OAuth codes. Host-header injection: many apps build absolute
links (especially password-reset emails) from the request Host, so a spoofed
``Host`` / ``X-Forwarded-Host`` poisons the reset link to an attacker domain.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_REDIRECT_PARAMS = (
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "url",
    "return",
    "return_to",
    "returnurl",
    "returnUrl",
    "callback",
    "dest",
    "destination",
    "continue",
    "r",
    "u",
)
_EVIL = "evil-strix.example"
_PAYLOAD = f"https://{_EVIL}/pwn"


def _header(headers: dict[str, str], name: str) -> str:
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return ""


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    query[name] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _check_open_redirect(
    url: str, params: list[str], headers: dict[str, str] | None, timeout: int
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for name in params:
        resp = _replay_impl(
            "GET", _with_param(url, name, _PAYLOAD), headers, None, timeout, allow_redirects=False
        )
        if not resp.get("success"):
            continue
        location = _header(resp.get("response_headers") or {}, "Location")
        body = resp.get("body") or ""
        in_location = _EVIL in location
        body_redirect_re = rf"(?:location|href|url)\s*[=:]\s*['\"]?https?://{re.escape(_EVIL)}"
        in_body = bool(re.search(body_redirect_re, body, re.IGNORECASE))
        if in_location or in_body:
            findings.append(
                {
                    "param": name,
                    "vector": "Location header" if in_location else "body redirect",
                    "status": resp.get("status_code"),
                    "location": location or None,
                }
            )
    return findings


def _check_host_injection(
    url: str, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    inj_headers = {**(headers or {}), "Host": _EVIL, "X-Forwarded-Host": _EVIL}
    resp = _replay_impl("GET", url, inj_headers, None, timeout, allow_redirects=False)
    if not resp.get("success"):
        return {"reflected": False, "error": resp.get("error")}
    location = _header(resp.get("response_headers") or {}, "Location")
    body = resp.get("body") or ""
    reflected = _EVIL in location or _EVIL in body
    return {
        "reflected": reflected,
        "where": ("Location" if _EVIL in location else "body") if reflected else None,
        "note": (
            "spoofed Host reflected into a link — reset-link poisoning if used in emails"
            if reflected
            else None
        ),
    }


def _redirect_probe_impl(
    url: str, params: list[str] | None, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    test_params = params or list(_REDIRECT_PARAMS)
    redirects = _check_open_redirect(url, test_params, headers, timeout)
    host = _check_host_injection(url, headers, timeout)
    return {
        "success": True,
        "url": url,
        "open_redirect_findings": redirects,
        "host_injection": host,
        "possible_open_redirect": bool(redirects),
        "possible_host_injection": bool(host.get("reflected")),
    }


@function_tool(timeout=120, strict_mode=False)
async def redirect_probe(
    ctx: RunContextWrapper,
    url: str,
    params: list[str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> str:
    """Test for open redirect and Host-header (reset-link) poisoning.

    Injects an attacker URL into common redirect params (``redirect``/``next``/
    ``url``/…) and flags it reflecting into the ``Location`` header or a body
    redirect (open redirect). Also sends a spoofed ``Host`` / ``X-Forwarded-Host``
    and flags it reflecting into a link (password-reset poisoning). Only test
    authorized targets.

    Returns JSON with ``open_redirect_findings``, ``host_injection``, and the
    ``possible_open_redirect`` / ``possible_host_injection`` flags.

    Args:
        url: The URL to test (a login/redirect/reset endpoint works best).
        params: Redirect param names to try; defaults to a built-in set.
        headers: Request headers (e.g. a session).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_redirect_probe_impl, url, params, headers, timeout),
        ensure_ascii=False,
        default=str,
    )
