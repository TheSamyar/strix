"""Audit response security headers + cookie flags.

Vibe deploys ship without CSP, HSTS, or clickjacking protection, and set auth
cookies without Secure/HttpOnly/SameSite. Each is a quick, deterministic header
check — low individually, but they're the baseline hardening AI codegen skips.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


# header (lowercase) -> (severity, why-it-matters)
_EXPECTED = {
    "content-security-policy": ("medium", "no CSP — XSS has no second line of defense"),
    "strict-transport-security": ("medium", "no HSTS — downgrade / SSL-strip possible"),
    "x-content-type-options": ("low", "missing nosniff — MIME-sniffing"),
    "referrer-policy": ("low", "no Referrer-Policy — URLs leak to third parties"),
}


def _headers_lower(resp: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (resp.get("response_headers") or {}).items()}


def _cookie_flag_issues(set_cookie: str) -> list[str]:
    if not set_cookie:
        return []
    low = set_cookie.lower()
    issues: list[str] = []
    if "httponly" not in low:
        issues.append("cookie without HttpOnly (readable by JS → XSS steals it)")
    if "secure" not in low:
        issues.append("cookie without Secure (sent over plain HTTP)")
    if "samesite" not in low:
        issues.append("cookie without SameSite (CSRF exposure)")
    return issues


def _security_headers_impl(url: str, timeout: int) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    resp = _replay_impl("GET", url, None, None, timeout, allow_redirects=True)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error")}
    headers = _headers_lower(resp)

    missing: list[dict[str, str]] = []
    for name, (severity, why) in _EXPECTED.items():
        if name not in headers:
            missing.append({"header": name, "severity": severity, "why": why})
    # HSTS only matters on HTTPS.
    if urlparse(url).scheme != "https":
        missing = [m for m in missing if m["header"] != "strict-transport-security"]

    # Clickjacking: needs X-Frame-Options OR CSP frame-ancestors.
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        missing.append(
            {
                "header": "x-frame-options / frame-ancestors",
                "severity": "medium",
                "why": "no clickjacking protection (page can be framed)",
            }
        )

    cookie_issues = _cookie_flag_issues(headers.get("set-cookie", ""))
    return {
        "success": True,
        "url": url,
        "missing_headers": missing,
        "cookie_issues": cookie_issues,
        "missing_count": len(missing),
        "possible_hardening_gaps": bool(missing or cookie_issues),
    }


@function_tool(timeout=60, strict_mode=False)
async def security_headers_probe(ctx: RunContextWrapper, url: str, timeout: int = 15) -> str:
    """Audit a response's security headers and cookie flags.

    Flags missing CSP, HSTS (on HTTPS), clickjacking protection
    (``X-Frame-Options`` / CSP ``frame-ancestors``), ``X-Content-Type-Options``,
    and ``Referrer-Policy``, plus auth cookies set without
    ``HttpOnly``/``Secure``/``SameSite``. Only test authorized targets.

    Returns JSON with ``missing_headers`` (header/severity/why), ``cookie_issues``,
    and ``possible_hardening_gaps``.

    Args:
        url: The URL whose response headers to audit.
        timeout: Request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_security_headers_impl, url, timeout),
        ensure_ascii=False,
        default=str,
    )
