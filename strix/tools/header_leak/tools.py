"""Scan response headers + cookies/JWT for leaked version, debug, and PII data.

Beyond the security-header audit, headers themselves leak: exact software
versions (targeted CVEs), debug/internal headers, per-user identifiers, cloud
metadata — and cookies/JWTs carry PII in their claims. This flags all of that.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


# header (lowercase) -> what it leaks / severity.
_VERSION_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
)
_DEBUG_HEADERS = (
    "x-debug",
    "x-debug-token",
    "x-debug-token-link",
    "x-runtime",
    "x-request-id",
    "x-sourcemap",
    "x-symfony-cache",
    "x-drupal-cache",
    "x-error",
    "x-exception",
)
_PII_HEADER_RE = re.compile(
    r"^x-(?:user|customer|account|email|member|employee)[\w-]*$", re.IGNORECASE
)
_INTERNAL_HEADER_RE = re.compile(
    r"^x-(?:amz-meta|backend|upstream|internal|host|real-ip|forwarded-server)", re.IGNORECASE
)
_VERSIONED = re.compile(r"\d+\.\d+")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*")
_PII_CLAIMS = ("email", "phone", "name", "given_name", "family_name", "address", "ssn", "dob")


def _b64url(segment: str) -> Any:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return None


def _scan_jwt_pii(value: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for token in _JWT_RE.findall(value):
        parts = token.split(".")
        if len(parts) < 2:
            continue
        payload = _b64url(parts[1])
        if isinstance(payload, dict):
            leaked = sorted(k for k in payload if str(k).lower() in _PII_CLAIMS)
            if leaked:
                out.append({"claims": leaked})
    return out


def _header_leak_impl(url: str, timeout: int) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    resp = _replay_impl("GET", url, None, None, timeout, allow_redirects=True)
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error")}
    headers = {str(k): str(v) for k, v in (resp.get("response_headers") or {}).items()}
    lower = {k.lower(): v for k, v in headers.items()}

    findings: list[dict[str, Any]] = []
    findings.extend(
        {"header": h, "leak": "software version", "value": lower[h]}
        for h in _VERSION_HEADERS
        if h in lower and _VERSIONED.search(lower[h])
    )
    findings.extend(
        {"header": h, "leak": "debug/internal", "value": lower[h][:120]}
        for h in _DEBUG_HEADERS
        if h in lower
    )
    for name, value in headers.items():
        low_name = name.lower()
        if _PII_HEADER_RE.match(name):
            findings.append(
                {"header": low_name, "leak": "per-user identifier", "value": value[:120]}
            )
        elif _INTERNAL_HEADER_RE.match(name):
            findings.append({"header": low_name, "leak": "internal infra", "value": value[:120]})
        elif _EMAIL_RE.search(value):
            findings.append({"header": low_name, "leak": "email in header", "value": value[:120]})

    cookie_pii = _scan_jwt_pii(lower.get("set-cookie", "") + " " + lower.get("authorization", ""))
    if cookie_pii:
        findings.append(
            {"header": "set-cookie/jwt", "leak": "PII in JWT claims", "value": cookie_pii}
        )

    return {
        "success": True,
        "url": url,
        "possible_header_leak": bool(findings),
        "findings": findings,
    }


@function_tool(timeout=60, strict_mode=False)
async def header_leak(ctx: RunContextWrapper, url: str, timeout: int = 15) -> str:
    """Scan response headers + cookies/JWT for version, debug, and PII leakage.

    Flags exact software-version banners (``Server``/``X-Powered-By`` with a
    version → targeted CVEs), debug/internal headers (``X-Debug``/``X-Runtime``),
    per-user identifier headers (``X-User-*``), internal-infra headers
    (``X-Amz-Meta-*``/``X-Backend``), emails in headers, and PII in JWT claims
    carried by ``Set-Cookie``/``Authorization``. Only test authorized targets.

    Returns JSON with ``findings`` (header/leak/value) and ``possible_header_leak``.

    Args:
        url: The URL whose response headers to inspect.
        timeout: Request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_header_leak_impl, url, timeout), ensure_ascii=False, default=str
    )
