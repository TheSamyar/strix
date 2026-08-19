"""Probe a URL for permissive CORS — the most common vibe-code misconfig.

AI codegen loves to reflect the request Origin (or set ``*``) and pair it with
``Access-Control-Allow-Credentials: true`` to "kill CORS friction". Reflected
origin + credentials is a critical cross-origin credentialed-read primitive.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_DEFAULT_ORIGINS = ("https://evil.example", "null")


def _header(headers: dict[str, str], name: str) -> str | None:
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return None


def _classify(origin: str, acao: str | None, creds: bool) -> tuple[str | None, str]:  # noqa: PLR0911
    """Return (severity, reason). None severity = not an issue."""
    if acao is None:
        return None, "no Access-Control-Allow-Origin returned"
    reflected = acao == origin
    wildcard = acao == "*"
    if wildcard and creds:
        # Browsers reject `*` + credentials, so not directly exploitable.
        return "low", "wildcard ACAO with credentials (browser-rejected, still sloppy)"
    if origin == "null" and reflected and creds:
        return "high", "reflects Origin: null with credentials (sandboxed-iframe attack)"
    if reflected and creds:
        return "critical", f"reflects Origin {origin!r} AND allows credentials"
    if reflected:
        return (
            "medium",
            f"reflects arbitrary Origin {origin!r} (cross-origin read of non-cred data)",
        )
    if wildcard:
        return "low", "wildcard ACAO (any origin can read non-credentialed responses)"
    return None, f"ACAO {acao!r} does not reflect the test origin"


def _cors_probe_impl(
    url: str, method: str, origins: list[str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    test_origins = origins or list(_DEFAULT_ORIGINS)
    results: list[dict[str, Any]] = []
    worst: str | None = None
    order = ["low", "medium", "high", "critical"]
    for origin in test_origins:
        resp = _replay_impl(method, url, {"Origin": origin}, None, timeout, allow_redirects=False)
        if not resp.get("success"):
            results.append({"origin": origin, "error": resp.get("error")})
            continue
        headers = resp.get("response_headers") or {}
        acao = _header(headers, "Access-Control-Allow-Origin")
        creds = (_header(headers, "Access-Control-Allow-Credentials") or "").lower() == "true"
        severity, reason = _classify(origin, acao, creds)
        results.append(
            {
                "origin": origin,
                "acao": acao,
                "allow_credentials": creds,
                "severity": severity,
                "reason": reason,
            }
        )
        if severity and (worst is None or order.index(severity) > order.index(worst)):
            worst = severity
    return {
        "success": True,
        "url": url,
        "possible_cors_issue": worst is not None,
        "worst_severity": worst,
        "results": results,
    }


@function_tool(timeout=90, strict_mode=False)
async def cors_probe(
    ctx: RunContextWrapper,
    url: str,
    method: str = "GET",
    origins: list[str] | None = None,
    timeout: int = 15,
) -> str:
    """Test a URL for permissive CORS (reflected/`*`/`null` Origin + credentials).

    Sends the request with several attacker Origins and inspects the
    ``Access-Control-Allow-Origin`` / ``Access-Control-Allow-Credentials``
    response headers. Reflected Origin + credentials is critical (cross-origin
    credentialed read). Only test authorized targets.

    Returns JSON with per-origin ``acao`` / ``allow_credentials`` / ``severity``
    and an overall ``possible_cors_issue`` + ``worst_severity``.

    Args:
        url: Full URL to test (ideally a credentialed API endpoint).
        method: HTTP method (default GET).
        origins: Origins to test (default an evil host and ``null``).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_cors_probe_impl, url, method, origins, timeout),
        ensure_ascii=False,
        default=str,
    )
