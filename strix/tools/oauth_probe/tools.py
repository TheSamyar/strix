"""Probe an OAuth/OIDC authorize endpoint for takeover-grade flaws.

The classic OAuth ATO is a ``redirect_uri`` the server doesn't strictly validate:
point it at an attacker host and the victim's authorization code/token is
delivered to the attacker. Missing ``state`` (login CSRF), no PKCE (code
interception), and implicit flow (token in the URL) round out the checks.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_EVIL = "evil-strix.example"


def _header(headers: dict[str, str], name: str) -> str:
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return ""


def _set_redirect(url: str, redirect_uri: str) -> str:
    parsed = urlparse(url)
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    query["redirect_uri"] = redirect_uri
    return urlunparse(parsed._replace(query=urlencode(query)))


def _redirect_variants(original: str) -> list[tuple[str, str]]:
    ev = f"https://{_EVIL}/cb"
    variants = [
        ("attacker_host", ev),
        ("subdomain", original.rstrip("/") + f".{_EVIL}"),
        ("userinfo_at", original.rstrip("/") + f"@{_EVIL}"),
        ("path_append", original.rstrip("/") + f"/../../{_EVIL}"),
    ]
    parsed = urlparse(original)
    if parsed.scheme and parsed.netloc:
        variants.append(("sibling_path", f"{parsed.scheme}://{parsed.netloc}/../{_EVIL}"))
    return variants


def _oauth_probe_impl(
    authorize_url: str, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    if not authorize_url or "redirect_uri" not in authorize_url:
        return {"success": False, "error": "authorize_url must include a redirect_uri parameter"}
    query = {k: v[0] for k, v in parse_qs(urlparse(authorize_url).query).items()}
    original_redirect = query.get("redirect_uri", "")

    findings: list[str] = []
    if "state" not in query:
        findings.append("no state parameter — login CSRF")
    if "code_challenge" not in query and query.get("response_type") != "token":
        findings.append("no PKCE (code_challenge) — code interception risk")
    if query.get("response_type") == "token":
        findings.append("implicit flow (response_type=token) — token exposed in the URL fragment")

    redirect_findings: list[dict[str, Any]] = []
    for name, variant in _redirect_variants(original_redirect):
        resp = _replay_impl(
            "GET",
            _set_redirect(authorize_url, variant),
            headers,
            None,
            timeout,
            allow_redirects=False,
        )
        if not resp.get("success"):
            continue
        location = _header(resp.get("response_headers") or {}, "Location")
        status = resp.get("status_code")
        # Accepted if it redirects to (or echoes) the attacker host rather than erroring.
        accepted = _EVIL in location or (_EVIL in (resp.get("body") or "") and status == 200)
        if accepted:
            redirect_findings.append(
                {"variant": name, "redirect_uri": variant, "location": location}
            )
    if redirect_findings:
        findings.append("redirect_uri not strictly validated — authorization code/token theft")

    return {
        "success": True,
        "authorize_url": authorize_url,
        "state_present": "state" in query,
        "pkce_present": "code_challenge" in query,
        "redirect_uri_findings": redirect_findings,
        "findings": findings,
        "possible_oauth_flaw": bool(findings),
    }


@function_tool(timeout=120, strict_mode=False)
async def oauth_probe(
    ctx: RunContextWrapper,
    authorize_url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> str:
    """Probe an OAuth/OIDC authorize URL for takeover-grade flaws.

    Checks for missing ``state`` (login CSRF), missing PKCE, and implicit flow,
    then tampers ``redirect_uri`` (attacker host, subdomain, ``@`` userinfo, path
    traversal) and flags any variant the server redirects to instead of
    rejecting — that's authorization-code/token theft → account takeover. Only
    test authorized targets.

    Returns JSON with ``redirect_uri_findings``, ``state_present``,
    ``pkce_present``, and ``possible_oauth_flaw``.

    Args:
        authorize_url: The full ``/authorize`` URL (must contain ``redirect_uri``).
        headers: Request headers (e.g. an active session for the consent step).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_oauth_probe_impl, authorize_url, headers, timeout),
        ensure_ascii=False,
        default=str,
    )
