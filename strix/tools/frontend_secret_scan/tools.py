"""Scan a site's SERVED JavaScript/HTML for leaked secrets, then live-validate.

gitleaks/git_recon cover the repo side; vibe-coded apps leak keys a different
way — baked into the shipped client bundle (``NEXT_PUBLIC_*``, Vite
``import.meta.env``, hardcoded Supabase ``service_role``, Stripe ``sk_live``).
This fetches the page + its JS, regex-matches key shapes, and (opt-in) validates
a couple providers so only LIVE keys are reported — no false positives.
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


_MAX_BUNDLES = 25
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)

# (name, regex, severity). Ordered; JWT handled separately to grade role.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("stripe_secret_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical"),
    ("stripe_restricted_key", re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), "critical"),
    ("stripe_test_key", re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "medium"),
    ("openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "critical"),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "high"),
    ("github_pat", re.compile(r"(?:ghp|gho|ghs)_[0-9A-Za-z]{36}"), "critical"),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("sendgrid_key", re.compile(r"SG\.[\w\-]{22}\.[\w\-]{43}"), "critical"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("stripe_publishable", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "info"),
)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _grade_jwt(token: str) -> tuple[str, str] | None:  # noqa: PLR0911
    """Return (label, severity) for a Supabase-style JWT, or None to skip."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    role = str(payload.get("role", ""))
    if role == "service_role":
        return "supabase_service_role_key", "critical"
    if role == "anon":
        return "supabase_anon_key", "info"
    if "role" in payload or "iss" in payload:
        return "jwt", "low"
    return None


def _scan_text(source_url: str, text: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = [
        {"type": name, "value": match, "severity": severity, "source": source_url}
        for name, pattern, severity in _SECRET_PATTERNS
        for match in set(pattern.findall(text))
    ]
    for token in set(_JWT_RE.findall(text)):
        graded = _grade_jwt(token)
        if graded:
            found.append(
                {"type": graded[0], "value": token, "severity": graded[1], "source": source_url}
            )
    return found


def _validate(finding: dict[str, Any], timeout: int) -> bool | None:
    """Best-effort live check for a couple providers. None = not attempted."""
    value = finding["value"]
    if finding["type"] in {"stripe_secret_key", "stripe_restricted_key", "stripe_test_key"}:
        resp = _replay_impl(
            "GET",
            "https://api.stripe.com/v1/balance",
            {"Authorization": f"Bearer {value}"},
            None,
            timeout,
            allow_redirects=False,
        )
        return resp.get("status_code") == 200 if resp.get("success") else None
    if finding["type"] == "openai_key":
        resp = _replay_impl(
            "GET",
            "https://api.openai.com/v1/models",
            {"Authorization": f"Bearer {value}"},
            None,
            timeout,
            allow_redirects=False,
        )
        return resp.get("status_code") == 200 if resp.get("success") else None
    return None


def _frontend_secret_scan_impl(url: str, validate: bool, timeout: int) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    page = _replay_impl("GET", url, None, None, timeout, allow_redirects=True)
    if not page.get("success"):
        return {"success": False, "error": page.get("error")}
    html = page.get("body") or ""
    final_url = page.get("final_url") or url

    texts: list[tuple[str, str]] = [(final_url, html)]
    bundle_urls = [urljoin(final_url, src) for src in _SCRIPT_SRC_RE.findall(html)]
    for bundle in bundle_urls[:_MAX_BUNDLES]:
        resp = _replay_impl("GET", bundle, None, None, timeout, allow_redirects=True)
        if resp.get("success"):
            texts.append((bundle, resp.get("body") or ""))

    seen: set[tuple[str, str]] = set()
    findings: list[dict[str, Any]] = []
    for source_url, text in texts:
        for f in _scan_text(source_url, text):
            key = (f["type"], f["value"])
            if key in seen:
                continue
            seen.add(key)
            if validate:
                f["live"] = _validate(f, timeout)
            findings.append(f)

    bundles_dropped = max(0, len(bundle_urls) - _MAX_BUNDLES)
    return {
        "success": True,
        "url": final_url,
        "bundles_scanned": len(texts) - 1,
        "bundles_dropped": bundles_dropped,
        "secret_count": len(findings),
        "possible_secret_leak": bool(findings),
        "findings": findings,
    }


@function_tool(timeout=180, strict_mode=False)
async def frontend_secret_scan(
    ctx: RunContextWrapper,
    url: str,
    validate: bool = False,
    timeout: int = 20,
) -> str:
    """Scan a page and its served JS bundles for leaked secrets.

    Fetches the HTML, follows its ``<script src>`` bundles, and regex-matches
    key shapes (AWS, Stripe ``sk_live``, OpenAI, Google, GitHub, Slack, private
    keys, and Supabase JWTs graded by role — ``service_role`` = critical, anon =
    info). With ``validate=True`` it live-checks Stripe/OpenAI keys against the
    provider so only working keys are confirmed. Only scan authorized targets.

    Returns JSON with ``secret_count``, ``possible_secret_leak``, and per-finding
    ``type`` / ``value`` / ``severity`` / ``source`` (+ ``live`` when validated).

    Args:
        url: Page URL to scan (the app's front end).
        validate: When True, live-validate Stripe/OpenAI keys (sends the key to
            the provider's own API). Default False.
        timeout: Per-request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_frontend_secret_scan_impl, url, validate, timeout),
        ensure_ascii=False,
        default=str,
    )
