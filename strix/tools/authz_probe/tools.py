"""Replay one request across identities and diff the responses.

Broken access control (IDOR, horizontal/vertical priv-esc) is the highest-value
bug class in the Strix methodology, and proving it means sending the *same*
request as several identities and comparing what comes back. Doing that by hand
is: get_credential, http_replay, get_credential, http_replay, diff_response —
repeated per identity. This collapses that into one call and surfaces the
signal (same data served to different identities, or a 2xx for an identity that
should be denied) so the driving LLM can judge and then validate_finding.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.credentials.tools import _get_credential_impl
from strix.tools.http_replay.tools import _replay_impl


logger = logging.getLogger(__name__)

_UNAUTH_LABELS = frozenset({"", "unauth", "anonymous", "none"})


def _identity_headers(
    identity: dict[str, Any], base_headers: dict[str, str] | None
) -> tuple[dict[str, str], str | None]:
    """Build the header set for one identity. Returns (headers, error)."""
    headers = dict(base_headers or {})
    label = str(identity.get("label", "")).strip()
    header_name = str(identity.get("header") or "Authorization")
    if label.lower() in _UNAUTH_LABELS:
        # Unauthenticated baseline: strip any inherited auth header.
        headers.pop(header_name, None)
        return headers, None
    cred = _get_credential_impl(label)
    if not cred.get("success"):
        return headers, f"credential '{label}' not found (store_credential first)"
    value = cred.get("value") or ""
    prefix = identity.get("value_prefix")
    headers[header_name] = f"{prefix}{value}" if isinstance(prefix, str) else value
    return headers, None


def _probe_one(
    method: str,
    url: str,
    identity: dict[str, Any],
    base_headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
) -> dict[str, Any]:
    label = str(identity.get("label", "")).strip() or "unauth"
    headers, err = _identity_headers(identity, base_headers)
    if err:
        return {"identity": label, "success": False, "error": err}
    resp = _replay_impl(method, url, headers, body, timeout, allow_redirects=False)
    if not resp.get("success"):
        return {"identity": label, "success": False, "error": resp.get("error")}
    text = resp.get("body") or ""
    return {
        "identity": label,
        "success": True,
        "status_code": resp.get("status_code"),
        "body_length": len(text),
        # sha256 over the (possibly truncated) body — same digest across two
        # identities is the IDOR tell.
        "body_sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16],
        "elapsed_ms": resp.get("elapsed_ms"),
    }


def _authz_probe_impl(
    method: str,
    url: str,
    identities: list[dict[str, Any]],
    base_headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not identities:
        return {
            "success": False,
            "error": "identities cannot be empty (list of {label, header?})",
        }
    results = [_probe_one(method, url, ident, base_headers, body, timeout) for ident in identities]

    ok = [r for r in results if r.get("success")]
    # Signal 1: two identities get byte-identical bodies = same object served
    # regardless of who asked = classic IDOR / broken access control.
    by_digest: dict[str, list[str]] = {}
    for r in ok:
        by_digest.setdefault(str(r["body_sha256"]), []).append(str(r["identity"]))
    shared = {digest: names for digest, names in by_digest.items() if len(names) > 1}
    # Signal 2: a 2xx for any identity beyond the first (the intended owner) — the
    # first identity is treated as the authorized baseline by convention.
    baseline = ok[0]["identity"] if ok else None
    unexpected_2xx = [
        r["identity"]
        for r in ok[1:]
        if isinstance(r.get("status_code"), int) and 200 <= r["status_code"] < 300
    ]
    return {
        "success": True,
        "url": url,
        "method": method.upper(),
        "baseline_identity": baseline,
        "results": results,
        # ponytail: byte-digest + status heuristic; the LLM confirms intent and
        # runs validate_finding before filing. Upgrade to structural JSON diff if
        # bodies carry per-identity nonces that defeat digest equality.
        "shared_body_identities": list(shared.values()),
        "identities_allowed_beyond_baseline": unexpected_2xx,
        "possible_authz_issue": bool(shared) or bool(unexpected_2xx),
    }


@function_tool(timeout=180, strict_mode=False)
async def authz_probe(
    ctx: RunContextWrapper,
    method: str,
    url: str,
    identities: list[dict[str, Any]],
    base_headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 15,
) -> str:
    """Replay one request as several identities and diff the responses to hunt
    broken access control (IDOR, horizontal/vertical priv-esc).

    Each identity injects a stored credential (by ``store_credential`` label)
    into a request header, then the same request is sent per identity and the
    responses are compared. Two identities getting a byte-identical body, or an
    identity beyond the first getting a 2xx, flags a possible authz issue —
    confirm it and run ``validate_finding`` before ``create_vulnerability_report``.
    Only test authorized targets; there are no scope guardrails.

    Returns JSON: per-identity ``status_code``, ``body_length``, ``body_sha256``;
    plus ``shared_body_identities`` (identities served the same body),
    ``identities_allowed_beyond_baseline`` (unexpected 2xx), and
    ``possible_authz_issue``.

    Args:
        method: HTTP method, e.g. ``"GET"``.
        url: Full request URL (typically an object the first identity owns).
        identities: List of ``{"label": <credential label or "unauth">,
            "header": "Authorization", "value_prefix": "Bearer "}``. ``header``
            defaults to ``Authorization``; ``value_prefix`` is prepended to the
            stored value (e.g. ``"Bearer "``). Label ``"unauth"`` sends no auth.
            The first identity is the authorized baseline.
        base_headers: Headers common to every identity (e.g. content type).
        body: Optional raw request body.
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _authz_probe_impl, method, url, identities, base_headers, body, timeout
        ),
        ensure_ascii=False,
        default=str,
    )
