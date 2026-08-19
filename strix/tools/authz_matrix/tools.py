"""Run the full authorization grid: every endpoint x every identity x method.

authz_probe checks one request across identities; this sweeps a whole endpoint
list against every stored identity (plus an unauth baseline) and diffs the grid.
Broken access control is the #1 high-payout class — an endpoint where two
different identities get the same 2xx body, or where unauth gets in, is IDOR /
BFLA. Runs the matrix in one call and reports the flagged cells.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.authz_probe.tools import _identity_headers
from strix.tools.http_replay.tools import _replay_impl


def _digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


def _normalize_endpoint(item: Any) -> tuple[str, str]:
    if isinstance(item, dict):
        method = str(item.get("method") or "GET").upper()
        url = str(item.get("url") or item.get("path") or item.get("endpoint") or "")
        return method, url
    return "GET", str(item)


def _authorized(status: Any) -> bool:
    return isinstance(status, int) and 200 <= status < 300


def _authz_matrix_impl(
    endpoints: list[Any],
    identities: list[dict[str, Any]],
    base_headers: dict[str, str] | None,
    timeout: int,
    max_requests: int,
) -> dict[str, Any]:
    if not endpoints:
        return {"success": False, "error": "endpoints cannot be empty"}
    idents = list(identities or [])
    if not any(str(i.get("label", "")).strip().lower() in {"", "unauth"} for i in idents):
        idents.append({"label": "unauth"})

    budget = max(1, max_requests)
    rows: list[dict[str, Any]] = []
    flagged: list[dict[str, Any]] = []
    truncated = False

    for method, url in [_normalize_endpoint(e) for e in endpoints]:
        if not url:
            continue
        cells: dict[str, dict[str, Any]] = {}
        for ident in idents:
            if budget <= 0:
                truncated = True
                break
            budget -= 1
            label = str(ident.get("label", "")).strip() or "unauth"
            headers, err = _identity_headers(ident, base_headers)
            if err:
                cells[label] = {"error": err}
                continue
            resp = _replay_impl(method, url, headers, None, timeout, allow_redirects=False)
            if not resp.get("success"):
                cells[label] = {"error": resp.get("error")}
                continue
            body = resp.get("body") or ""
            cells[label] = {
                "status": resp.get("status_code"),
                "len": len(body),
                "digest": _digest(body),
                "authorized": _authorized(resp.get("status_code")),
            }

        # Analyze this endpoint's row: identities that got 2xx, grouped by body.
        by_digest: dict[str, list[str]] = {}
        for label, cell in cells.items():
            if cell.get("authorized"):
                by_digest.setdefault(str(cell["digest"]), []).append(label)
        shared = [labels for labels in by_digest.values() if len(labels) > 1]
        unauth_ok = cells.get("unauth", {}).get("authorized", False)
        if shared or unauth_ok:
            flagged.append(
                {
                    "endpoint": url,
                    "method": method,
                    "shared_body_identities": shared,
                    "unauth_authorized": bool(unauth_ok),
                }
            )
        rows.append({"endpoint": url, "method": method, "cells": cells})
        if truncated:
            break

    return {
        "success": True,
        "endpoints_tested": len(rows),
        "identities": [str(i.get("label", "")).strip() or "unauth" for i in idents],
        "flagged_count": len(flagged),
        "possible_broken_authz": bool(flagged),
        "flagged": flagged,
        "matrix": rows,
        "truncated": truncated,
    }


@function_tool(timeout=600, strict_mode=False)
async def authz_matrix(
    ctx: RunContextWrapper,
    endpoints: list[Any],
    identities: list[dict[str, Any]],
    base_headers: dict[str, str] | None = None,
    timeout: int = 15,
    max_requests: int = 400,
) -> str:
    """Sweep the whole authorization grid: endpoints x identities x method.

    For every endpoint, requests it as each stored identity (plus an auto unauth
    baseline) and diffs the row: two different identities getting the same 2xx
    body — or unauth getting a 2xx — is broken access control (IDOR/BFLA). Feed
    the endpoints from ``auth_crawl``/``endpoint_risk_rank`` and identities as
    ``{"label": <credential label or "unauth">, "header": "Authorization",
    "value_prefix": "Bearer "}`` (same shape as authz_probe). Only test
    authorized targets.

    Returns JSON with ``flagged`` (endpoint + shared/unauth-authorized), the full
    ``matrix``, and ``truncated``.

    Args:
        endpoints: Endpoints — path/URL strings or ``{"method", "url"}`` objects.
        identities: Identities to test (credential labels; ``unauth`` auto-added).
        base_headers: Headers common to every request (e.g. content type).
        timeout: Per-request timeout in seconds (default 15).
        max_requests: Budget across the whole grid (default 400).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _authz_matrix_impl, endpoints, identities, base_headers, timeout, max_requests
        ),
        ensure_ascii=False,
        default=str,
    )
