"""Test whether 2FA/MFA can be skipped (account takeover).

Common vibe bug: the app gates the LOGIN screen with 2FA but the protected
resource itself only checks that you logged in — so a session that stopped at the
"enter your code" step can reach the resource directly. Also tests whether a
client-trusted header (``X-2FA-Verified``) flips the gate.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_TRUST_HEADERS = {
    "X-2FA-Verified": "true",
    "X-Mfa-Verified": "1",
    "X-2FA-Passed": "true",
    "X-Authenticated-2FA": "true",
}


def _authorized(resp: dict[str, Any]) -> bool:
    status = resp.get("status_code")
    return isinstance(status, int) and 200 <= status < 300


def _mfa_bypass_impl(
    protected_url: str,
    pre_2fa_headers: dict[str, str] | None,
    method: str,
    timeout: int,
) -> dict[str, Any]:
    if not protected_url or not pre_2fa_headers:
        return {
            "success": False,
            "error": "protected_url and pre_2fa_headers (session stopped at the 2FA step) required",
        }
    findings: list[str] = []

    # 1. Direct access with a pre-2FA session.
    direct = _replay_impl(
        method, protected_url, pre_2fa_headers, None, timeout, allow_redirects=False
    )
    if not direct.get("success"):
        return {"success": False, "error": direct.get("error")}
    direct_ok = _authorized(direct)
    if direct_ok:
        findings.append(
            "a pre-2FA session reaches the protected resource — 2FA not enforced past login"
        )

    # 2. Client-trusted 2FA header flips the gate.
    if not direct_ok:
        forged = {**pre_2fa_headers, **_TRUST_HEADERS}
        h_resp = _replay_impl(method, protected_url, forged, None, timeout, allow_redirects=False)
        if _authorized(h_resp):
            findings.append("a client-supplied X-2FA-Verified header bypasses 2FA")

    return {
        "success": True,
        "protected_url": protected_url,
        "direct_status": direct.get("status_code"),
        "possible_mfa_bypass": bool(findings),
        "findings": findings,
        "note": (
            None
            if findings
            else "no bypass seen — confirm the session truly stopped before the 2FA code"
        ),
    }


@function_tool(timeout=90, strict_mode=False)
async def mfa_bypass(
    ctx: RunContextWrapper,
    protected_url: str,
    pre_2fa_headers: dict[str, str],
    method: str = "GET",
    timeout: int = 15,
) -> str:
    """Test whether 2FA/MFA can be skipped to reach a protected resource.

    Using a session that stopped at the "enter your 2FA code" step, requests the
    protected resource directly — success = 2FA gates only the login screen, not
    the resource (ATO). Also tries client-trusted headers (``X-2FA-Verified``).
    Only test authorized targets.

    Returns JSON with ``possible_mfa_bypass`` and the ``findings``.

    Args:
        protected_url: A resource that should require completed 2FA.
        pre_2fa_headers: Headers for a session authenticated but NOT past 2FA.
        method: HTTP method (default GET).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_mfa_bypass_impl, protected_url, pre_2fa_headers, method, timeout),
        ensure_ascii=False,
        default=str,
    )
