"""Minimal interactsh client — out-of-band interaction (OAST) capture.

Blind bugs (blind SSRF/XSS/SQLi/RCE, DNS exfil, indirect prompt-injection) leave
no trace in the response; the only proof is the target calling back to a host we
control. Strix runs with no public ingress, so it borrows an interactsh server:
register an RSA public key, hand out ``<token>.<server>`` payload domains, then
poll for AES-encrypted interactions the server captured and decrypt them locally.

Protocol: register public key + correlation-id + secret; poll returns an
RSA-OAEP(SHA-256)-encrypted AES key plus AES-CFB-encrypted interaction blobs.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import string
import threading
from dataclasses import dataclass, field
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEFAULT_SERVER = os.environ.get("STRIX_INTERACTSH_SERVER", "oast.pro").strip() or "oast.pro"
_ALPHABET = string.ascii_lowercase + string.digits
_CORRELATION_LEN = 20
_SUBDOMAIN_PAD = 13
_AES_IV_LEN = 16


@dataclass
class _Session:
    server: str
    correlation_id: str
    secret: str
    private_key: rsa.RSAPrivateKey
    public_key_b64: str
    interactions: list[dict[str, Any]] = field(default_factory=list)
    registered: bool = False


_sessions: dict[str, _Session] = {}
_lock = threading.Lock()


def _rand(n: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def _new_session(server: str) -> _Session:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return _Session(
        server=server,
        correlation_id=_rand(_CORRELATION_LEN),
        secret=str(secrets.token_hex(16)),
        private_key=key,
        public_key_b64=base64.b64encode(pub_pem).decode("ascii"),
    )


def _register(session: _Session, timeout: int) -> None:
    resp = requests.post(
        f"https://{session.server}/register",
        json={
            "public-key": session.public_key_b64,
            "secret-key": session.secret,
            "correlation-id": session.correlation_id,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    session.registered = True


def get_domain(server: str | None = None, timeout: int = 15) -> dict[str, Any]:
    """Register (once per server) and return a fresh payload domain."""
    server = (server or DEFAULT_SERVER).strip()
    with _lock:
        session = _sessions.get(server)
        if session is None:
            session = _new_session(server)
            _sessions[server] = session
        if not session.registered:
            try:
                _register(session, timeout)
            except (requests.RequestException, ValueError) as exc:
                _sessions.pop(server, None)
                return {"success": False, "error": f"interactsh register failed: {exc}"}
        domain = f"{session.correlation_id}{_rand(_SUBDOMAIN_PAD)}.{server}"
        return {
            "success": True,
            "domain": domain,
            "url": f"https://{domain}",
            "correlation_id": session.correlation_id,
            "server": server,
        }


def _decrypt_interaction(
    session: _Session, aes_key_b64: str, data_b64: str
) -> dict[str, Any] | None:
    aes_key = session.private_key.decrypt(
        base64.b64decode(aes_key_b64),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    raw = base64.b64decode(data_b64)
    iv, ct = raw[:_AES_IV_LEN], raw[_AES_IV_LEN:]
    decryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
    plaintext = decryptor.update(ct) + decryptor.finalize()
    try:
        parsed = json.loads(plaintext)
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def poll(correlation_id: str | None = None, timeout: int = 15) -> dict[str, Any]:
    """Poll for new interactions on a registered correlation id."""
    with _lock:
        if correlation_id:
            session = next(
                (s for s in _sessions.values() if s.correlation_id == correlation_id), None
            )
        else:
            session = next(iter(_sessions.values()), None)
        if session is None:
            return {"success": False, "error": "no registered OAST session; call oast_get_domain"}
        server, corr, secret = session.server, session.correlation_id, session.secret

    try:
        resp = requests.get(
            f"https://{server}/poll",
            params={"id": corr, "secret": secret},
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return {"success": False, "error": f"interactsh poll failed: {exc}"}

    aes_key = payload.get("aes_key")
    new: list[dict[str, Any]] = []
    for item in payload.get("data") or []:
        if not aes_key:
            continue
        interaction = _decrypt_interaction(session, aes_key, str(item))
        if interaction is not None:
            new.append(
                {
                    "protocol": interaction.get("protocol"),
                    "remote_address": interaction.get("remote-address"),
                    "timestamp": interaction.get("timestamp"),
                    "full_id": interaction.get("full-id"),
                    "raw_request": (interaction.get("raw-request") or "")[:2000],
                }
            )
    with _lock:
        session.interactions.extend(new)
    return {
        "success": True,
        "correlation_id": corr,
        "new_interactions": len(new),
        "total_interactions": len(session.interactions),
        "interactions": new,
        "got_callback": bool(session.interactions),
    }
