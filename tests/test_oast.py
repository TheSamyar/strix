"""OAST interactsh client: register handshake + decrypt a captured interaction."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from strix.tools.oast import client


class _Resp:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


@pytest.fixture(autouse=True)
def _clear_sessions() -> None:
    client._sessions.clear()


def _encrypt_for(session: client._Session, interaction: dict[str, Any]) -> tuple[str, str]:
    """Encrypt an interaction the way an interactsh server would."""
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).encryptor()
    ct = encryptor.update(json.dumps(interaction).encode()) + encryptor.finalize()
    data_b64 = base64.b64encode(iv + ct).decode()
    enc_key = session.private_key.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.b64encode(enc_key).decode(), data_b64


def test_get_domain_registers_and_returns_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client.requests, "post", lambda *a, **k: _Resp({"message": "ok"}))
    out = client.get_domain("oast.test")
    assert out["success"] is True
    assert out["domain"].endswith(".oast.test")
    assert len(out["correlation_id"]) == 20


def test_register_failure_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: Any, **k: Any) -> Any:
        raise client.requests.RequestException("down")

    monkeypatch.setattr(client.requests, "post", _boom)
    out = client.get_domain("oast.test")
    assert out["success"] is False


def test_poll_decrypts_interaction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client.requests, "post", lambda *a, **k: _Resp({"message": "ok"}))
    reg = client.get_domain("oast.test")
    session = next(iter(client._sessions.values()))

    interaction = {
        "protocol": "dns",
        "remote-address": "9.9.9.9",
        "timestamp": "2026-01-01T00:00:00Z",
        "full-id": "abc",
        "raw-request": ";; QUESTION",
    }
    aes_key_b64, data_b64 = _encrypt_for(session, interaction)
    monkeypatch.setattr(
        client.requests, "get", lambda *a, **k: _Resp({"aes_key": aes_key_b64, "data": [data_b64]})
    )

    out = client.poll(reg["correlation_id"])
    assert out["success"] is True
    assert out["new_interactions"] == 1
    assert out["got_callback"] is True
    assert out["interactions"][0]["protocol"] == "dns"
    assert out["interactions"][0]["remote_address"] == "9.9.9.9"


def test_poll_without_session_errors() -> None:
    out = client.poll("nonexistent")
    assert out["success"] is False
