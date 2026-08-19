"""jwt_confusion, session_fixation_probe, reset_token_probe (takeover)."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from strix.tools.jwt_confusion.tools import _jwt_confusion_impl
from strix.tools.session_fixation import tools as sf


def _resp(
    body: str = "", status: int = 200, headers: dict[str, str] | None = None
) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body, "response_headers": headers or {}}


def _jwt(payload: dict[str, Any]) -> str:
    h = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.originalsig"


# ---- jwt_confusion -------------------------------------------------------


def test_rs_to_hs_confusion_forged() -> None:
    token = _jwt({"user": "bob", "role": "user"})
    out = _jwt_confusion_impl(token, "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----")
    assert "rs256_to_hs256" in out["forged_tokens"]
    # forged token carries escalated role=admin
    payload_b64 = out["forged_tokens"]["rs256_to_hs256"].split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    assert json.loads(base64.urlsafe_b64decode(payload_b64))["role"] == "admin"


def test_kid_and_none_always_forged() -> None:
    out = _jwt_confusion_impl(_jwt({"role": "user"}), None)
    assert "kid_devnull_empty_secret" in out["forged_tokens"]
    assert out["forged_tokens"]["alg_none"].endswith(".")


def test_jwt_confusion_bad_token() -> None:
    assert _jwt_confusion_impl("not.a.jwt.x", None)["success"] is False


# ---- session_fixation_probe ----------------------------------------------


def test_session_not_rotated_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # login returns the SAME session id it was given (no rotation)
    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        if method == "GET":
            return _resp(headers={"Set-Cookie": "session=abc123; Path=/"})
        return _resp(headers={"Set-Cookie": "session=abc123; Path=/"})

    monkeypatch.setattr(sf, "_replay_impl", _fake)
    out = sf._session_fixation_impl(
        "https://x/login", {"u": "a", "p": "b"}, "session", None, "POST", 10
    )
    assert out["possible_session_fixation"] is True


def test_session_rotated_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        if method == "GET":
            return _resp(headers={"Set-Cookie": "session=anon1; Path=/"})
        return _resp(headers={"Set-Cookie": "session=authed2; Path=/"})  # rotated

    monkeypatch.setattr(sf, "_replay_impl", _fake)
    out = sf._session_fixation_impl(
        "https://x/login", {"u": "a", "p": "b"}, "session", None, "POST", 10
    )
    assert out["possible_session_fixation"] is False


# ---- reset_token_probe ---------------------------------------------------


def test_reset_token_leaked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sf, "_replay_impl", lambda *a, **k: _resp('{"reset_link":"/r?token=' + "a" * 40 + '"}')
    )
    out = sf._reset_token_impl("https://x/reset", "email", "v@x.com", None, "POST", 10)
    assert out["possible_reset_weakness"] is True
    assert out["tokens_seen_in_response"] >= 1


def test_reset_no_token_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sf,
        "_replay_impl",
        lambda *a, **k: _resp('{"message":"If the email exists we sent a link"}'),
    )
    out = sf._reset_token_impl("https://x/reset", "email", "v@x.com", None, "POST", 10)
    assert out["possible_reset_weakness"] is False
