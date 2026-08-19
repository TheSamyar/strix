"""csrf_probe and default_creds."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.tools.csrf_probe import tools as csrf
from strix.tools.default_creds import tools as dc


def _resp(
    status: int = 200, headers: dict[str, str] | None = None, body: str = ""
) -> dict[str, Any]:
    return {"success": True, "status_code": status, "response_headers": headers or {}, "body": body}


# ---- csrf_probe ----------------------------------------------------------


def test_csrf_no_origin_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # every request (incl. forged Origin / no token) succeeds
    monkeypatch.setattr(csrf, "_replay_impl", lambda *a, **k: _resp(200))
    out = csrf._csrf_probe_impl(
        "POST",
        "https://x/change-email",
        '{"email":"a@b.c","csrf_token":"t"}',
        {"Cookie": "s=1"},
        "csrf_token",
        10,
    )
    assert out["possible_csrf"] is True


def test_csrf_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: Any, *a: Any, **k: Any) -> dict[str, Any]:
        origin = (headers or {}).get("Origin", "")
        has_token = body and "csrf_token" in body
        # rejects forged origin and missing token
        if origin or not has_token:
            return _resp(403)
        return _resp(200)

    monkeypatch.setattr(csrf, "_replay_impl", _fake)
    out = csrf._csrf_probe_impl(
        "POST", "https://x/change", '{"v":1,"csrf_token":"t"}', {"Cookie": "s=1"}, "csrf_token", 10
    )
    assert out["possible_csrf"] is False


def test_csrf_requires_write_method() -> None:
    out = csrf._csrf_probe_impl("GET", "https://x/", None, None, "csrf_token", 10)
    assert out["success"] is False


# ---- default_creds -------------------------------------------------------


def test_default_creds_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        creds = json.loads(body)
        if creds["username"] == "admin" and creds["password"] == "admin":
            return _resp(200, headers={"Set-Cookie": "session=win; Path=/"})
        return _resp(401, body="invalid credentials")

    monkeypatch.setattr(dc, "_replay_impl", _fake)
    out = dc._default_creds_impl("https://x/login", "username", "password", "POST", None, None, 10)
    assert out["possible_default_creds"] is True
    assert {"username": "admin", "password": "admin"} in out["valid_credentials"]


def test_default_creds_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dc, "_replay_impl", lambda *a, **k: _resp(401, body="invalid credentials"))
    out = dc._default_creds_impl("https://x/login", "username", "password", "POST", None, None, 10)
    assert out["possible_default_creds"] is False


def test_default_creds_extra_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        creds = json.loads(body)
        if creds["username"] == "founder" and creds["password"] == "letmein":
            return _resp(302, headers={"Set-Cookie": "auth=ok"})
        return _resp(401, body="wrong")

    monkeypatch.setattr(dc, "_replay_impl", _fake)
    out = dc._default_creds_impl(
        "https://x/login", "username", "password", "POST", None, [["founder", "letmein"]], 10
    )
    assert any(c["username"] == "founder" for c in out["valid_credentials"])
