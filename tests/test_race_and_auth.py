"""race_probe (TOCTOU) and session_invalidation_probe (broken logout)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from strix.tools.auth_probe import tools as authp
from strix.tools.race_probe import tools as racep


def _resp(status: int, body: str = "") -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body}


# ---- race_probe ----------------------------------------------------------


def test_race_flags_multiple_write_successes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(racep, "_replay_impl", lambda *a, **k: _resp(200, "redeemed"))
    out = asyncio.run(racep._race_probe_impl("POST", "https://x/redeem", 10, None, None, 5))
    assert out["success_count"] == 10
    assert out["possible_race"] is True


def test_race_get_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(racep, "_replay_impl", lambda *a, **k: _resp(200, "ok"))
    out = asyncio.run(racep._race_probe_impl("GET", "https://x/", 10, None, None, 5))
    assert out["possible_race"] is False  # GETs expected to all succeed


def test_race_single_success_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def _fake(*a: Any, **k: Any) -> dict[str, Any]:
        calls["n"] += 1
        return _resp(200) if calls["n"] == 1 else _resp(409)  # only first wins

    monkeypatch.setattr(racep, "_replay_impl", _fake)
    out = asyncio.run(racep._race_probe_impl("POST", "https://x/redeem", 5, None, None, 5))
    assert out["success_count"] == 1
    assert out["possible_race"] is False


# ---- session_invalidation_probe -----------------------------------------


def test_broken_logout_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # protected always returns 200, even after logout → token never invalidated.
    monkeypatch.setattr(authp, "_replay_impl", lambda method, url, *a, **k: _resp(200))
    out = authp._session_invalidation_impl(
        "https://x/me", "https://x/logout", {"Cookie": "s=1"}, "GET", "POST", 10
    )
    assert out["broken_session_invalidation"] is True


def test_good_logout_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"logged_out": False}

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith("/logout"):
            state["logged_out"] = True
            return _resp(200)
        return _resp(401) if state["logged_out"] else _resp(200)

    monkeypatch.setattr(authp, "_replay_impl", _fake)
    out = authp._session_invalidation_impl(
        "https://x/me", "https://x/logout", {"Cookie": "s=1"}, "GET", "POST", 10
    )
    assert out["broken_session_invalidation"] is False


def test_inconclusive_when_not_authorized_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authp, "_replay_impl", lambda *a, **k: _resp(401))
    out = authp._session_invalidation_impl(
        "https://x/me", "https://x/logout", {"Cookie": "bad"}, "GET", "POST", 10
    )
    assert out.get("inconclusive") is True


def test_session_probe_requires_headers() -> None:
    out = authp._session_invalidation_impl(
        "https://x/me", "https://x/logout", None, "GET", "POST", 10
    )
    assert out["success"] is False
