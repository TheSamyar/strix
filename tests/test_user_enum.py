"""user_enumeration_probe: detect existing-vs-nonexistent account leaks."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.user_enum import tools as ue


def _resp(body: str = "", status: int = 200, elapsed_ms: float = 50.0) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body, "elapsed_ms": elapsed_ms}


def test_message_based_enum_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every (invalid) request says "no account with that email".
    monkeypatch.setattr(
        ue, "_replay_impl", lambda *a, **k: _resp("No account with that email", 404)
    )
    out = ue._user_enum_impl("POST", "https://x/reset", "email", None, None, None, "body", 10)
    assert out["possible_user_enumeration"] is True
    assert any("message-based" in s for s in out["signals"])


def test_status_diff_enum_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        # valid account → 200; nonexistent → 404
        return _resp("ok", 200) if "known@corp.com" in (body or "") else _resp("nope", 404)

    monkeypatch.setattr(ue, "_replay_impl", _fake)
    out = ue._user_enum_impl(
        "POST", "https://x/login", "email", "known@corp.com", None, None, "body", 10
    )
    assert out["possible_user_enumeration"] is True
    assert any("status differs" in s for s in out["signals"])


def test_timing_enum_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        # valid account hashes a password → much slower, same body/status
        if "known@corp.com" in (body or ""):
            return _resp("generic", 401, elapsed_ms=900)
        return _resp("generic", 401, elapsed_ms=60)

    monkeypatch.setattr(ue, "_replay_impl", _fake)
    out = ue._user_enum_impl(
        "POST", "https://x/login", "email", "known@corp.com", None, None, "body", 10
    )
    assert any("timing enum" in s for s in out["signals"])


def test_uniform_response_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # Same generic response for everything, same timing → no enumeration.
    monkeypatch.setattr(
        ue, "_replay_impl", lambda *a, **k: _resp("If the email exists, we sent a link", 200)
    )
    out = ue._user_enum_impl(
        "POST", "https://x/reset", "email", "known@corp.com", None, None, "body", 10
    )
    assert out["possible_user_enumeration"] is False


def test_empty_url_rejected() -> None:
    assert ue._user_enum_impl("POST", "", "email", None, None, None, "body", 10)["success"] is False
