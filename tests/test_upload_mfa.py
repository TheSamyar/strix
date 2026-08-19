"""upload_probe and mfa_bypass."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.mfa_bypass import tools as mfa
from strix.tools.upload_probe import tools as up


def _resp(status: int = 200, body: str = "") -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body}


# ---- upload_probe --------------------------------------------------------


def test_upload_accepts_dangerous_files(monkeypatch: pytest.MonkeyPatch) -> None:
    # server accepts everything and echoes the stored filename
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        # pull the filename from the multipart body
        fn = body.split('filename="')[1].split('"', maxsplit=1)[0]
        return _resp(200, body=f'{{"stored":"/uploads/{fn.split("/")[-1]}"}}')

    monkeypatch.setattr(up, "_replay_impl", _fake)
    out = up._upload_probe_impl("https://x/upload", "file", "POST", None, 10)
    assert out["possible_upload_flaw"] is True
    assert "svg_xss" in out["accepted_uploads"]
    assert "php_rce" in out["accepted_uploads"]


def test_upload_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        up, "_replay_impl", lambda *a, **k: _resp(415, body="unsupported media type")
    )
    out = up._upload_probe_impl("https://x/upload", "file", "POST", None, 10)
    assert out["possible_upload_flaw"] is False


def test_upload_empty_url_rejected() -> None:
    assert up._upload_probe_impl("", "file", "POST", None, 10)["success"] is False


# ---- mfa_bypass ----------------------------------------------------------


def test_mfa_direct_access_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # a pre-2FA session reaches the protected resource
    monkeypatch.setattr(mfa, "_replay_impl", lambda *a, **k: _resp(200, body="account data"))
    out = mfa._mfa_bypass_impl("https://x/account", {"Cookie": "half=1"}, "GET", 10)
    assert out["possible_mfa_bypass"] is True
    assert any("pre-2FA" in f for f in out["findings"])


def test_mfa_header_trust_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        # only authorized when the client-supplied 2FA header is present
        return _resp(200) if (headers or {}).get("X-2FA-Verified") else _resp(401)

    monkeypatch.setattr(mfa, "_replay_impl", _fake)
    out = mfa._mfa_bypass_impl("https://x/account", {"Cookie": "half=1"}, "GET", 10)
    assert out["possible_mfa_bypass"] is True
    assert any("header" in f for f in out["findings"])


def test_mfa_enforced_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mfa, "_replay_impl", lambda *a, **k: _resp(403))
    out = mfa._mfa_bypass_impl("https://x/account", {"Cookie": "half=1"}, "GET", 10)
    assert out["possible_mfa_bypass"] is False


def test_mfa_requires_session() -> None:
    assert mfa._mfa_bypass_impl("https://x/account", None, "GET", 10)["success"] is False
