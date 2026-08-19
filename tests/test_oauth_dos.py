"""oauth_probe (redirect_uri/state/PKCE) and dos_probe (resource exhaustion)."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.dos_probe import tools as dp
from strix.tools.oauth_probe import tools as oa


def _resp(
    status: int = 200,
    headers: dict[str, str] | None = None,
    elapsed_ms: float = 40.0,
    body: str = "",
) -> dict[str, Any]:
    return {
        "success": True,
        "status_code": status,
        "response_headers": headers or {},
        "elapsed_ms": elapsed_ms,
        "body": body,
    }


# ---- oauth_probe ---------------------------------------------------------


def test_oauth_redirect_uri_not_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        # server blindly redirects to whatever redirect_uri was supplied
        if "evil-strix.example" in url:
            return _resp(302, headers={"Location": "https://evil-strix.example/cb?code=abc"})
        return _resp(302, headers={"Location": "https://legit/cb"})

    monkeypatch.setattr(oa, "_replay_impl", _fake)
    url = "https://idp/authorize?client_id=x&redirect_uri=https://app/cb&state=1&code_challenge=y"
    out = oa._oauth_probe_impl(url, None, 10)
    assert out["possible_oauth_flaw"] is True
    assert out["redirect_uri_findings"]


def test_oauth_missing_state_and_pkce(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oa, "_replay_impl", lambda *a, **k: _resp(400))
    url = "https://idp/authorize?client_id=x&redirect_uri=https://app/cb&response_type=code"
    out = oa._oauth_probe_impl(url, None, 10)
    assert out["state_present"] is False
    assert out["pkce_present"] is False
    assert any("state" in f for f in out["findings"])
    assert any("PKCE" in f for f in out["findings"])


def test_oauth_requires_redirect_uri() -> None:
    out = oa._oauth_probe_impl("https://idp/authorize?client_id=x", None, 10)
    assert out["success"] is False


# ---- dos_probe -----------------------------------------------------------


def test_dos_amplification_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: Any, *a: Any, **k: Any) -> dict[str, Any]:
        # the huge pagination value makes the endpoint crawl
        if "99999999" in url:
            return _resp(elapsed_ms=9000)
        return _resp(elapsed_ms=30)

    monkeypatch.setattr(dp, "_replay_impl", _fake)
    out = dp._dos_probe_impl("GET", "https://x/list", "limit", None, 20)
    assert out["possible_dos"] is True
    assert "huge_pagination" in out["amplified_tests"]


def test_dos_500_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: Any, *a: Any, **k: Any) -> dict[str, Any]:
        # deeply nested body crashes the parser
        if body and body.startswith('{"a"'):
            return _resp(status=500, elapsed_ms=50)
        return _resp(elapsed_ms=30)

    monkeypatch.setattr(dp, "_replay_impl", _fake)
    out = dp._dos_probe_impl("POST", "https://x/api", "q", None, 20)
    assert out["possible_dos"] is True


def test_dos_robust_endpoint_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dp, "_replay_impl", lambda *a, **k: _resp(status=200, elapsed_ms=35))
    out = dp._dos_probe_impl("GET", "https://x/list", "limit", None, 20)
    assert out["possible_dos"] is False
