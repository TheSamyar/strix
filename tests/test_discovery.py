"""param_discover and content_discover."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from strix.tools.discovery import tools as disc


def _resp(body: str = "", status: int = 200) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body}


# ---- param_discover ------------------------------------------------------


def test_hidden_param_reflected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        q = parse_qs(urlparse(url).query)
        # the app secretly honours 'debug' and reflects its value
        if "debug" in q:
            return _resp(f"debug output: {q['debug'][0]}")
        return _resp("normal page")

    monkeypatch.setattr(disc, "_replay_impl", _fake)
    out = disc._param_discover_impl("https://x/", None, None, 10)
    assert any(p["param"] == "debug" and p["signal"] == "reflected" for p in out["hidden_params"])


def test_param_response_change_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        q = parse_qs(urlparse(url).query)
        if "admin" in q:
            return _resp("A" * 500)  # much larger response = param processed
        return _resp("small")

    monkeypatch.setattr(disc, "_replay_impl", _fake)
    out = disc._param_discover_impl("https://x/", None, None, 10)
    assert any(p["param"] == "admin" for p in out["hidden_params"])


def test_no_hidden_params(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(disc, "_replay_impl", lambda *a, **k: _resp("same static page"))
    out = disc._param_discover_impl("https://x/", None, None, 10)
    assert out["found_count"] == 0


def test_param_mining_from_page(monkeypatch: pytest.MonkeyPatch) -> None:
    html = '<input name="secret_flag"><a href="/x?hidden_toggle=1">'
    monkeypatch.setattr(disc, "_replay_impl", lambda *a, **k: _resp(html))
    out = disc._param_discover_impl("https://x/", None, None, 10)
    assert "secret_flag" in out["mined_from_page"] or "hidden_toggle" in out["mined_from_page"]


# ---- content_discover ----------------------------------------------------


def test_content_finds_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if "nope" in url:
            return _resp("404", status=404)
        if url.rstrip("/").endswith("/admin"):
            return _resp("Admin panel", status=200)
        return _resp("nf", status=404)

    monkeypatch.setattr(disc, "_replay_impl", _fake)
    out = disc._content_discover_impl("https://x", None, 10)
    assert any(f["path"] == "/admin" for f in out["found"])


def test_content_reports_protected_401(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if "nope" in url:
            return _resp("404", status=404)
        if url.rstrip("/").endswith("/actuator"):
            return _resp("unauthorized", status=401)
        return _resp("nf", status=404)

    monkeypatch.setattr(disc, "_replay_impl", _fake)
    out = disc._content_discover_impl("https://x", None, 10)
    assert any(f["path"] == "/actuator" and f["status"] == 401 for f in out["found"])


def test_content_spa_catch_all_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(disc, "_replay_impl", lambda *a, **k: _resp("<html>app</html>", status=200))
    out = disc._content_discover_impl("https://x", None, 10)
    assert out["found_count"] == 0
    assert out["spa_catch_all"] is True
