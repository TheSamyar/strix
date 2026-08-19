"""ssr_leak_scan, data_exposure_probe, storage_probe, cache_privacy_probe."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.cache_privacy import tools as cachep
from strix.tools.data_exposure.tools import _data_exposure_impl
from strix.tools.ssr_leak import tools as ssr
from strix.tools.storage_probe import tools as storep


def _resp(
    body: str = "", status: int = 200, headers: dict[str, str] | None = None
) -> dict[str, Any]:
    return {
        "success": True,
        "status_code": status,
        "body": body,
        "final_url": "https://x/",
        "response_headers": headers or {},
    }


# ---- ssr_leak_scan -------------------------------------------------------


def test_ssr_leak_flags_embedded_pii(monkeypatch: pytest.MonkeyPatch) -> None:
    html = (
        '<html><script id="__NEXT_DATA__" type="application/json">'
        '{"props":{"user":{"email":"victim@corp.com","is_admin":true}}}'
        "</script></html>"
    )
    monkeypatch.setattr(ssr, "_replay_impl", lambda *a, **k: _resp(html))
    out = ssr._ssr_leak_impl("https://x/", 10)
    assert out["possible_ssr_leak"] is True
    blob = next(r for r in out["results"] if r["source"] == "__NEXT_DATA__")
    assert "is_admin" in blob["sensitive_fields"]
    assert blob["emails_found"] >= 1


def test_ssr_leak_clean_page(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssr, "_replay_impl", lambda *a, **k: _resp("<html>hi there</html>"))
    out = ssr._ssr_leak_impl("https://x/", 10)
    assert out["possible_ssr_leak"] is False


# ---- data_exposure_probe -------------------------------------------------


def test_excessive_exposure_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    import strix.tools.data_exposure.tools as de

    body = '{"id":1,"name":"Bob","password_hash":"abc","stripe_id":"cus_1","is_admin":false}'
    monkeypatch.setattr(de, "_replay_impl", lambda *a, **k: _resp(body))
    out = _data_exposure_impl("GET", "https://x/api/me", None, 10)
    assert out["possible_excessive_exposure"] is True
    assert "password_hash" in out["sensitive_fields"]
    assert "stripe_id" in out["sensitive_fields"]


def test_clean_response_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    import strix.tools.data_exposure.tools as de

    monkeypatch.setattr(de, "_replay_impl", lambda *a, **k: _resp('{"id":1,"name":"Bob"}'))
    out = _data_exposure_impl("GET", "https://x/api/me", None, 10)
    assert out["possible_excessive_exposure"] is False


# ---- storage_probe -------------------------------------------------------


def test_storage_exposed_env(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if "strix-nope" in url:
            return _resp("404 not found", status=404)
        if url.endswith("/.env"):
            return _resp("SECRET_KEY=abc123", status=200)
        return _resp("", status=404)

    monkeypatch.setattr(storep, "_replay_impl", _fake)
    out = storep._storage_probe_impl("https://x", None, 10)
    assert out["possible_exposure"] is True
    assert any(e["path"] == "/.env" for e in out["exposed"])


def test_storage_spa_catch_all_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every path (incl. junk) returns the same SPA index → no real exposure.
    monkeypatch.setattr(
        storep, "_replay_impl", lambda *a, **k: _resp("<html>app</html>", status=200)
    )
    out = storep._storage_probe_impl("https://x", None, 10)
    assert out["possible_exposure"] is False
    assert out["spa_catch_all"] is True


# ---- cache_privacy_probe -------------------------------------------------


def test_cache_privacy_flags_public_authed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cachep,
        "_replay_impl",
        lambda *a, **k: _resp("data", headers={"Cache-Control": "public, max-age=60"}),
    )
    out = cachep._cache_privacy_impl("https://x/account", {"Cookie": "s=1"}, 10)
    assert out["authenticated_response_cacheable"] is True
    assert out["possible_privacy_leak"] is True


def test_cache_privacy_flags_token_in_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cachep, "_replay_impl", lambda *a, **k: _resp("data", headers={"Cache-Control": "no-store"})
    )
    out = cachep._cache_privacy_impl("https://x/cb?access_token=eyJabc.def.ghi", None, 10)
    assert "access_token" in out["token_params_in_url"]
    assert out["possible_privacy_leak"] is True


def test_cache_privacy_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cachep,
        "_replay_impl",
        lambda *a, **k: _resp("data", headers={"Cache-Control": "no-store, private"}),
    )
    out = cachep._cache_privacy_impl("https://x/account", {"Cookie": "s=1"}, 10)
    assert out["possible_privacy_leak"] is False
