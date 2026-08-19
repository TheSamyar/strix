"""error_leak_probe, sourcemap_recover, signed_url_probe."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.tools.error_leak import tools as el
from strix.tools.signed_url import tools as su
from strix.tools.sourcemap import tools as sm


def _resp(body: str = "", status: int = 200, final_url: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"success": True, "status_code": status, "body": body}
    if final_url:
        out["final_url"] = final_url
    return out


# ---- error_leak_probe ----------------------------------------------------


def test_error_leak_stack_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if "id=" in url and "id=1" not in url.split("id=", maxsplit=1)[0]:  # any malformed id
            return _resp('Traceback (most recent call last):\n  File "/app/main.py", line 5', 500)
        return _resp("ok")

    monkeypatch.setattr(el, "_replay_impl", _fake)
    out = el._error_leak_impl("GET", "https://x/item", "id", None, 10)
    assert out["possible_error_leak"] is True
    assert any("stack_trace" in f["leaked"] for f in out["findings"])


def test_error_leak_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(el, "_replay_impl", lambda *a, **k: _resp("generic error", 400))
    out = el._error_leak_impl("GET", "https://x/item", "id", None, 10)
    assert out["possible_error_leak"] is False


# ---- sourcemap_recover ---------------------------------------------------


def test_sourcemap_recovered_with_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    smap = json.dumps(
        {
            "version": 3,
            "sources": ["src/api.ts"],
            "sourcesContent": [
                'const k = "sk_live_' + "a" * 30 + '"; fetch("/api/internal/users")'
            ],
        }
    )

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith(".map"):
            return _resp(smap)
        if url.endswith("app.js"):
            return _resp("code //# sourceMappingURL=app.js.map")
        return _resp('<script src="/app.js"></script>', final_url="https://x/")

    monkeypatch.setattr(sm, "_replay_impl", _fake)
    out = sm._sourcemap_impl("https://x/", 10)
    assert out["possible_source_exposure"] is True
    assert any(s["type"] == "stripe_secret_key" for s in out["secrets"])
    assert "/api/internal/users" in out["internal_routes"]


def test_sourcemap_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith(".map"):
            return _resp("not found", 404)
        return _resp('<script src="/app.js"></script>', final_url="https://x/")

    monkeypatch.setattr(sm, "_replay_impl", _fake)
    out = sm._sourcemap_impl("https://x/", 10)
    assert out["possible_source_exposure"] is False


# ---- signed_url_probe ----------------------------------------------------


def test_signature_not_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    # both signed and stripped requests return the same file
    monkeypatch.setattr(su, "_replay_impl", lambda *a, **k: _resp("FILE-CONTENT"))
    out = su._signed_url_impl(["https://cdn/x/file.pdf?signature=abc&expires=123"], 10)
    assert out["possible_leak"] is True
    assert any("signature not enforced" in f for f in out["results"][0]["findings"])


def test_sequential_object_id(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        # each numeric id returns distinct content
        return _resp(f"file-{url.rsplit('/', 1)[-1]}")

    monkeypatch.setattr(su, "_replay_impl", _fake)
    out = su._signed_url_impl(["https://cdn/files/100?se=1&sig=z"], 10)
    assert any("sequential object id" in f for f in out["results"][0]["findings"])


def test_signed_url_empty_rejected() -> None:
    assert su._signed_url_impl([], 10)["success"] is False
