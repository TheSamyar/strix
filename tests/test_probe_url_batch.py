"""url_batch: passive single-URL probes accept a urls list — same per-URL logic."""

from __future__ import annotations

from typing import Any

from strix.tools import batching
from strix.tools.cors_probe import tools as cors
from strix.tools.error_leak import tools as error_leak
from strix.tools.security_headers import tools as security_headers


def _fake_impl(url: str, timeout: int) -> dict[str, Any]:
    return {"success": True, "seen_timeout": timeout, "flag": url.endswith("/leak")}


def test_url_batch_loops_impl_and_echoes_url() -> None:
    out = batching.url_batch(_fake_impl, ["https://x/a", "https://x/leak"], 15)
    assert out["success"] is True
    assert out["count"] == 2
    assert out["results"][0]["url"] == "https://x/a"
    assert out["results"][1]["flag"] is True
    assert "dropped" not in out


def test_url_batch_caps_and_reports_dropped() -> None:
    urls = [f"https://x/{i}" for i in range(40)]
    out = batching.url_batch(_fake_impl, urls, 15, cap=25)
    assert out["count"] == 25
    assert out["dropped"] == 15


def test_url_batch_skips_blank_urls() -> None:
    out = batching.url_batch(_fake_impl, ["", "  ", "https://x/a"], 15)
    assert out["count"] == 1
    assert out["results"][0]["url"] == "https://x/a"


def test_single_url_path_unchanged(monkeypatch: Any) -> None:
    # single-URL impl still returns the bare object (no results wrapper)
    def _fake_replay(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"success": True, "response_headers": {}}

    monkeypatch.setattr(security_headers, "_replay_impl", _fake_replay)
    out = security_headers._security_headers_impl("https://x", 15)
    assert "results" not in out
    assert out["success"] is True
    assert "missing_headers" in out


def _fake_cors(url: str, _method: str, _origins: list[str] | None, _timeout: int) -> dict[str, Any]:
    return {"success": True, "hit": url}


def test_cors_probe_urls_returns_count_2(monkeypatch: Any) -> None:
    monkeypatch.setattr(cors, "_cors_probe_impl", _fake_cors)
    out = cors._cors_probe_run("https://unused", "GET", None, 10, ["https://a", "https://b"])
    assert out["count"] == 2
    assert out["results"][0]["url"] == "https://a"
    assert out["results"][1]["hit"] == "https://b"


def _fake_error(
    _method: str, url: str, _param: str, _headers: dict[str, str] | None, _timeout: int
) -> dict[str, Any]:
    return {"success": True, "hit": url}


def test_error_leak_urls_returns_count_2(monkeypatch: Any) -> None:
    monkeypatch.setattr(error_leak, "_error_leak_impl", _fake_error)
    out = error_leak._error_leak_run(
        "GET", "https://unused", "id", None, 10, ["https://a", "https://b"]
    )
    assert out["count"] == 2
    assert [r["url"] for r in out["results"]] == ["https://a", "https://b"]
