"""suggest_chains, auth_crawl, cache_deception_probe, request_smuggling_probe."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.auth_crawl import tools as crawl
from strix.tools.chain_suggest.tools import _chain_suggest_impl
from strix.tools.desync import tools as desync


# ---- suggest_chains ------------------------------------------------------


def test_chain_from_ssrf_finding() -> None:
    findings = [{"id": "vuln-1", "title": "SSRF in image proxy", "cwe": "CWE-918"}]
    out = _chain_suggest_impl(findings)
    names = [c["name"] for c in out["chains"]]
    assert any("cloud metadata" in n for n in names)
    assert out["chains"][0]["builds_on"] == ["vuln-1"]


def test_chain_requires_two_findings_for_xss_session() -> None:
    only_xss = _chain_suggest_impl([{"id": "v1", "title": "Reflected XSS", "cwe": "CWE-79"}])
    assert not any("account takeover" in c["name"] for c in only_xss["chains"])
    both = _chain_suggest_impl(
        [
            {"id": "v1", "title": "Reflected XSS", "cwe": "CWE-79"},
            {"id": "v2", "title": "Session cookie without HttpOnly", "cwe": "CWE-1004"},
        ]
    )
    assert any("account takeover" in c["name"] for c in both["chains"])


def test_no_findings_no_chains() -> None:
    out = _chain_suggest_impl([])
    assert out["chains"] == []


# ---- auth_crawl ----------------------------------------------------------


def test_crawl_discovers_links_and_api(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {
        "https://x/": '<a href="/dash">d</a><script>fetch("/api/me")</script>',
        "https://x/dash": '<a href="/settings">s</a><form action="/api/update"></form>',
        "https://x/settings": "<html>done</html>",
    }

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        body = pages.get(url.rstrip("/") if url != "https://x/" else url, "")
        return {"success": True, "status_code": 200, "body": body, "final_url": url}

    monkeypatch.setattr(crawl, "_replay_impl", _fake)
    out = crawl._crawl("https://x/", {"Cookie": "s=1"}, 40, 10)
    assert "https://x/api/me" in out["endpoints"]
    assert "https://x/api/update" in out["endpoints"]
    assert out["pages_crawled"] >= 2


def test_crawl_stays_in_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        body = (
            '<a href="https://evil.com/x">e</a><a href="/local">l</a>'
            if url == "https://x/"
            else ""
        )
        return {"success": True, "status_code": 200, "body": body, "final_url": url}

    monkeypatch.setattr(crawl, "_replay_impl", _fake)
    out = crawl._crawl("https://x/", None, 40, 10)
    assert all("evil.com" not in e for e in out["endpoints"])


# ---- cache_deception_probe -----------------------------------------------


def test_cache_deception_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    private = "SECRET-USER-DATA-123"

    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        # both authed base and UNauthed crafted request return the private body
        return {
            "success": True,
            "status_code": 200,
            "body": private,
            "response_headers": {"X-Cache": "HIT"},
        }

    monkeypatch.setattr(desync, "_replay_impl", _fake)
    out = desync._cache_deception_impl("https://x/account", {"Cookie": "s=1"}, 10)
    assert out["possible_cache_deception"] is True


def test_cache_deception_not_flagged_when_anon_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        if headers:  # authed base
            return {"success": True, "status_code": 200, "body": "PRIVATE", "response_headers": {}}
        return {"success": True, "status_code": 403, "body": "denied", "response_headers": {}}

    monkeypatch.setattr(desync, "_replay_impl", _fake)
    out = desync._cache_deception_impl("https://x/account", {"Cookie": "s=1"}, 10)
    assert out["possible_cache_deception"] is False


# ---- request_smuggling_probe ---------------------------------------------


def test_smuggling_flagged_when_probe_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(host: str, port: int, tls: bool, payload: bytes, timeout: int) -> dict[str, Any]:
        hung = b"Transfer-Encoding" in payload  # desync probes hang
        return {"ok": True, "elapsed": 6.0 if hung else 0.1, "timed_out": hung, "bytes": 0}

    monkeypatch.setattr(desync, "_raw_exchange", _fake)
    out = desync._request_smuggling_impl("https://x/", 6)
    assert out["possible_request_smuggling"] is True


def test_smuggling_not_flagged_when_all_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        desync,
        "_raw_exchange",
        lambda *a, **k: {"ok": True, "elapsed": 0.1, "timed_out": False, "bytes": 100},
    )
    out = desync._request_smuggling_impl("https://x/", 6)
    assert out["possible_request_smuggling"] is False
