"""injection_fuzz (SQLi/SSTI/XSS/SSRF) and prompt_injection_probe."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.injection_fuzz import tools as fuzz
from strix.tools.prompt_injection import tools as pinj


def _resp(body: str = "", elapsed_ms: float = 50.0, status: int = 200) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body, "elapsed_ms": elapsed_ms}


# ---- injection_fuzz ------------------------------------------------------


def test_time_based_sqli_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(
        method: str, url: str, headers: Any, body: Any, timeout: int, **k: Any
    ) -> dict[str, Any]:
        # slow only when a SLEEP/sleep payload rides the query
        if "SLEEP" in url or "sleep" in url:
            return _resp(elapsed_ms=5200)
        return _resp(elapsed_ms=40)

    monkeypatch.setattr(fuzz, "_replay_impl", _fake)
    out = fuzz._injection_fuzz_impl("GET", "https://x/item", ["id"], None, None, "query", None, 12)
    assert out["possible_injection"] is True
    assert any(f["family"] in {"sql_time", "cmd_time"} for f in out["findings"])


def test_ssti_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    from urllib.parse import parse_qs, urlparse

    def _fake(
        method: str, url: str, headers: Any, body: Any, timeout: int, **k: Any
    ) -> dict[str, Any]:
        # decode the query value; a template engine would evaluate 1337*1337
        values = parse_qs(urlparse(url).query)
        injected = next((v[0] for v in values.values()), "")
        return _resp(body="result=1787569" if "1337*1337" in injected else "hello")

    monkeypatch.setattr(fuzz, "_replay_impl", _fake)
    out = fuzz._injection_fuzz_impl("GET", "https://x/p", ["name"], None, None, "query", None, 12)
    assert any(f["family"] == "ssti" for f in out["findings"])


def test_xss_reflection_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(
        method: str, url: str, headers: Any, body: Any, timeout: int, **k: Any
    ) -> dict[str, Any]:
        # reflect the raw query value back into the body
        from urllib.parse import parse_qs, urlparse

        q = parse_qs(urlparse(url).query)
        val = next((v[0] for v in q.values()), "")
        return _resp(body=f"<div>{val}</div>")

    monkeypatch.setattr(fuzz, "_replay_impl", _fake)
    out = fuzz._injection_fuzz_impl("GET", "https://x/s", ["q"], None, None, "query", None, 12)
    assert any(f["family"] == "xss" for f in out["findings"])


def test_clean_param_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fuzz, "_replay_impl", lambda *a, **k: _resp(body="static", elapsed_ms=30))
    out = fuzz._injection_fuzz_impl("GET", "https://x/s", ["q"], None, None, "query", None, 12)
    assert out["possible_injection"] is False


def test_ssrf_payload_sent_when_oast_given(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fuzz, "_replay_impl", lambda *a, **k: _resp(body="ok"))
    out = fuzz._injection_fuzz_impl(
        "GET", "https://x/f", ["url"], None, None, "query", "abc.oast.pro", 12
    )
    assert any(f["family"] == "ssrf" for f in out["findings"])


def test_fuzz_empty_params_rejected() -> None:
    assert (
        fuzz._injection_fuzz_impl("GET", "https://x", [], None, None, "query", None, 12)["success"]
        is False
    )


# ---- prompt_injection_probe ----------------------------------------------


def test_prompt_injection_canary_echo_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pinj,
        "_replay_impl",
        lambda *a, **k: _resp(body="Sure: ZXQ7CANARY42 and my system prompt is..."),
    )
    out = pinj._prompt_injection_impl("https://x/chat", "message", None, None, 10)
    assert out["possible_prompt_injection"] is True
    assert any(r.get("leak_signals") for r in out["results"])


def test_prompt_injection_resistant_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pinj, "_replay_impl", lambda *a, **k: _resp(body="I can't help with that."))
    out = pinj._prompt_injection_impl("https://x/chat", "message", None, None, 10)
    assert out["possible_prompt_injection"] is False


def test_prompt_injection_empty_url_rejected() -> None:
    assert pinj._prompt_injection_impl("", "message", None, None, 10)["success"] is False
