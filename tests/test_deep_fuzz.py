"""deep_fuzz: error-signature / SSTI / traversal / time / encoding + verb tampering."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from strix.tools.deep_fuzz import tools as df


def _resp(body: str = "", elapsed_ms: float = 40.0, status: int = 200) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body, "elapsed_ms": elapsed_ms}


def _injected(url: str) -> str:
    q = parse_qs(urlparse(url).query)
    return next((v[0] for v in q.values()), "")


def test_sql_error_signature_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        val = _injected(url)
        if any(c in val for c in ("'", '"', ")")):
            return _resp("You have an error in your SQL syntax near '''")
        return _resp("normal page")

    monkeypatch.setattr(df, "_replay_impl", _fake)
    out = df._deep_fuzz_impl("GET", "https://x/item", ["id"], None, None, "query", 300, 12)
    assert out["possible_injection"] is True
    assert any(f["family"] == "sqli" for f in out["findings"])


def test_ssti_multi_engine_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        val = _injected(url)
        # decoded value contains the math → engine evaluates it
        return _resp("2099597" if "1447*1451" in val else "hi")

    monkeypatch.setattr(df, "_replay_impl", _fake)
    out = df._deep_fuzz_impl("GET", "https://x/p", ["q"], None, None, "query", 300, 12)
    assert any(f["family"] == "ssti" for f in out["findings"])


def test_traversal_signature_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        val = _injected(url)
        return _resp("root:x:0:0:root:/root:/bin/bash" if "passwd" in val else "hi")

    monkeypatch.setattr(df, "_replay_impl", _fake)
    out = df._deep_fuzz_impl("GET", "https://x/file", ["path"], None, None, "query", 300, 12)
    assert any(f["family"] == "traversal" for f in out["findings"])


def test_time_based_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        val = _injected(url)
        slow = "SLEEP" in val or "pg_sleep" in val or "WAITFOR" in val or "sleep" in val
        return _resp("ok", elapsed_ms=6000 if slow else 30)

    monkeypatch.setattr(df, "_replay_impl", _fake)
    out = df._deep_fuzz_impl("GET", "https://x/item", ["id"], None, None, "query", 300, 12)
    assert any("time-based" in f["evidence"] for f in out["findings"])


def test_encoding_variants_are_attempted(monkeypatch: pytest.MonkeyPatch) -> None:
    # Capture every URL sent and confirm deep_fuzz tries encoded payload variants
    # (double-URL-encoded braces = %25257B), not just the raw payload.
    sent: list[str] = []

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        sent.append(url)
        return _resp("nothing")

    monkeypatch.setattr(df, "_replay_impl", _fake)
    df._deep_fuzz_impl("GET", "https://x/p", ["q"], None, None, "query", 300, 12)
    assert any("%25257B" in u for u in sent)  # double-URL-encoded '{'


def test_clean_param_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(df, "_replay_impl", lambda *a, **k: _resp("static content", elapsed_ms=30))
    out = df._deep_fuzz_impl("GET", "https://x/p", ["q"], None, None, "query", 300, 12)
    assert out["possible_injection"] is False


def test_budget_truncates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(df, "_replay_impl", lambda *a, **k: _resp("x", elapsed_ms=10))
    out = df._deep_fuzz_impl("GET", "https://x/p", ["a", "b", "c"], None, None, "query", 25, 12)
    assert out["truncated"] is True


def test_empty_params_rejected() -> None:
    assert (
        df._deep_fuzz_impl("GET", "https://x", [], None, None, "query", 300, 12)["success"] is False
    )
