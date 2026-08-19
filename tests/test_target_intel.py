"""profile_target, plan_tests, and endpoint_risk_rank — the target-intelligence layer."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

import strix.report.state as report_state_mod
from strix.tools.endpoint_risk.tools import _endpoint_risk_rank_impl
from strix.tools.plan_tests.tools import _plan_tests_impl
from strix.tools.profile_target import tools as profiler


def _resp(
    status: int = 200,
    body: str = "",
    final_url: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "success": True,
        "status_code": status,
        "body": body,
        "final_url": final_url or "https://x/",
        "response_headers": headers or {},
    }


# ---- profile_target ------------------------------------------------------


def test_profile_detects_nextjs_and_supabase(monkeypatch: pytest.MonkeyPatch) -> None:
    anon = _make_anon_jwt()
    html = (
        '<html><script src="/_next/static/app.js"></script>'
        "<script>window.__NEXT_DATA__={}</script></html>"
    )
    bundle = f'const c = createClient("https://abcdefghijklmnop.supabase.co", "{anon}")'

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith("app.js"):
            return _resp(body=bundle)
        return _resp(body=html, final_url="https://x/")

    monkeypatch.setattr(profiler, "_replay_impl", _fake)
    out = profiler._profile_target_impl("https://x/", 10)
    assert out["framework"] == "nextjs"
    assert "supabase" in out["baas"]
    assert out["supabase_url"] == "https://abcdefghijklmnop.supabase.co"
    assert out["supabase_anon_key"] == anon


def test_profile_detects_graphql_via_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        profiler,
        "_replay_impl",
        lambda *a, **k: _resp(body="fetch('/graphql'); const x = data.__typename"),
    )
    out = profiler._profile_target_impl("https://x/", 10)
    assert "graphql" in out["api"]


def _make_anon_jwt() -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"role": "anon"}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig123456"


# ---- plan_tests ----------------------------------------------------------


def test_plan_includes_baseline_and_supabase() -> None:
    report_state_mod._global_report_state = None
    profile = {
        "baas": ["supabase"],
        "api": ["graphql"],
        "auth": ["jwt"],
        "supabase_url": "u",
        "supabase_anon_key": "k",
    }
    out = _plan_tests_impl(profile, "mcp-plan-test", seed=False)
    areas = [rec["area"] for rec in out["plan"]]
    assert any("Access control" in a for a in areas)  # baseline
    assert any("Supabase" in a for a in areas)
    assert any("GraphQL" in a for a in areas)
    assert any("JWT" in a for a in areas)
    assert out["supabase_ready"] is True
    report_state_mod._global_report_state = None


def test_plan_rejects_non_dict() -> None:
    out = _plan_tests_impl({}, "mcp", seed=False)
    assert out["success"] is False


# ---- endpoint_risk_rank --------------------------------------------------


def test_risk_rank_orders_by_attack_surface() -> None:
    endpoints = [
        {"method": "GET", "url": "/about"},
        {"method": "DELETE", "url": "/api/admin/users/42"},
        {"method": "GET", "url": "/api/fetch?url=http://x"},
    ]
    out = _endpoint_risk_rank_impl(endpoints)
    ranked = out["ranked"]
    assert ranked[0]["score"] > ranked[-1]["score"]
    assert ranked[-1]["endpoint"] == "/about"  # lowest surface
    admin = next(r for r in ranked if "admin" in r["endpoint"])
    assert any("auth/admin" in reason for reason in admin["reasons"])


def test_risk_rank_accepts_plain_strings() -> None:
    out = _endpoint_risk_rank_impl(["/api/orders/1", "/static/logo.png"])
    assert out["count"] == 2
    assert out["top"] == "/api/orders/1"


def test_risk_rank_empty_rejected() -> None:
    assert _endpoint_risk_rank_impl([])["success"] is False


def test_profile_extracts_endpoints_from_page_and_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    html = '<html><script src="/app.js"></script></html>'
    bundle = (
        'fetch("/api/users/1");axios.post("/api/orders");const g="/graphql";'
        'u="https://x/api/admin";ext="https://evil.com/api/steal";'
        'css="/assets/main.css";page="/about";'
    )

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith("app.js"):
            return _resp(body=bundle)
        return _resp(body=html, final_url="https://x/")

    monkeypatch.setattr(profiler, "_replay_impl", _fake)
    out = profiler._profile_target_impl("https://x/", 10)
    eps = out["endpoints"]
    assert "/api/users/1" in eps
    assert "/api/orders" in eps
    assert "/graphql" in eps
    assert "https://x/api/admin" in eps
    # noise + cross-host excluded
    assert "/assets/main.css" not in eps
    assert "/about" not in eps
    assert "https://evil.com/api/steal" not in eps
