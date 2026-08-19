"""backend_rules_probe (Supabase/Firebase) and frontend_secret_scan."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from strix.tools.backend_rules_probe import tools as baas
from strix.tools.frontend_secret_scan import tools as secrets


def _resp(status: int = 200, body: str = "", final_url: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"success": True, "status_code": status, "body": body}
    if final_url:
        out["final_url"] = final_url
    return out


# ---- backend_rules_probe -------------------------------------------------


def test_supabase_open_rls_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        baas, "_replay_impl", lambda *a, **k: _resp(200, json.dumps([{"id": 1, "email": "a@b.c"}]))
    )
    out = baas._backend_rules_probe_impl(
        "supabase", "https://x.supabase.co", "anon-key", ["users"], 10
    )
    assert out["possible_open_rules"] is True
    assert out["results"][0]["rows_returned"] == 1


def test_supabase_protected_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baas, "_replay_impl", lambda *a, **k: _resp(200, "[]"))
    out = baas._backend_rules_probe_impl(
        "supabase", "https://x.supabase.co", "anon-key", ["users"], 10
    )
    assert out["possible_open_rules"] is False


def test_supabase_requires_anon_key() -> None:
    out = baas._backend_rules_probe_impl("supabase", "https://x.supabase.co", None, None, 10)
    assert out["success"] is False


def test_firebase_open_rules_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baas, "_replay_impl", lambda *a, **k: _resp(200, '{"secret":"data"}'))
    out = baas._backend_rules_probe_impl("firebase", "https://x.firebaseio.com", None, ["/"], 10)
    assert out["possible_open_rules"] is True


def test_auto_provider_picks_firebase() -> None:
    out = baas._backend_rules_probe_impl("auto", "https://x.firebaseio.com", None, [], 10)
    assert out["provider"] == "firebase"


# ---- frontend_secret_scan ------------------------------------------------


def _make_jwt(role: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"role": role}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.aaaaaa"


def test_secret_scan_finds_stripe_key_in_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    html = '<html><script src="/app.js"></script></html>'
    bundle = 'const k = "sk_live_' + "a" * 30 + '";'

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith("app.js"):
            return _resp(200, bundle)
        return _resp(200, html, final_url="https://x.example/")

    monkeypatch.setattr(secrets, "_replay_impl", _fake)
    out = secrets._frontend_secret_scan_impl("https://x.example/", validate=False, timeout=10)
    assert out["possible_secret_leak"] is True
    types = {f["type"] for f in out["findings"]}
    assert "stripe_secret_key" in types


def test_secret_scan_grades_service_role_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    jwt = _make_jwt("service_role")
    html = f'<script>const key="{jwt}"</script>'
    monkeypatch.setattr(
        secrets, "_replay_impl", lambda *a, **k: _resp(200, html, final_url="https://x/")
    )
    out = secrets._frontend_secret_scan_impl("https://x/", validate=False, timeout=10)
    sev = {f["type"]: f["severity"] for f in out["findings"]}
    assert sev.get("supabase_service_role_key") == "critical"


def test_secret_scan_clean_page(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        secrets,
        "_replay_impl",
        lambda *a, **k: _resp(200, "<html>nothing here</html>", final_url="https://x/"),
    )
    out = secrets._frontend_secret_scan_impl("https://x/", validate=False, timeout=10)
    assert out["possible_secret_leak"] is False


def test_secret_scan_validate_marks_live(monkeypatch: pytest.MonkeyPatch) -> None:
    html = 'const k = "sk_live_' + "b" * 30 + '";'

    def _fake(method: str, url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if "stripe.com" in url:
            return _resp(200)  # live key
        return _resp(200, html, final_url="https://x/")

    monkeypatch.setattr(secrets, "_replay_impl", _fake)
    out = secrets._frontend_secret_scan_impl("https://x/", validate=True, timeout=10)
    stripe = next(f for f in out["findings"] if f["type"] == "stripe_secret_key")
    assert stripe["live"] is True
