"""mass_assignment_probe, redirect_probe, security_headers_probe."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.tools.mass_assignment.tools import _mass_assignment_impl
from strix.tools.redirect_probe import tools as redir
from strix.tools.security_headers.tools import _security_headers_impl


def _resp(
    body: str = "", status: int = 200, headers: dict[str, str] | None = None
) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body, "response_headers": headers or {}}


# ---- mass_assignment_probe -----------------------------------------------


def test_mass_assignment_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    import strix.tools.mass_assignment.tools as ma

    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        sent = json.loads(body)
        # server reflects back the object it created, including is_admin
        return _resp(
            json.dumps({"id": 1, "name": sent.get("name"), "is_admin": sent.get("is_admin")})
        )

    monkeypatch.setattr(ma, "_replay_impl", _fake)
    out = _mass_assignment_impl("POST", "https://x/signup", {"name": "bob"}, ["is_admin"], None, 10)
    assert out["possible_mass_assignment"] is True
    assert "is_admin" in out["fields_accepted"]


def test_mass_assignment_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    import strix.tools.mass_assignment.tools as ma

    # server ignores privileged fields — returns only allowed ones
    monkeypatch.setattr(
        ma, "_replay_impl", lambda *a, **k: _resp(json.dumps({"id": 1, "name": "bob"}))
    )
    out = _mass_assignment_impl("POST", "https://x/signup", {"name": "bob"}, ["is_admin"], None, 10)
    assert out["possible_mass_assignment"] is False


# ---- redirect_probe ------------------------------------------------------


def test_open_redirect_via_location(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        if "redirect=" in url:
            return _resp(status=302, headers={"Location": "https://evil-strix.example/pwn"})
        return _resp()

    monkeypatch.setattr(redir, "_replay_impl", _fake)
    out = redir._redirect_probe_impl("https://x/login", ["redirect"], None, 10)
    assert out["possible_open_redirect"] is True


def test_host_injection_reflected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        host = (headers or {}).get("Host", "")
        return _resp(body=f"reset link: https://{host}/reset?t=1")

    monkeypatch.setattr(redir, "_replay_impl", _fake)
    out = redir._redirect_probe_impl("https://x/reset", [], None, 10)
    assert out["possible_host_injection"] is True


def test_no_redirect_no_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redir, "_replay_impl", lambda *a, **k: _resp(body="nothing reflected here"))
    out = redir._redirect_probe_impl("https://x/login", ["redirect"], None, 10)
    assert out["possible_open_redirect"] is False
    assert out["possible_host_injection"] is False


# ---- security_headers_probe ----------------------------------------------


def test_missing_headers_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    import strix.tools.security_headers.tools as sh

    monkeypatch.setattr(sh, "_replay_impl", lambda *a, **k: _resp(headers={"Server": "nginx"}))
    out = _security_headers_impl("https://x/", 10)
    missing = {m["header"] for m in out["missing_headers"]}
    assert "content-security-policy" in missing
    assert "strict-transport-security" in missing
    assert any("frame" in h for h in missing)
    assert out["possible_hardening_gaps"] is True


def test_cookie_flags_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    import strix.tools.security_headers.tools as sh

    monkeypatch.setattr(
        sh, "_replay_impl", lambda *a, **k: _resp(headers={"Set-Cookie": "session=abc; Path=/"})
    )
    out = _security_headers_impl("https://x/", 10)
    assert any("HttpOnly" in i for i in out["cookie_issues"])
    assert any("SameSite" in i for i in out["cookie_issues"])


def test_well_hardened_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    import strix.tools.security_headers.tools as sh

    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    monkeypatch.setattr(sh, "_replay_impl", lambda *a, **k: _resp(headers=headers))
    out = _security_headers_impl("https://x/", 10)
    assert out["possible_hardening_gaps"] is False
