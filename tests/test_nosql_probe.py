"""nosql_probe: MongoDB operator injection auth-bypass via differential oracle."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.tools.nosql_probe import tools as nt


def test_auth_bypass_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    def vuln(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        data = json.loads(body) if body else {}
        if isinstance(data.get("password"), dict):  # operator injected → bypass
            return {"success": True, "status_code": 302, "response_headers": {"Set-Cookie": "s=1"}, "body": ""}
        return {"success": True, "status_code": 401, "response_headers": {}, "body": "invalid"}

    monkeypatch.setattr(nt, "_replay_impl", vuln)
    out = nt._nosql_probe_impl("POST", "https://x/login", "password", "body", {"username": "a"}, None, 15)
    assert out["possible_nosqli"] is True
    assert any(f["severity"] == "critical" for f in out["findings"])


def test_safe_endpoint_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def safe(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        return {"success": True, "status_code": 401, "response_headers": {}, "body": "invalid"}

    monkeypatch.setattr(nt, "_replay_impl", safe)
    out = nt._nosql_probe_impl("POST", "https://x/login", "password", "body", {"username": "a"}, None, 15)
    assert out["finding_count"] == 0


def test_query_bracket_notation(monkeypatch: pytest.MonkeyPatch) -> None:
    def vuln_q(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        if any(op in url for op in ("[$ne]", "[$gt]", "[$regex]", "[$nin]")):
            return {"success": True, "status_code": 200, "response_headers": {"Set-Cookie": "s=1"}, "body": "ok"}
        return {"success": True, "status_code": 403, "response_headers": {}, "body": "denied"}

    monkeypatch.setattr(nt, "_replay_impl", vuln_q)
    out = nt._nosql_probe_impl("GET", "https://x/api?", "user", "query", None, None, 15)
    assert out["possible_nosqli"] is True


def test_field_required() -> None:
    assert nt._nosql_probe_impl("POST", "https://x", "", "body", None, None, 15)["success"] is False
