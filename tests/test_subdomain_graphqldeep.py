"""subdomain_takeover, graphql_field_leak, graphql_dos."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.tools.graphql_deep import tools as gd
from strix.tools.subdomain_takeover import tools as st


def _resp(body: str = "", status: int = 200, elapsed_ms: float = 40.0) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body, "elapsed_ms": elapsed_ms}


# ---- subdomain_takeover --------------------------------------------------


def test_takeover_s3_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        st, "_replay_impl", lambda *a, **k: _resp("<Error>NoSuchBucket</Error>", 404)
    )
    out = st._subdomain_takeover_impl(["files.example.com"], 10)
    assert out["possible_takeover"] is True
    assert out["vulnerable"][0]["service"] == "aws_s3"


def test_takeover_live_site_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "_replay_impl", lambda *a, **k: _resp("<html>Welcome</html>", 200))
    out = st._subdomain_takeover_impl(["app.example.com"], 10)
    assert out["possible_takeover"] is False


# ---- graphql_field_leak --------------------------------------------------

_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {
                "name": "Query",
                "fields": [{"name": "me", "type": {"name": "User", "kind": "OBJECT"}}],
            },
            "types": [
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "id", "type": {"name": "ID", "kind": "SCALAR"}},
                        {"name": "email", "type": {"name": "String", "kind": "SCALAR"}},
                        {"name": "password", "type": {"name": "String", "kind": "SCALAR"}},
                    ],
                }
            ],
        }
    }
}


def test_graphql_field_leak_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        q = json.loads(body)["query"]
        if "__schema" in q:
            return _resp(json.dumps(_SCHEMA))
        # querying me{email password} returns data
        return _resp(json.dumps({"data": {"me": {"email": "v@x.com", "password": "h"}}}))

    monkeypatch.setattr(gd, "_replay_impl", _fake)
    out = gd._graphql_field_leak_impl("https://x/graphql", None, 10)
    assert out["possible_field_leak"] is True
    assert "password" in out["schema_sensitive_fields"]
    assert out["confirmed_queries"]


def test_graphql_field_leak_introspection_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gd, "_replay_impl", lambda *a, **k: _resp(json.dumps({"errors": [{"message": "off"}]}), 400)
    )
    out = gd._graphql_field_leak_impl("https://x/graphql", None, 10)
    assert out["possible_field_leak"] is False


# ---- graphql_dos ---------------------------------------------------------


def test_graphql_dos_amplified(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        q = json.loads(body)["query"]
        if "a0:__typename" in q:  # alias bomb is slow
            return _resp("{}", elapsed_ms=9000)
        return _resp("{}", elapsed_ms=30)

    monkeypatch.setattr(gd, "_replay_impl", _fake)
    out = gd._graphql_dos_impl("https://x/graphql", None, 2000, 20)
    assert out["possible_dos"] is True
    assert "alias_bomb" in out["amplified_tests"]


def test_graphql_dos_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gd, "_replay_impl", lambda *a, **k: _resp("{}", elapsed_ms=35))
    out = gd._graphql_dos_impl("https://x/graphql", None, 2000, 20)
    assert out["possible_dos"] is False
