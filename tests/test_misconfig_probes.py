"""cors_probe / rate_limit_probe / graphql_introspection / jwt_audit."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.tools.cors_probe import tools as cors
from strix.tools.graphql_probe import tools as gql
from strix.tools.jwt_audit import tools as jwt
from strix.tools.rate_limit_probe import tools as ratelimit


def _resp(
    status: int = 200, headers: dict[str, str] | None = None, body: str = ""
) -> dict[str, Any]:
    return {
        "success": True,
        "status_code": status,
        "response_headers": headers or {},
        "body": body,
    }


# ---- cors_probe ----------------------------------------------------------


def test_cors_reflected_origin_with_credentials_is_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake(
        method: str, url: str, headers: dict[str, str] | None, *a: Any, **k: Any
    ) -> dict[str, Any]:
        origin = (headers or {}).get("Origin", "")
        return _resp(
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
        )

    monkeypatch.setattr(cors, "_replay_impl", _fake)
    out = cors._cors_probe_impl("https://x/api", "GET", ["https://evil.example"], 10)
    assert out["possible_cors_issue"] is True
    assert out["worst_severity"] == "critical"


def test_cors_wildcard_no_credentials_low(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(
        method: str, url: str, headers: dict[str, str] | None, *a: Any, **k: Any
    ) -> dict[str, Any]:
        return _resp(headers={"Access-Control-Allow-Origin": "*"})

    monkeypatch.setattr(cors, "_replay_impl", _fake)
    out = cors._cors_probe_impl("https://x/api", "GET", ["https://evil.example"], 10)
    assert out["worst_severity"] == "low"


def test_cors_locked_down_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(
        method: str, url: str, headers: dict[str, str] | None, *a: Any, **k: Any
    ) -> dict[str, Any]:
        return _resp(headers={"Access-Control-Allow-Origin": "https://trusted.example"})

    monkeypatch.setattr(cors, "_replay_impl", _fake)
    out = cors._cors_probe_impl("https://x/api", "GET", ["https://evil.example"], 10)
    assert out["possible_cors_issue"] is False


# ---- rate_limit_probe ----------------------------------------------------


def test_rate_limit_missing_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_replay_impl", lambda *a, **k: _resp(200))
    out = ratelimit._rate_limit_probe_impl("GET", "https://x/login", 10, None, None, 5)
    assert out["possible_missing_rate_limit"] is True
    assert out["saw_429"] is False


def test_rate_limit_429_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_replay_impl", lambda *a, **k: _resp(429))
    out = ratelimit._rate_limit_probe_impl("GET", "https://x/login", 5, None, None, 5)
    assert out["throttled"] is True
    assert out["possible_missing_rate_limit"] is False


def test_rate_limit_header_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ratelimit, "_replay_impl", lambda *a, **k: _resp(200, {"RateLimit-Remaining": "0"})
    )
    out = ratelimit._rate_limit_probe_impl("GET", "https://x/login", 3, None, None, 5)
    assert out["saw_ratelimit_header"] is True
    assert out["throttled"] is True


# ---- graphql_introspection ----------------------------------------------


def test_graphql_introspection_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "User"}, {"name": "Query"}],
                }
            }
        }
    )
    monkeypatch.setattr(gql, "_replay_impl", lambda *a, **k: _resp(200, body=body))
    out = gql._graphql_introspection_impl("https://x/graphql", None, 10)
    assert out["introspection_enabled"] is True
    assert out["type_count"] == 2
    assert "User" in out["types_sample"]


def test_graphql_introspection_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"errors": [{"message": "introspection disabled"}]})
    monkeypatch.setattr(gql, "_replay_impl", lambda *a, **k: _resp(400, body=body))
    out = gql._graphql_introspection_impl("https://x/graphql", None, 10)
    assert out["introspection_enabled"] is False


# ---- jwt_audit (offline) -------------------------------------------------


def _make_jwt(payload: dict[str, Any], secret: str) -> str:
    header_b64 = jwt._b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_b64 = jwt._b64url_encode(json.dumps(payload).encode())
    sig = jwt._sign_hs256(f"{header_b64}.{payload_b64}", secret)
    return f"{header_b64}.{payload_b64}.{sig}"


def test_jwt_weak_secret_cracked_and_admin_forged() -> None:
    token = _make_jwt({"user": "bob", "role": "user"}, "secret")
    out = jwt._jwt_audit_impl(token, None)
    assert out["cracked_secret"] == "secret"
    assert out["possible_jwt_issue"] is True
    assert "admin_hs256" in out["forged_tokens"]
    # forged admin token decodes to role=admin
    admin_payload = out["forged_tokens"]["admin_hs256"].split(".")[1]
    assert json.loads(jwt._b64url_decode(admin_payload))["role"] == "admin"


def test_jwt_alg_none_always_forged() -> None:
    token = _make_jwt({"user": "bob"}, "an-uncrackable-long-random-secret-xyz")
    out = jwt._jwt_audit_impl(token, None)
    assert out["cracked_secret"] is None
    assert out["forged_tokens"]["alg_none"].endswith(".")


def test_jwt_missing_exp_flagged() -> None:
    token = _make_jwt({"user": "bob"}, "secret")
    out = jwt._jwt_audit_impl(token, None)
    assert any("no exp" in f for f in out["findings"])


def test_jwt_not_a_jwt() -> None:
    out = jwt._jwt_audit_impl("not.a.jwt.token.extra", None)
    assert out["success"] is False
