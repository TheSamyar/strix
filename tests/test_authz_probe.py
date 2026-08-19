"""authz_probe: replay one request across identities and flag broken access control."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.authz_probe import tools as authz
from strix.tools.credentials import tools as creds


@pytest.fixture(autouse=True)
def _clear_creds() -> None:
    creds._credentials_storage.clear()


def _stub_responses(
    monkeypatch: pytest.MonkeyPatch, by_auth: dict[str | None, dict[str, Any]]
) -> None:
    """Route _replay_impl by the Authorization header value it receives."""

    def _fake(
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: Any,
        timeout: int,
        allow_redirects: bool,
    ) -> dict[str, Any]:
        del method, url, body, timeout, allow_redirects
        auth = (headers or {}).get("Authorization")
        resp = by_auth[auth]
        return {
            "success": True,
            "status_code": resp["status"],
            "body": resp["body"],
            "elapsed_ms": 1.0,
        }

    monkeypatch.setattr(authz, "_replay_impl", _fake)


def test_shared_body_flags_idor(monkeypatch: pytest.MonkeyPatch) -> None:
    creds._store_credential_impl("owner", "tok-owner")
    creds._store_credential_impl("attacker", "tok-attacker")
    # Both identities get the SAME body = object served regardless of who asks.
    _stub_responses(
        monkeypatch,
        {
            "tok-owner": {"status": 200, "body": "secret-doc"},
            "tok-attacker": {"status": 200, "body": "secret-doc"},
        },
    )
    out = authz._authz_probe_impl(
        "GET",
        "https://x/doc/1",
        [{"label": "owner"}, {"label": "attacker"}],
        None,
        None,
        15,
    )
    assert out["success"] is True
    assert out["possible_authz_issue"] is True
    assert out["shared_body_identities"] == [["owner", "attacker"]]
    assert out["identities_allowed_beyond_baseline"] == ["attacker"]


def test_proper_authz_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    creds._store_credential_impl("owner", "tok-owner")
    _stub_responses(
        monkeypatch,
        {
            "tok-owner": {"status": 200, "body": "secret-doc"},
            None: {"status": 403, "body": "denied"},
        },
    )
    out = authz._authz_probe_impl(
        "GET",
        "https://x/doc/1",
        [{"label": "owner"}, {"label": "unauth"}],
        None,
        None,
        15,
    )
    assert out["possible_authz_issue"] is False
    assert out["shared_body_identities"] == []
    assert out["identities_allowed_beyond_baseline"] == []


def test_value_prefix_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    creds._store_credential_impl("u", "abc")
    seen: dict[str, Any] = {}

    def _fake(
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: Any,
        timeout: int,
        allow_redirects: bool,
    ) -> dict[str, Any]:
        del method, url, body, timeout, allow_redirects
        seen["auth"] = (headers or {}).get("Authorization")
        return {"success": True, "status_code": 200, "body": "x", "elapsed_ms": 1.0}

    monkeypatch.setattr(authz, "_replay_impl", _fake)
    authz._authz_probe_impl(
        "GET", "https://x", [{"label": "u", "value_prefix": "Bearer "}], None, None, 15
    )
    assert seen["auth"] == "Bearer abc"


def test_missing_credential_reports_error() -> None:
    out = authz._authz_probe_impl("GET", "https://x", [{"label": "ghost"}], None, None, 15)
    assert out["results"][0]["success"] is False
    assert "not found" in out["results"][0]["error"]


def test_empty_identities_rejected() -> None:
    out = authz._authz_probe_impl("GET", "https://x", [], None, None, 15)
    assert out["success"] is False
