"""authz_matrix (BOLA/BFLA grid) and stored_probe (second-order/stored XSS)."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.authz_matrix import tools as azm
from strix.tools.credentials import tools as creds
from strix.tools.stored_probe import tools as stored


def _resp(body: str = "", status: int = 200) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body}


@pytest.fixture(autouse=True)
def _clear_creds() -> None:
    creds._credentials_storage.clear()


# ---- authz_matrix --------------------------------------------------------


def test_matrix_flags_shared_body(monkeypatch: pytest.MonkeyPatch) -> None:
    creds._store_credential_impl("owner", "tok-owner")
    creds._store_credential_impl("attacker", "tok-attacker")

    # every identity gets the same doc back = broken object-level authz
    monkeypatch.setattr(azm, "_replay_impl", lambda *a, **k: _resp("secret-doc-1"))
    out = azm._authz_matrix_impl(
        ["https://x/doc/1"], [{"label": "owner"}, {"label": "attacker"}], None, 15, 400
    )
    assert out["possible_broken_authz"] is True
    assert out["flagged"][0]["shared_body_identities"]


def test_matrix_flags_unauth_access(monkeypatch: pytest.MonkeyPatch) -> None:
    creds._store_credential_impl("owner", "tok")

    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        return _resp("data", 200)  # unauth also gets 200

    monkeypatch.setattr(azm, "_replay_impl", _fake)
    out = azm._authz_matrix_impl(["https://x/admin"], [{"label": "owner"}], None, 15, 400)
    assert any(f["unauth_authorized"] for f in out["flagged"])


def test_matrix_proper_authz_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    creds._store_credential_impl("owner", "tok-owner")

    def _fake(method: str, url: str, headers: Any, *a: Any, **k: Any) -> dict[str, Any]:
        # owner (has Authorization) gets 200, unauth gets 403
        return _resp("owned", 200) if headers and headers.get("Authorization") else _resp("no", 403)

    monkeypatch.setattr(azm, "_replay_impl", _fake)
    out = azm._authz_matrix_impl(["https://x/doc/1"], [{"label": "owner"}], None, 15, 400)
    assert out["possible_broken_authz"] is False


def test_matrix_budget_truncates(monkeypatch: pytest.MonkeyPatch) -> None:
    creds._store_credential_impl("a", "t")
    monkeypatch.setattr(azm, "_replay_impl", lambda *a, **k: _resp("x"))
    out = azm._authz_matrix_impl(
        [f"https://x/{i}" for i in range(10)], [{"label": "a"}], None, 15, 3
    )
    assert out["truncated"] is True


# ---- stored_probe --------------------------------------------------------


def test_stored_xss_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    store_state = {"saved": ""}

    def _fake(method: str, url: str, headers: Any, body: Any, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith("/comment"):  # the inject request
            import json

            store_state["saved"] = json.loads(body)["text"]
            return _resp("saved", 201)
        # the sweep endpoint renders the stored value unescaped
        return _resp(f"<div>{store_state['saved']}</div>")

    monkeypatch.setattr(stored, "_replay_impl", _fake)
    out = stored._stored_probe_impl(
        "https://x/comment", "text", ["https://x/feed"], "POST", "body", None, None, 10
    )
    assert out["possible_stored_xss"] is True


def test_second_order_flow_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    store_state = {"saved": ""}

    def _fake(method: str, url: str, headers: Any, body: Any, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith("/note"):
            import json

            store_state["saved"] = json.loads(body)["v"]
            return _resp("ok")
        # rendered ESCAPED — marker present but payload neutralized
        escaped = store_state["saved"].replace("<", "&lt;").replace(">", "&gt;")
        return _resp(f"<p>{escaped}</p>")

    monkeypatch.setattr(stored, "_replay_impl", _fake)
    out = stored._stored_probe_impl(
        "https://x/note", "v", ["https://x/admin"], "POST", "body", None, None, 10
    )
    assert out["possible_second_order"] is True
    assert out["possible_stored_xss"] is False


def test_stored_not_surfaced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stored, "_replay_impl", lambda *a, **k: _resp("nothing relevant"))
    out = stored._stored_probe_impl(
        "https://x/comment", "text", ["https://x/feed"], "POST", "body", None, None, 10
    )
    assert out["possible_second_order"] is False


def test_stored_requires_sweep_urls() -> None:
    out = stored._stored_probe_impl("https://x/c", "t", [], "POST", "body", None, None, 10)
    assert out["success"] is False
