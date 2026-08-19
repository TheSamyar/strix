"""autopwn (chained pipeline) and verify_finding (adversarial re-confirm)."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.autopwn import tools as ap


def _ok(**kw: Any) -> dict[str, Any]:
    return {"success": True, **kw}


# ---- autopwn: pivots on a leaked Supabase key ----------------------------


def test_autopwn_chains_leaked_key_to_rls(monkeypatch: pytest.MonkeyPatch) -> None:
    # profile finds a Supabase URL + anon key; backend_rules then dumps a table.
    monkeypatch.setattr(
        ap,
        "_profile_target_impl",
        lambda url, t: _ok(
            framework="nextjs",
            baas=["supabase"],
            api=[],
            supabase_url="https://p.supabase.co",
            supabase_anon_key="anon-key",
        ),
    )
    monkeypatch.setattr(ap, "_param_discover_impl", lambda *a, **k: _ok(hidden_params=[]))
    monkeypatch.setattr(ap, "_content_discover_impl", lambda *a, **k: _ok(found=[]))
    monkeypatch.setattr(ap, "_frontend_secret_scan_impl", lambda *a, **k: _ok(findings=[]))
    monkeypatch.setattr(ap, "_ssr_leak_impl", lambda *a, **k: _ok(possible_ssr_leak=False))
    monkeypatch.setattr(ap, "_storage_probe_impl", lambda *a, **k: _ok(possible_exposure=False))
    monkeypatch.setattr(ap, "_error_leak_impl", lambda *a, **k: _ok(possible_error_leak=False))
    monkeypatch.setattr(ap, "_header_leak_impl", lambda *a, **k: _ok(possible_header_leak=False))
    monkeypatch.setattr(
        ap,
        "_backend_rules_probe_impl",
        lambda *a, **k: _ok(possible_open_rules=True, results=[{"table": "users"}]),
    )
    monkeypatch.setattr(ap, "_cors_probe_impl", lambda *a, **k: _ok(possible_cors_issue=False))
    monkeypatch.setattr(
        ap, "_security_headers_impl", lambda *a, **k: _ok(possible_hardening_gaps=False)
    )
    monkeypatch.setattr(
        ap, "_chain_suggest_impl", lambda f: _ok(chains=[{"name": "RLS -> takeover"}])
    )

    out = ap._autopwn_impl("https://x/", None, None, 10)
    assert out["success"] is True
    titles = [f["title"] for f in out["findings"]]
    assert any("Supabase RLS" in t for t in titles)
    # the RLS finding was re-run and verified True
    rls = next(f for f in out["findings"] if "Supabase RLS" in f["title"])
    assert rls["verified"] is True
    assert out["chains"]


def test_autopwn_clean_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ap, "_profile_target_impl", lambda url, t: _ok(baas=[], api=[]))
    for name in (
        "_param_discover_impl",
        "_content_discover_impl",
        "_frontend_secret_scan_impl",
        "_ssr_leak_impl",
        "_storage_probe_impl",
        "_error_leak_impl",
        "_header_leak_impl",
        "_cors_probe_impl",
        "_security_headers_impl",
    ):
        monkeypatch.setattr(ap, name, lambda *a, **k: _ok())
    monkeypatch.setattr(ap, "_chain_suggest_impl", lambda f: _ok(chains=[]))
    out = ap._autopwn_impl("https://x/", None, None, 10)
    assert out["finding_count"] == 0


def test_autopwn_empty_url_rejected() -> None:
    assert ap._autopwn_impl("", None, None, 10)["success"] is False


# ---- verify_finding ------------------------------------------------------


def test_verify_confirms_reproducing_cors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ap, "_cors_probe_impl", lambda *a, **k: _ok(possible_cors_issue=True))
    out = ap._verify_finding_impl("cors", "https://x/api", "GET", None, None, None, None, 3, 10)
    assert out["verdict"] == "CONFIRMED"
    assert out["signal_reproduced"] == 3


def test_verify_rejects_flaky(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"n": 0}

    def _flaky(*a: Any, **k: Any) -> dict[str, Any]:
        state["n"] += 1
        return _ok(possible_cors_issue=state["n"] == 1)  # only the first run flags

    monkeypatch.setattr(ap, "_cors_probe_impl", _flaky)
    out = ap._verify_finding_impl("cors", "https://x/api", "GET", None, None, None, None, 3, 10)
    assert out["verdict"] == "NOT_REPRODUCED"


def test_verify_unknown_kind_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    out = ap._verify_finding_impl("mystery", "https://x/", "GET", None, None, None, None, 2, 10)
    assert out["verdict"] == "NOT_REPRODUCED"
    assert out["errors"]
