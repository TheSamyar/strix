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
    monkeypatch.setattr(ap, "_oast_get_domain", lambda **k: {"success": False})

    out = ap._autopwn_impl("https://x/", None, None, None, False, 2, 10)
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
    monkeypatch.setattr(ap, "_oast_get_domain", lambda **k: {"success": False})
    out = ap._autopwn_impl("https://x/", None, None, None, False, 2, 10)
    assert out["finding_count"] == 0


def test_autopwn_empty_url_rejected() -> None:
    assert ap._autopwn_impl("", None, None, None, False, 2, 10)["success"] is False


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


# ---- autopwn: new deepeners (OAST, loop, IDOR grid, auto-file) ------------


def _patch_clean_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralize every seed-harvest / probe stage so a test can flip one on."""
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
        "_data_exposure_impl",
        "_deep_fuzz_impl",
        "_graphql_field_leak_impl",
    ):
        monkeypatch.setattr(ap, name, lambda *a, **k: _ok())
    monkeypatch.setattr(ap, "_chain_suggest_impl", lambda f: _ok(chains=[]))
    monkeypatch.setattr(ap, "_oast_get_domain", lambda **k: {"success": False})


def test_autopwn_oast_blind_ssrf(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clean_seed(monkeypatch)
    monkeypatch.setattr(
        ap, "_oast_get_domain", lambda **k: _ok(domain="abc.oast.pro", correlation_id="cid")
    )
    # a hidden param exists so the injection-fuzz stage plants the OAST payload
    monkeypatch.setattr(
        ap, "_param_discover_impl", lambda *a, **k: _ok(hidden_params=[{"param": "u"}])
    )
    monkeypatch.setattr(ap, "_injection_fuzz_impl", lambda *a, **k: _ok())
    monkeypatch.setattr(
        ap,
        "_oast_poll",
        lambda cid, t: _ok(interactions=[{"protocol": "dns", "full_id": "abc.oast.pro"}]),
    )
    out = ap._autopwn_impl("https://x/", None, None, None, False, 2, 10)
    assert any(f["kind"] == "ssrf" for f in out["findings"])
    assert out["oast_domain"] == "abc.oast.pro"


def test_autopwn_loops_into_discovered_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clean_seed(monkeypatch)
    # seed page discovers /admin; on it, a hidden param fuzzes to an injection hit
    monkeypatch.setattr(
        ap, "_content_discover_impl", lambda *a, **k: _ok(found=[{"path": "/admin"}])
    )

    def _params(url: str, *a: Any, **k: Any) -> dict[str, Any]:
        if url.endswith("/admin"):
            return _ok(hidden_params=[{"param": "q"}])
        return _ok(hidden_params=[])

    monkeypatch.setattr(ap, "_param_discover_impl", _params)
    monkeypatch.setattr(
        ap,
        "_deep_fuzz_impl",
        lambda *a, **k: _ok(findings=[{"family": "SQLi", "param": "q", "severity": "high"}]),
    )
    out = ap._autopwn_impl("https://x/", None, None, None, False, 3, 10)
    assert out["endpoints_probed"] >= 2
    assert any("SQLi injection" in f["title"] and "/admin" in f["title"] for f in out["findings"])


def test_autopwn_two_identity_idor_grid(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clean_seed(monkeypatch)
    monkeypatch.setattr(
        ap,
        "_authz_matrix_impl",
        lambda *a, **k: _ok(flagged=[{"endpoint": "https://x/me", "issue": "cross-tenant"}]),
    )
    identities = [{"name": "a", "headers": {}}, {"name": "b", "headers": {}}]
    out = ap._autopwn_impl("https://x/", None, None, identities, False, 2, 10)
    assert any(f["kind"] == "idor" for f in out["findings"])


def test_autopwn_files_verified_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clean_seed(monkeypatch)
    # a verified RLS finding (verify closure returns True on re-run)
    monkeypatch.setattr(
        ap,
        "_profile_target_impl",
        lambda url, t: _ok(supabase_url="https://p.supabase.co", supabase_anon_key="k"),
    )
    monkeypatch.setattr(
        ap, "_backend_rules_probe_impl", lambda *a, **k: _ok(possible_open_rules=True, results=[])
    )

    calls: list[dict[str, Any]] = []

    class _State:
        def add_vulnerability_report(self, **kw: Any) -> str:
            calls.append(kw)
            return "vuln-1"

    monkeypatch.setattr(ap, "get_global_report_state", lambda: _State())
    out = ap._autopwn_impl("https://x/", None, None, None, True, 2, 10)
    assert out["filed_reports"] >= 1
    assert calls and calls[0]["validated"] is True
