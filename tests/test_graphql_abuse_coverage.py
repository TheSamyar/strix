"""graphql_abuse (batching/aliasing/suggestions) and coverage_gaps (critic)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

import strix.report.state as report_state_mod
from strix.report.state import ReportState
from strix.tools.attack_surface import tools as asf
from strix.tools.coverage_gaps.tools import _coverage_gaps_impl, _surface_gaps
from strix.tools.graphql_abuse import tools as gqla
from strix.tools.todo.tools import _get_agent_todos, seed_todos


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def _resp(body: str, status: int = 200) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body}


# ---- graphql_abuse -------------------------------------------------------


def test_array_batching_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        payload = json.loads(body)
        if isinstance(payload, list):
            return _resp(json.dumps([{"data": {"__typename": "Query"}} for _ in payload]))
        return _resp(json.dumps({"data": {"__typename": "Query"}}))

    monkeypatch.setattr(gqla, "_replay_impl", _fake)
    out = gqla._graphql_abuse_impl("https://x/graphql", None, 5, 10)
    assert out["array_batching"] is True
    assert out["possible_abuse"] is True


def test_alias_batching_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        payload = json.loads(body)
        if isinstance(payload, dict) and "a0:" in payload.get("query", ""):
            n = payload["query"].count("__typename")
            return _resp(json.dumps({"data": {f"a{i}": "Query" for i in range(n)}}))
        return _resp(json.dumps({"data": {}}))

    monkeypatch.setattr(gqla, "_replay_impl", _fake)
    out = gqla._graphql_abuse_impl("https://x/graphql", None, 4, 10)
    assert out["alias_batching"] is True


def test_field_suggestions_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(method: str, url: str, headers: Any, body: str, *a: Any, **k: Any) -> dict[str, Any]:
        if "thisFieldDoesNotExist" in body:
            return _resp(json.dumps({"errors": [{"message": "Did you mean 'user'?"}]}))
        return _resp(json.dumps({"data": {}}))

    monkeypatch.setattr(gqla, "_replay_impl", _fake)
    out = gqla._graphql_abuse_impl("https://x/graphql", None, 3, 10)
    assert out["field_suggestions_enabled"] is True


def test_locked_down_graphql_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gqla,
        "_replay_impl",
        lambda *a, **k: _resp(json.dumps({"errors": [{"message": "no"}]}), 400),
    )
    out = gqla._graphql_abuse_impl("https://x/graphql", None, 5, 10)
    assert out["possible_abuse"] is False


# ---- coverage_gaps -------------------------------------------------------


def _reset_surface() -> None:
    asf._store["endpoints"].clear()
    asf._store["roles"].clear()
    asf._store["matrix"].clear()


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    _reset_surface()
    state = ReportState(run_name="gaps-test")
    report_state_mod.set_global_report_state(state)
    yield state
    report_state_mod._global_report_state = None
    _reset_surface()


def test_gaps_shallow_when_todos_pending(run: ReportState) -> None:
    seed_todos("gaps-agent", [{"title": f"[coverage] test {i}"} for i in range(6)])
    out = _coverage_gaps_impl("gaps-agent")
    assert out["pending_todo_count"] == 6
    assert out["thoroughness"] == "shallow"


def test_gaps_thorough_when_clear(run: ReportState) -> None:
    # no todos pending; no audit log → unrun_count 0 (unknown); empty mapped
    # must still be allowed to look_thorough
    out = _coverage_gaps_impl("empty-agent")
    assert _get_agent_todos("empty-agent") == {}
    assert out["thoroughness"] == "looks_thorough"
    assert out["mapped_endpoint_count"] == 0
    assert out["endpoint_coverage_ratio"] == 1.0
    assert out["untested_endpoint_count"] == 0


def test_surface_gaps_flag_untested_deep_classes() -> None:
    _reset_surface()
    asf._record_endpoint_impl("/graphql", "POST", params=["query"], auth_required=True)
    asf._record_endpoint_impl(
        "/api/avatar/upload", "POST", params=["file"], auth_required=True, notes="multipart"
    )
    asf._record_role_impl("admin")
    asf._record_role_impl("user")

    gaps = _surface_gaps(set())  # nothing deep ran
    joined = " ".join(gaps).lower()
    assert "authorization" in joined  # multi-identity → IDOR/BOLA
    assert "graphql" in joined
    assert "upload" in joined
    assert "injection" in joined
    assert "stored" in joined

    assert "ssrf" in joined  # 'file' param is SSRF-prone

    # once the deep tools ran, the surface gaps clear (matrix bookkeeping optional)
    ran = {
        "authz_probe",
        "graphql_abuse",
        "upload_probe",
        "injection_fuzz",
        "stored_probe",
        "ssrf_probe",
        "lfi_probe",
    }
    assert _surface_gaps(ran) == []
    _reset_surface()


def test_surface_gaps_never_break_without_audit_log() -> None:
    assert _surface_gaps(None) == []
