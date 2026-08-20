"""coverage_gaps: thoroughness is endpoint coverage, not tool-name ticks."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import strix.report.state as report_state_mod
from strix.report.state import ReportState
from strix.tools.attack_surface import tools as asf
from strix.tools.coverage_gaps.tools import (
    _KEY_TOOLS,
    _coverage_gaps_impl,
    _path_covers,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def _reset_surface() -> None:
    asf._store["endpoints"].clear()
    asf._store["roles"].clear()
    asf._store["matrix"].clear()


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    _reset_surface()
    state = ReportState(run_name="cov-gaps")
    report_state_mod.set_global_report_state(state)
    yield state
    report_state_mod._global_report_state = None
    _reset_surface()


def _map_n(n: int) -> None:
    for i in range(n):
        asf._record_endpoint_impl(f"/api/res{i}", "GET")


def _all_key_plus_stored() -> set[str]:
    return set(_KEY_TOOLS) | {"stored_probe"}


def test_path_covers_param_segment() -> None:
    assert _path_covers("/api/users/2", "/api/users/{id}")
    assert _path_covers("/api/users/2", "/api/users/:id")
    assert not _path_covers("/api/orders/2", "/api/users/{id}")


@pytest.mark.usefixtures("run")
def test_mapped_untested_not_thorough_even_if_key_tools_ran(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "strix.tools.coverage_gaps.tools._tools_run",
        _all_key_plus_stored,
    )
    _map_n(10)
    out = _coverage_gaps_impl("agent")
    assert out["mapped_endpoint_count"] == 10
    assert out["untested_endpoint_count"] == 10
    assert out["endpoint_coverage_ratio"] == 0.0
    assert out["thoroughness"] != "looks_thorough"


def test_eight_of_ten_mapped_not_yet_thorough(
    run: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Policy: thorough requires >= 0.85 endpoint coverage, so 8/10 is still in progress.
    monkeypatch.setattr(
        "strix.tools.coverage_gaps.tools._tools_run",
        _all_key_plus_stored,
    )
    _map_n(10)
    for i in range(8):
        run.add_vulnerability_report(
            title=f"finding {i}",
            severity="medium",
            target="https://app.example.com",
            endpoint=f"/api/res{i}",
        )
    out = _coverage_gaps_impl("agent")
    assert out["endpoint_coverage_ratio"] == 0.8
    assert out["thoroughness"] != "looks_thorough"


def test_nine_of_ten_mapped_looks_thorough(
    run: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "strix.tools.coverage_gaps.tools._tools_run",
        _all_key_plus_stored,
    )
    _map_n(10)
    for i in range(9):
        run.add_vulnerability_report(
            title=f"finding {i}",
            severity="medium",
            target="https://app.example.com",
            endpoint=f"/api/res{i}",
        )
    out = _coverage_gaps_impl("agent")
    assert out["pending_todo_count"] == 0
    assert out["surface_gaps"] == []
    assert out["mapped_endpoint_count"] == 10
    assert out["untested_endpoint_count"] == 1
    assert out["endpoint_coverage_ratio"] == 0.9
    assert out["thoroughness"] == "looks_thorough"


def test_untested_high_risk_endpoint_blocks_thorough(
    run: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "strix.tools.coverage_gaps.tools._tools_run",
        _all_key_plus_stored,
    )
    # 9 cheap static routes + 1 admin IDOR route: ratio hits 0.9 without ever
    # touching the endpoint that matters.
    _map_n(9)
    asf._record_endpoint_impl("/admin/users/{id}", "DELETE")
    for i in range(9):
        run.add_vulnerability_report(
            title=f"finding {i}",
            severity="medium",
            target="https://app.example.com",
            endpoint=f"/api/res{i}",
        )
    out = _coverage_gaps_impl("agent")
    assert out["endpoint_coverage_ratio"] == 0.9
    assert out["untested_high_risk"]
    assert out["untested_high_risk"][0]["endpoint"] == "/admin/users/{id}"
    assert out["thoroughness"] != "looks_thorough"


@pytest.mark.usefixtures("run")
def test_new_surface_gaps_fire_for_write_ai_and_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "strix.tools.coverage_gaps.tools._tools_run",
        _all_key_plus_stored,  # none of the new probes ran
    )
    asf._record_endpoint_impl("/api/chat/message", "POST", params=["prompt"], auth_required=True)
    asf._record_endpoint_impl("/oauth/authorize", "GET", params=["redirect_uri"])
    out = _coverage_gaps_impl("agent")
    blob = " ".join(out["surface_gaps"]).lower()
    assert "csrf_probe" in blob
    assert "mass_assignment_probe" in blob
    assert "prompt_injection_probe" in blob
    assert "redirect_probe" in blob
    assert "oauth_probe" in blob
    assert out["thoroughness"] != "looks_thorough"


@pytest.mark.usefixtures("run")
def test_injection_fuzz_name_not_enough_if_endpoints_untested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "strix.tools.coverage_gaps.tools._tools_run",
        _all_key_plus_stored,
    )
    assert "injection_fuzz" in _all_key_plus_stored()
    _map_n(10)
    out = _coverage_gaps_impl("agent")
    assert "injection_fuzz" not in (
        out["key_tools_not_run"] if isinstance(out["key_tools_not_run"], list) else []
    )
    assert out["untested_endpoint_count"] == 10
    assert out["thoroughness"] != "looks_thorough"
