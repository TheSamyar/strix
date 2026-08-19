"""dedupe_reports: merge duplicate findings (same class + endpoint + method + target)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

import strix.report.state as report_state_mod
from strix.report.state import ReportState


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    state = ReportState(run_name="dedupe-test")
    report_state_mod.set_global_report_state(state)
    yield state
    report_state_mod._global_report_state = None


def _add(state: ReportState, title: str, endpoint: str, cwe: str = "CWE-89") -> str:
    return state.add_vulnerability_report(
        title=title, severity="high", target="https://x", endpoint=endpoint, method="GET", cwe=cwe
    )


def test_merges_same_class_same_endpoint(run: ReportState) -> None:
    _add(run, "SQLi in id", "/api/item")
    _add(run, "SQL injection again", "/api/item")  # same cwe + endpoint + method + target
    _add(run, "SQLi elsewhere", "/api/other")  # different endpoint → kept

    result = run.dedupe_vulnerability_reports()
    assert result["removed_count"] == 1
    assert result["kept_count"] == 2
    assert len(run.vulnerability_reports) == 2
    kept_first = next(r for r in run.vulnerability_reports if r["endpoint"] == "/api/item")
    assert kept_first["duplicates_merged"] == 1


def test_different_class_not_merged(run: ReportState) -> None:
    _add(run, "SQLi", "/api/item", cwe="CWE-89")
    _add(run, "XSS", "/api/item", cwe="CWE-79")
    result = run.dedupe_vulnerability_reports()
    assert result["removed_count"] == 0
    assert result["kept_count"] == 2


def test_idempotent(run: ReportState) -> None:
    _add(run, "SQLi", "/api/item")
    _add(run, "SQLi dup", "/api/item")
    run.dedupe_vulnerability_reports()
    second = run.dedupe_vulnerability_reports()
    assert second["removed_count"] == 0


def test_disk_reflects_dedupe(run: ReportState, tmp_path: Path) -> None:
    _add(run, "SQLi", "/api/item")
    _add(run, "SQLi dup", "/api/item")
    run.dedupe_vulnerability_reports()
    data = json.loads(
        (tmp_path / "strix_runs" / "dedupe-test" / "vulnerabilities.json").read_text()
    )
    assert len(data) == 1
