"""validate_finding: PoC re-run + proof capture, and its wiring into reporting."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _do_create
from strix.tools.validation import tools as validation


if TYPE_CHECKING:
    from pathlib import Path


_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}

_VERIFICATION = "Re-ran the curl PoC twice; both times HTTP 200 with the data returned."

_LEAK = "victim@example.com"


def _resp(body: str, status: int = 200) -> dict[str, Any]:
    return {"success": True, "status_code": status, "body": body, "response_headers": {}}


@pytest.fixture(autouse=True)
def _fresh_store(tmp_path: Path) -> None:
    validation.hydrate_validations_from_disk(tmp_path)


def test_data_leak_validated_with_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        validation, "_replay_impl", lambda *_a, **_k: _resp(f"user data: {_LEAK} end")
    )
    rec = validation._validate_impl(
        claim_type="data_leak",
        method="GET",
        url="https://app/api/user/2",
        headers={"Authorization": "Bearer attacker"},
        body=None,
        timeout=20,
        allow_redirects=False,
        expect_contains=_LEAK,
        expect_regex=None,
        expect_status=None,
        baseline_headers=None,
        baseline_no_auth=False,
    )
    assert rec["validated"] is True
    assert _LEAK in rec["proof_excerpt"]
    assert validation.get_validation(rec["id"]) == rec


def test_signal_absent_not_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validation, "_replay_impl", lambda *_a, **_k: _resp("nothing here"))
    rec = validation._validate_impl(
        claim_type="data_leak",
        method="GET",
        url="https://app/api/user/2",
        headers=None,
        body=None,
        timeout=20,
        allow_redirects=False,
        expect_contains=_LEAK,
        expect_regex=None,
        expect_status=None,
        baseline_headers=None,
        baseline_no_auth=False,
    )
    assert rec["validated"] is False
    assert "not found" in rec["reason"]
    assert rec["proof_excerpt"] is None


def test_public_data_fails_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    # Both the authed exploit and the no-auth baseline return the data → public.
    monkeypatch.setattr(
        validation, "_replay_impl", lambda *_a, **_k: _resp(f"data: {_LEAK}")
    )
    rec = validation._validate_impl(
        claim_type="data_leak",
        method="GET",
        url="https://app/api/user/2",
        headers={"Authorization": "Bearer attacker"},
        body=None,
        timeout=20,
        allow_redirects=False,
        expect_contains=_LEAK,
        expect_regex=None,
        expect_status=None,
        baseline_headers=None,
        baseline_no_auth=True,
    )
    assert rec["validated"] is False
    assert "public" in rec["reason"]


def _valid_report_kwargs() -> dict[str, Any]:
    return {
        "title": "IDOR exposes another user's email",
        "description": "The /api/user/{id} endpoint returns other users' records.",
        "impact": "An authenticated attacker reads any user's email.",
        "target": "https://app.example.com",
        "technical_analysis": "The handler skips the ownership check on the id parameter.",
        "poc_description": "1. Request /api/user/2 with your own token.",
        "poc_script_code": "curl -H 'Authorization: Bearer x' https://app.example.com/api/user/2",
        "remediation_steps": "Enforce an ownership check keyed on the session user.",
        "evidence": (
            "```http\nGET /api/user/2 HTTP/1.1\n\nHTTP/1.1 200 OK\n\n"
            f'{{"email": "{_LEAK}"}}\n```'
        ),
        "assumptions": "Assumes an authenticated low-privilege user.",
        "verification": _VERIFICATION,
        "fix_effort": "low",
        "cvss_breakdown": _CVSS,
        "endpoint": "/api/user/2",
        "method": "GET",
        "cve": None,
        "cwe": "CWE-639",
        "code_locations": None,
    }


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="valid-run")
    set_global_report_state(state)
    return state


async def test_report_with_passing_validation_embeds_proof(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        validation, "get_validation", lambda _id: {"validated": True, "proof_excerpt": _LEAK}
    )
    result = await _do_create(**_valid_report_kwargs(), validation_id="abc123")
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["validated"] is True
    assert report["validation_proof"] == _LEAK


async def test_report_with_failed_validation_rejected(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(validation, "get_validation", lambda _id: None)
    result = await _do_create(**_valid_report_kwargs(), validation_id="missing")
    assert result["success"] is False
    assert any("did not pass" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


@pytest.mark.parametrize("validation_id", [None, "", "   "])
async def test_report_without_validation_id_rejected(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
    validation_id: str | None,
) -> None:
    monkeypatch.delenv("STRIX_REQUIRE_VALIDATION", raising=False)
    result = await _do_create(**_valid_report_kwargs(), validation_id=validation_id)
    assert result["success"] is False
    joined = " ".join(result["errors"])
    assert "validate_finding" in joined
    assert "validation_id" in joined
    assert "required" in joined.lower()
    assert not report_state.vulnerability_reports


@pytest.mark.parametrize("hatch", ["0", "false", "no", "FALSE"])
async def test_report_without_validation_id_allowed_when_requirement_disabled(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
    hatch: str,
) -> None:
    monkeypatch.setenv("STRIX_REQUIRE_VALIDATION", hatch)
    result = await _do_create(**_valid_report_kwargs())
    assert result["success"] is True
    assert report_state.vulnerability_reports[0]["validated"] is False


async def test_failed_validation_id_rejected_even_when_requirement_disabled(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIX_REQUIRE_VALIDATION", "0")
    monkeypatch.setattr(validation, "get_validation", lambda _id: None)
    result = await _do_create(**_valid_report_kwargs(), validation_id="missing")
    assert result["success"] is False
    assert any("did not pass" in e for e in result["errors"])
    assert not report_state.vulnerability_reports
