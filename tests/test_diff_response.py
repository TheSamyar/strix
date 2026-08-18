"""Tests for the ``diff_response`` MCP tool."""

from __future__ import annotations

from strix.tools.diff_response.tools import _diff_response_impl


def test_reflection_detected() -> None:
    result = _diff_response_impl(
        baseline="<div>Results for cat</div>",
        payload_response="<div>Results for <script>alert(1)</script></div>",
        payload="<script>alert(1)</script>",
    )
    assert result["reflection"]["reflected"] is True
    assert result["reflection"]["occurrences"] == 1
    assert "<script>alert(1)</script>" in result["reflection"]["context"]
    assert any("reflected" in s for s in result["signals"])


def test_status_change_flagged() -> None:
    result = _diff_response_impl(
        baseline="ok",
        payload_response="error",
        baseline_status=200,
        payload_status=500,
    )
    assert result["status_changed"] is True
    assert any("status changed" in s for s in result["signals"])


def test_identical_inputs_no_signals() -> None:
    body = "same body\nline two"
    result = _diff_response_impl(
        baseline=body,
        payload_response=body,
        payload="notpresent",
        baseline_status=200,
        payload_status=200,
    )
    assert result["signals"] == []
    assert result["added_lines"] == 0
    assert result["removed_lines"] == 0
    assert result["reflection"]["reflected"] is False
