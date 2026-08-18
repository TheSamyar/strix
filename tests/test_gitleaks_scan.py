"""gitleaks_scan: parse findings, redact secrets, degrade when binary missing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.tools.gitleaks_scan import tools as gitleaks_tools


_SAMPLE_SECRET = "AKIAIOSFODNN7EXAMPLE_supersecret"
_SAMPLE_REPORT = [
    {
        "RuleID": "aws-access-token",
        "File": "config/prod.env",
        "StartLine": 12,
        "Commit": "abc123",
        "Author": "Jane Dev",
        "Date": "2026-01-02T00:00:00Z",
        "Secret": _SAMPLE_SECRET,
        "Match": f"key={_SAMPLE_SECRET}",
    }
]


def _fake_run_writing(report: object):
    def _run(argv, **_kwargs):
        report_path = argv[argv.index("--report-path") + 1]
        Path(report_path).write_text(json.dumps(report), encoding="utf-8")

    return _run


def test_not_installed_returns_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks_tools.shutil, "which", lambda _: None)
    result = gitleaks_tools._scan_impl("/repo", no_git=False)
    assert result["error"]
    assert result["hint"] == "install gitleaks"


def test_parses_and_redacts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks_tools.shutil, "which", lambda _: "/usr/bin/gitleaks")
    monkeypatch.setattr(gitleaks_tools.subprocess, "run", _fake_run_writing(_SAMPLE_REPORT))

    result = gitleaks_tools._scan_impl("/repo", no_git=False)
    assert result["count"] == 1
    finding = result["findings"][0]
    assert finding["rule"] == "aws-access-token"
    assert finding["file"] == "config/prod.env"
    assert finding["line"] == 12
    assert finding["commit"] == "abc123"
    assert finding["secret"] == "AK***"

    # CRITICAL: the raw secret must never appear anywhere in the output.
    assert _SAMPLE_SECRET not in json.dumps(result)


def test_no_git_flag_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks_tools.shutil, "which", lambda _: "/usr/bin/gitleaks")
    seen: dict[str, list[str]] = {}

    def _run(argv, **_kwargs):
        seen["argv"] = argv
        Path(argv[argv.index("--report-path") + 1]).write_text("[]", encoding="utf-8")

    monkeypatch.setattr(gitleaks_tools.subprocess, "run", _run)

    result = gitleaks_tools._scan_impl("/repo", no_git=True)
    assert result["count"] == 0
    assert "--no-git" in seen["argv"]
