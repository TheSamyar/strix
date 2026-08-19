"""gitleaks_scan: parse findings, return secrets, degrade when binary missing."""

from __future__ import annotations

import hashlib
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


def test_parses_and_returns_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks_tools.shutil, "which", lambda _: "/usr/bin/gitleaks")
    monkeypatch.setattr(gitleaks_tools.subprocess, "run", _fake_run_writing(_SAMPLE_REPORT))

    result = gitleaks_tools._scan_impl("/repo", no_git=False)
    assert result["count"] == 1
    finding = result["findings"][0]
    assert finding["rule"] == "aws-access-token"
    assert finding["file"] == "config/prod.env"
    assert finding["line"] == 12
    assert finding["commit"] == "abc123"
    assert finding["secret"] == _SAMPLE_SECRET


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


def test_shannon_entropy() -> None:
    assert gitleaks_tools._shannon_entropy("") == 0.0
    assert gitleaks_tools._shannon_entropy("aaaa") == 0.0  # zero entropy
    # A random-looking key has higher entropy than a repeated string.
    high = gitleaks_tools._shannon_entropy("aA1!bB2@cC3#")
    assert high > gitleaks_tools._shannon_entropy("aaaabbbb")


def test_findings_carry_entropy_and_sort(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gitleaks_tools.shutil, "which", lambda _: "/usr/bin/gitleaks")
    report = [
        {"RuleID": "low", "File": "a", "StartLine": 1, "Secret": "aaaaaaaa"},
        {"RuleID": "high", "File": "b", "StartLine": 2, "Secret": "aA1!bB2@cC3#dD4$"},
    ]
    monkeypatch.setattr(gitleaks_tools.subprocess, "run", _fake_run_writing(report))
    result = gitleaks_tools._scan_impl("/repo", no_git=False)
    # highest-entropy first
    assert result["findings"][0]["rule"] == "high"
    assert all("entropy" in f for f in result["findings"])


def test_hibp_k_anonymity_match() -> None:
    secret = "password"
    suffix = hashlib.sha1(secret.encode()).hexdigest().upper()[5:]  # noqa: S324

    def fetcher(prefix: str) -> str:
        return f"0000000000000000000000000000000000A:1\r\n{suffix}:42"

    assert gitleaks_tools.hibp_pwned_count(secret, fetcher=fetcher) == 42


def test_hibp_no_match_and_error() -> None:
    assert gitleaks_tools.hibp_pwned_count("x", fetcher=lambda _p: "DEADBEEF:9") == 0
    assert gitleaks_tools.hibp_pwned_count("", fetcher=lambda _p: "") is None

    def boom(_prefix: str) -> str:
        raise OSError("down")

    assert gitleaks_tools.hibp_pwned_count("x", fetcher=boom) is None


def test_to_sarif() -> None:
    findings = [{"rule": "aws", "file": "config.env", "line": 3, "secret": "k"}]
    doc = gitleaks_tools.to_sarif(findings, "/repo")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "gitleaks"
    assert run["results"][0]["ruleId"] == "aws"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
