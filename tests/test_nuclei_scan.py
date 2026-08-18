"""nuclei_scan tool: JSONL parsing, missing binary, and timeout handling."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from strix.tools.nuclei_scan.tools import _scan_impl


if TYPE_CHECKING:
    import pytest


_SAMPLE_JSONL = (
    '{"template-id":"CVE-2021-1234","info":{"name":"Example RCE",'
    '"severity":"critical","description":"Remote code execution."},'
    '"matched-at":"https://t.example.com/a"}\n'
    '{"template-id":"tech-detect","info":{"name":"Nginx",'
    '"severity":"info","description":"Detected Nginx."},'
    '"matched-at":"https://t.example.com"}\n'
)


def test_parses_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/nuclei")

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_JSONL, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = _scan_impl("https://t.example.com", None, None, 300)
    assert result["success"] is True
    assert result["count"] == 2
    first = result["findings"][0]
    assert first == {
        "template_id": "CVE-2021-1234",
        "name": "Example RCE",
        "severity": "critical",
        "matched_at": "https://t.example.com/a",
        "description": "Remote code execution.",
    }


def test_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    result = _scan_impl("https://t.example.com", "high", None, 300)
    assert result["success"] is False
    assert result["hint"] == "install nuclei"


def test_timeout_returns_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/nuclei")

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=1, output=_SAMPLE_JSONL)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = _scan_impl("https://t.example.com", None, "cve", 1)
    assert result["success"] is False
    assert "timed out" in result["error"]
    assert result["count"] == 2
