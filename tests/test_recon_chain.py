"""Recon macro chaining: subfinder → httpx → nuclei, with the binaries mocked."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from strix.tools.recon import tools


def _fake_proc(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_is_bare_domain() -> None:
    assert tools._is_bare_domain("example.com")
    assert not tools._is_bare_domain("https://example.com")
    assert not tools._is_bare_domain("example.com/app")


def test_lines_caps() -> None:
    assert tools._lines("a\n\nb\nc\n", cap=2) == ["a", "b"]


def test_chain_bare_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/usr/bin/x")
    calls: list[list[str]] = []

    def fake_run(argv: list[str], *, stdin: str | None, timeout: int) -> Any:
        calls.append(argv)
        if argv[0] == "subfinder":
            return _fake_proc("api.example.com\nexample.com\n")
        if argv[0] == "httpx":
            return _fake_proc("https://api.example.com\n")
        if argv[0] == "nuclei":
            return _fake_proc('{"template-id":"cve-x","info":{"severity":"high"}}\n')
        raise AssertionError(argv)

    monkeypatch.setattr(tools, "_run", fake_run)
    out = tools._recon_impl("example.com", "high", 400)

    assert [c[0] for c in calls] == ["subfinder", "httpx", "nuclei"]
    assert out["success"] and out["live"] == 1 and out["count"] == 1
    assert out["findings"][0]["template_id"] == "cve-x"


def test_url_skips_subfinder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/usr/bin/x")
    seen: list[str] = []

    def fake_run(argv: list[str], *, stdin: str | None, timeout: int) -> Any:
        seen.append(argv[0])
        if argv[0] == "httpx":
            return _fake_proc("https://example.com/app\n")
        return _fake_proc("")  # nuclei: no findings

    monkeypatch.setattr(tools, "_run", fake_run)
    out = tools._recon_impl("https://example.com/app", None, 400)

    assert "subfinder" not in seen
    assert out["success"] and out["count"] == 0


def test_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools.shutil, "which", lambda _: None)
    out = tools._recon_impl("example.com", "high", 400)
    assert not out["success"] and "not found" in out["error"]
