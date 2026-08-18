"""run_scanner: allowlist enforcement and list-argv (never shell=True) construction."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from strix.tools.run_scanner.tools import _run_scanner_impl


def test_off_allowlist_rejected_without_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("subprocess.run must not be called for a rejected tool")

    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr("strix.tools.run_scanner.tools.shutil.which", lambda _tool: "/usr/bin/x")

    result = _run_scanner_impl("rm", "target", ["-rf", "/"], 300)
    assert result["success"] is False
    assert "not allowlisted" in result["error"]


@pytest.mark.parametrize(
    ("tool", "target", "extra", "expected_argv"),
    [
        ("nmap", "1.2.3.4", ["-sV"], ["nmap", "1.2.3.4", "-sV"]),
        (
            "sqlmap",
            "https://x/y?id=1",
            ["--level", "5"],
            ["sqlmap", "-u", "https://x/y?id=1", "--batch", "--level", "5"],
        ),
    ],
)
def test_argv_built_as_list_never_shell(
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    target: str,
    extra: list[str],
    expected_argv: list[str],
) -> None:
    calls: dict[str, Any] = {}

    def _fake_run(argv: Any, **kwargs: Any) -> Any:
        calls["argv"] = argv
        calls["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, stdout="out", stderr="err")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    monkeypatch.setattr("strix.tools.run_scanner.tools.shutil.which", lambda _tool: "/usr/bin/x")

    result = _run_scanner_impl(tool, target, extra, 300)

    assert isinstance(calls["argv"], list)
    assert calls["argv"] == expected_argv
    # extra_args land as separate argv elements, not one joined string.
    for token in extra:
        assert token in calls["argv"]
    assert "shell" not in calls["kwargs"]  # never shell=True
    assert result["argv"] == expected_argv
    assert result["returncode"] == 0


def test_not_installed_returns_structured_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("subprocess.run must not run when binary is missing")

    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr("strix.tools.run_scanner.tools.shutil.which", lambda _tool: None)

    result = _run_scanner_impl("nmap", "1.2.3.4", None, 300)
    assert result["success"] is False
    assert "not installed" in result["error"]
