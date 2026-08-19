"""local_security_scan: safe local scanner dispatch and structured output."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

import pytest

from strix.tools.local_scan.tools import _scan_impl


if TYPE_CHECKING:
    from pathlib import Path


def test_rejects_unknown_scanner_without_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: pytest.fail("ran"))
    result = _scan_impl("rm", ".", 60)
    assert result["success"] is False
    assert "not allowlisted" in result["error"]


def test_missing_target_is_structured_error() -> None:
    result = _scan_impl("trivy_fs", "/path/that/does/not/exist", 60)
    assert result == {"success": False, "error": "Path not found: /path/that/does/not/exist"}


def test_builds_fixed_argv_and_preserves_json_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: dict[str, Any] = {}

    def fake_run(argv: Any, **kwargs: Any) -> Any:
        calls["argv"] = argv
        calls["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 1, stdout='{"Results": []}', stderr="warning")

    monkeypatch.setattr("strix.tools.local_scan.tools.shutil.which", lambda _: "/bin/tool")
    monkeypatch.setattr("strix.tools.local_scan.tools.subprocess.run", fake_run)

    result = _scan_impl("trivy_fs", str(tmp_path), 42)

    assert result["success"] is True
    assert calls["argv"] == [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        "vuln,misconfig,secret",
        str(tmp_path),
    ]
    assert "shell" not in calls["kwargs"]
    assert result["stdout"] == '{"Results": []}'
    assert result["returncode"] == 1
