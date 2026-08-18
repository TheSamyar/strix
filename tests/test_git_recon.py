"""git_recon over a real temp git repo."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from strix.tools.git_recon.tools import _git_recon_impl


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603, S607


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.name", "Ada Tester")
    _git(tmp_path, "config", "user.email", "ada@example.com")
    (tmp_path / "README.md").write_text("hello\n")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-m", "initial commit")
    (tmp_path / ".env").write_text("SECRET=shh\n")
    _git(tmp_path, "add", ".env")
    _git(tmp_path, "commit", "-m", "oops add env")
    return tmp_path


def test_git_recon_parses_history(repo: Path) -> None:
    result = _git_recon_impl(str(repo))
    assert result["success"] is True

    emails = {c["email"] for c in result["contributors"]}
    assert "ada@example.com" in emails

    subjects = [c["subject"] for c in result["recent_commits"]]
    assert "initial commit" in subjects
    assert len(result["recent_commits"]) == 2

    flagged = {f["path"] for f in result["sensitive_files"]}
    assert ".env" in flagged
    assert "README.md" not in flagged
    # No file contents leak into the report.
    assert "SECRET=shh" not in json.dumps(result)


def test_git_recon_non_repo(tmp_path: Path) -> None:
    result = _git_recon_impl(str(tmp_path))
    assert result["success"] is False
    assert "git repository" in result["error"]
