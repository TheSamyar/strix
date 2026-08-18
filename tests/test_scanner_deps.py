"""Tests for the scanner dependency registry + installer."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from strix.tools.scanner_deps import tools as sd


def test_tool_status_shape() -> None:
    status = sd.tool_status()
    names = {s.name for s in sd.SCANNERS}
    assert set(status) == names
    for entry in status.values():
        assert set(entry) == {"installed", "binary", "path", "note"}
        assert isinstance(entry["installed"], bool)


def test_install_skips_already_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sd.shutil, "which", lambda _b: "/usr/bin/found")
    called = False

    def _no_run(_argv: list[str]) -> tuple[bool, str]:
        nonlocal called
        called = True
        return True, "x"

    monkeypatch.setattr(sd, "_run_install", _no_run)
    results = sd.install_tools(["nmap"])
    assert results["nmap"]["status"] == "already"
    assert called is False


def test_install_runs_first_available_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    # nmap missing; only apt-get available → should run the apt candidate.
    monkeypatch.setattr(sd.shutil, "which", lambda b: None if b == "nmap" else "/bin/x")
    monkeypatch.setattr(sd, "_available_managers", lambda: {"apt-get"})
    ran: list[list[str]] = []

    def _fake_run(argv: list[str], **_kw: Any) -> tuple[bool, str]:
        ran.append(argv)
        return True, " ".join(argv)

    monkeypatch.setattr(sd, "_run_install", _fake_run)
    results = sd.install_tools(["nmap"])
    assert results["nmap"]["status"] == "installed"
    assert ran == [["apt-get", "install", "-y", "nmap"]]


def test_install_skipped_when_no_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sd.shutil, "which", lambda _b: None)
    monkeypatch.setattr(sd, "_available_managers", set)
    results = sd.install_tools(["gitleaks"])
    assert results["gitleaks"]["status"] == "skipped"


def test_install_falls_through_to_next_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    # ffuf missing; brew present but fails → falls through to go.
    monkeypatch.setattr(sd.shutil, "which", lambda b: None if b == "ffuf" else "/bin/x")
    monkeypatch.setattr(sd, "_available_managers", lambda: {"brew", "go"})

    def _fake_run(argv: list[str], **_kw: Any) -> tuple[bool, str]:
        if argv[0] == "brew":
            return False, "brew boom"
        return True, " ".join(argv)

    monkeypatch.setattr(sd, "_run_install", _fake_run)
    results = sd.install_tools(["ffuf"])
    assert results["ffuf"]["status"] == "installed"
    assert results["ffuf"]["detail"].startswith("go install")


def test_run_install_no_shell_and_sudo_for_apt(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sd.subprocess, "run", _fake_run)
    monkeypatch.setattr(sd.shutil, "which", lambda _b: "/usr/bin/sudo")
    monkeypatch.setattr(sd.os, "geteuid", lambda: 1000, raising=False)
    ok, _detail = sd._run_install(["apt-get", "install", "-y", "nmap"])
    assert ok is True
    assert captured["cmd"][0] == "sudo"
    # never shell=True
    assert captured["kwargs"].get("shell", False) is False


def test_missing_tools_reflects_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sd.shutil, "which", lambda _b: None)
    assert sorted(sd.missing_tools()) == sorted(s.name for s in sd.SCANNERS)


def test_to_upgrade_per_manager() -> None:
    assert sd._to_upgrade(["brew", "install", "nmap"]) == ["brew", "upgrade", "nmap"]
    assert sd._to_upgrade(["pipx", "install", "sqlmap"]) == ["pipx", "upgrade", "sqlmap"]
    assert sd._to_upgrade(["gem", "install", "wpscan"]) == ["gem", "update", "wpscan"]
    assert sd._to_upgrade(["apt-get", "install", "-y", "nmap"]) == [
        "apt-get",
        "install",
        "--only-upgrade",
        "-y",
        "nmap",
    ]
    # go @latest already upgrades → unchanged
    goc = ["go", "install", "github.com/ffuf/ffuf/v2@latest"]
    assert sd._to_upgrade(goc) == goc


def test_upgrade_runs_upgrade_form_for_present_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    # nmap present; brew available → should run `brew upgrade nmap`, status upgraded.
    monkeypatch.setattr(sd.shutil, "which", lambda b: "/bin/x" if b in {"nmap", "sudo"} else None)
    monkeypatch.setattr(sd, "_available_managers", lambda: {"brew"})
    ran: list[list[str]] = []

    def _fake_run(argv: list[str], **_kw: Any) -> tuple[bool, str]:
        ran.append(argv)
        return True, " ".join(argv)

    monkeypatch.setattr(sd, "_run_install", _fake_run)
    results = sd.install_tools(["nmap"], upgrade=True)
    assert results["nmap"]["status"] == "upgraded"
    assert ["brew", "upgrade", "nmap"] in ran


def test_upgrade_refreshes_nuclei_templates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sd.shutil, "which", lambda b: "/bin/x" if b == "nuclei" else None)
    monkeypatch.setattr(sd, "_available_managers", lambda: {"brew"})
    ran: list[list[str]] = []

    def _fake_run(argv: list[str], **_kw: Any) -> tuple[bool, str]:
        ran.append(argv)
        return True, " ".join(argv)

    monkeypatch.setattr(sd, "_run_install", _fake_run)
    results = sd.install_tools(["nuclei"], upgrade=True)
    assert results["nuclei-templates"]["status"] == "upgraded"
    assert ["nuclei", "-update-templates"] in ran


def test_run_install_skips_sudo_when_disallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sd.os, "geteuid", lambda: 1000, raising=False)
    called = False

    def _boom(*_a: Any, **_k: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr(sd.subprocess, "run", _boom)
    ok, detail = sd._run_install(["apt-get", "install", "-y", "nmap"], allow_sudo=False)
    assert ok is False
    assert "sudo" in detail
    assert called is False


def test_is_stale_true_when_no_marker(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setattr(sd, "_MARKER", tmp_path / "none.json")
    monkeypatch.delenv("STRIX_TOOL_AUTOUPDATE_DAYS", raising=False)
    assert sd.is_stale() is True


def test_is_stale_false_when_fresh(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    marker = tmp_path / "m.json"
    monkeypatch.setattr(sd, "_MARKER", marker)
    sd._mark_updated()  # writes now
    assert sd.is_stale(7) is False


def test_auto_update_disabled_with_zero_days(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_TOOL_AUTOUPDATE_DAYS", "0")
    monkeypatch.setattr(sd, "install_tools", lambda **_k: pytest.fail("must not install"))
    assert sd.auto_update_if_stale() is None


def test_auto_update_runs_when_stale(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setattr(sd, "_MARKER", tmp_path / "m.json")
    monkeypatch.delenv("STRIX_TOOL_AUTOUPDATE_DAYS", raising=False)
    seen: dict[str, Any] = {}

    def _fake_install(**kwargs: Any) -> dict[str, dict[str, object]]:
        seen.update(kwargs)
        return {"nmap": {"status": "upgraded", "detail": "brew upgrade nmap"}}

    monkeypatch.setattr(sd, "install_tools", _fake_install)
    results = sd.auto_update_if_stale()
    assert results is not None
    assert seen == {"upgrade": True, "allow_sudo": False}  # non-interactive upgrade
    assert (tmp_path / "m.json").exists()  # marker written


def test_render_report_flags_failures() -> None:
    report = sd.render_install_report(
        {
            "nmap": {"status": "installed", "detail": "brew install nmap"},
            "wpscan": {"status": "failed", "detail": "gem boom"},
        }
    )
    assert "nmap" in report
    assert "Install manually: wpscan" in report
