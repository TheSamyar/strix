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
        (
            "sslscan",
            "target.tld:443",
            ["--no-failed"],
            ["sslscan", "target.tld:443", "--no-failed"],
        ),
        (
            "sstimap",
            "https://x/page?name=a",
            ["-l", "1"],
            ["sstimap", "-u", "https://x/page?name=a", "-l", "1"],
        ),
        (
            "commix",
            "https://x/cmd?q=1",
            ["--level", "1"],
            ["commix", "-u", "https://x/cmd?q=1", "--batch", "--level", "1"],
        ),
        (
            "whatweb",
            "https://x",
            ["-a", "1"],
            ["whatweb", "https://x", "-a", "1"],
        ),
        (
            "crlfuzz",
            "https://x",
            ["-s"],
            ["crlfuzz", "-u", "https://x", "-s"],
        ),
        (
            "searchsploit",
            "apache 2.4",
            ["-j"],
            ["searchsploit", "apache 2.4", "-j"],
        ),
        ("hashid", "$1$abc", ["-j"], ["hashid", "$1$abc", "-j"]),
        (
            "wpscan",
            "https://x",
            ["--enumerate", "vp"],
            ["wpscan", "--url", "https://x", "--enumerate", "vp"],
        ),
        (
            "nikto",
            "https://x",
            ["-Tuning", "9"],
            ["nikto", "-host", "https://x", "-Tuning", "9"],
        ),
        (
            "dalfox",
            "https://x/?q=1",
            ["--deep-domxss"],
            ["dalfox", "url", "https://x/?q=1", "--deep-domxss"],
        ),
        ("katana", "https://x", ["-jc"], ["katana", "-u", "https://x", "-jc"]),
        (
            "subfinder",
            "example.com",
            ["-silent"],
            ["subfinder", "-d", "example.com", "-silent"],
        ),
        ("arjun", "https://x/api", ["-m", "GET"], ["arjun", "-u", "https://x/api", "-m", "GET"]),
        (
            "naabu",
            "1.2.3.4",
            ["-top-ports", "100"],
            ["naabu", "-host", "1.2.3.4", "-top-ports", "100"],
        ),
        ("gau", "example.com", ["--threads", "5"], ["gau", "example.com", "--threads", "5"]),
        ("dnsx", "example.com", ["-a"], ["dnsx", "-d", "example.com", "-a"]),
        (
            "dirsearch",
            "https://x",
            ["--plain-text-report", "out.txt"],
            ["dirsearch", "-u", "https://x", "--plain-text-report", "out.txt"],
        ),
        ("wafw00f", "https://x", [], ["wafw00f", "https://x"]),
        (
            "trufflehog",
            "/repo",
            ["--no-verification"],
            ["trufflehog", "filesystem", "/repo", "--no-verification"],
        ),
        ("retire", "/repo", [], ["retire", "--path", "/repo"]),
        (
            "amass",
            "example.com",
            ["-passive"],
            ["amass", "enum", "-d", "example.com", "-passive"],
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


def test_every_allowlisted_web_tool_has_a_skill_doc() -> None:
    """Each run_scanner allowlist entry ships a tooling skill so agents know its
    syntax. Guards the allowlist<->skill drift that left amass undocumented."""
    import re
    from pathlib import Path

    from strix.tools.run_scanner.tools import _ALLOWLIST

    skill_dir = Path(__file__).resolve().parents[1] / "strix" / "skills" / "tooling"
    skills = {p.stem for p in skill_dir.glob("*.md")}
    missing = sorted(set(_ALLOWLIST) - skills)
    assert not missing, f"allowlisted tools without a tooling skill: {missing}"

    # No skill's run_scanner(tool="X") example may reference an off-allowlist tool.
    bad: list[str] = []
    for md in skill_dir.glob("*.md"):
        for tool in re.findall(r'run_scanner\(tool="([a-z0-9_]+)"', md.read_text()):
            if tool not in _ALLOWLIST:
                bad.append(f"{md.name}:{tool}")
    assert not bad, f"skills referencing non-allowlisted run_scanner tools: {bad}"
