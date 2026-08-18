from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from strix.audit import (
    claude_argv,
    codex_argv,
    cursor_argv,
    jobs_for_mode,
    load_worker_reports,
    mcp_argv,
    remint_ids,
    resolve_agent,
    write_mcp_config_json,
    write_parent_reports,
)


def test_quick_has_four_jobs() -> None:
    jobs = jobs_for_mode("quick")
    assert [j.id for j in jobs] == ["recon", "auth", "injection", "access"]
    assert jobs[0].skills == ("asset_discovery",)
    assert jobs[2].skills == ("sql_injection", "xss", "rce")


def test_standard_extends_quick() -> None:
    ids = [j.id for j in jobs_for_mode("standard")]
    assert ids == ["recon", "auth", "injection", "access", "ssrf_files", "secrets_deps"]


def test_deep_extends_standard() -> None:
    ids = [j.id for j in jobs_for_mode("deep")]
    assert ids[-2:] == ["logic", "deser_ssti"]
    assert len(ids) == 8


def test_unknown_mode_raises() -> None:
    with pytest.raises(ValueError, match="scan-mode"):
        jobs_for_mode("turbo")


def test_mcp_argv_chdirs_then_passes_run_name() -> None:
    argv = mcp_argv("/repo", "run1/workers/recon")
    assert argv[0] == sys.executable
    assert argv[1] == "-c"
    assert "os.chdir(sys.argv[1])" in argv[2]
    assert "--run-name" not in argv[2]
    assert argv[3:] == ["/repo", "--run-name", "run1/workers/recon", "--no-seed"]


def test_resolve_agent_skips_cursor_ide(tmp_path: Path) -> None:
    claude = tmp_path / "claude"
    cursor_ide = tmp_path / "cursor"
    cursor_agent = tmp_path / "cursor-agent"
    claude.write_text("")
    cursor_ide.write_text("")
    cursor_agent.write_text("")

    def lookup(name: str) -> str | None:
        p = tmp_path / name
        return str(p) if p.exists() else None

    assert resolve_agent(None, path_lookup=lookup) == ("claude", str(claude))
    assert resolve_agent("cursor", path_lookup=lookup) == ("cursor", str(cursor_agent))
    with pytest.raises(FileNotFoundError, match="codex"):
        resolve_agent("codex", path_lookup=lookup)


def test_claude_argv_is_unattended() -> None:
    argv = claude_argv("claude", "do the job", Path("/tmp/mcp.json"))  # noqa: S108
    assert argv[:2] == ["claude", "-p"]
    assert "--dangerously-skip-permissions" in argv
    assert "--strict-mcp-config" in argv
    assert argv[argv.index("--mcp-config") + 1] == "/tmp/mcp.json"  # noqa: S108
    assert "do the job" in argv


def test_cursor_argv_never_uses_ide_binary() -> None:
    argv = cursor_argv("cursor-agent", "do the job", Path("/ws"))
    assert argv[0] == "cursor-agent"
    assert "--force" in argv
    assert "--approve-mcps" in argv
    assert "--sandbox" in argv
    assert argv[argv.index("--workspace") + 1] == "/ws"
    assert "cursor" != argv[0] or argv[0] == "cursor-agent"  # noqa: SIM300


def test_codex_argv_injects_mcp_via_dash_c() -> None:
    argv = codex_argv("codex", "do the job", Path("/wt"), "/repo", "run1/workers/recon")
    joined = " ".join(argv)
    assert argv[:2] == ["codex", "exec"]
    assert "--dangerously-bypass-approvals-and-sandbox" in argv
    assert "-C" in argv
    assert "mcp_servers.strix_audit" in joined
    assert "--no-seed" in joined


def test_mcp_config_json_schema() -> None:
    cfg = write_mcp_config_json("/usr/bin/python", ["-c", "x", "/repo"])
    server = cfg["mcpServers"]["strix"]
    assert server["type"] == "stdio"
    assert server["command"] == "/usr/bin/python"
    assert server["args"][0] == "-c"


def _finding(vid: str, title: str) -> dict[str, object]:
    return {
        "id": vid,
        "title": title,
        "severity": "high",
        "timestamp": "2026-08-18 00:00:00 UTC",
    }


def test_remint_keeps_colliding_worker_ids(tmp_path: Path) -> None:
    parent = tmp_path / "run"
    for job, title in (("recon", "XSS"), ("auth", "JWT none")):
        d = parent / "workers" / job
        d.mkdir(parents=True)
        (d / "vulnerabilities.json").write_text(
            json.dumps([_finding("vuln-0001", title)]), encoding="utf-8"
        )
    raw = load_worker_reports(parent, ["recon", "auth"])
    minted = remint_ids(raw)
    assert [r["id"] for r in minted] == ["vuln-0001", "vuln-0002"]
    assert [r["title"] for r in minted] == ["XSS", "JWT none"]
    write_parent_reports(parent, minted, jobs_summary="recon ok\nauth ok")
    saved = json.loads((parent / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert [r["id"] for r in saved] == ["vuln-0001", "vuln-0002"]
    assert (parent / "vulnerabilities" / "vuln-0002.md").is_file()
    assert (parent / "findings.sarif").is_file()
    assert "JWT none" in (parent / "penetration_test_report.md").read_text(encoding="utf-8")


def test_load_skips_missing_and_corrupt(tmp_path: Path) -> None:
    parent = tmp_path / "run"
    (parent / "workers" / "recon").mkdir(parents=True)
    (parent / "workers" / "recon" / "vulnerabilities.json").write_text("{", encoding="utf-8")
    assert load_worker_reports(parent, ["recon", "auth"]) == []
