from __future__ import annotations

import json  # noqa: F401
import sys
from pathlib import Path

import pytest

from strix.audit import (
    claude_argv,
    codex_argv,
    cursor_argv,
    jobs_for_mode,
    mcp_argv,
    resolve_agent,
    write_mcp_config_json,
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
