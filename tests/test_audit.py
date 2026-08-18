from __future__ import annotations

import contextlib
import importlib
import json
import os
import signal
import stat
import sys
import threading
import time
from argparse import Namespace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import strix.audit as audit_mod


if TYPE_CHECKING:
    import subprocess

from strix.audit import (
    AuditJob,
    JobResult,
    audit_exit_code,
    claude_argv,
    codex_argv,
    codex_worktree_argv,
    cursor_argv,
    first_local_path,
    jobs_for_mode,
    load_worker_reports,
    mcp_argv,
    plan_isolation,
    remint_ids,
    resolve_agent,
    run_jobs,
    targets_info_for_audit,
    worker_prompt,
    write_mcp_config_json,
    write_parent_reports,
)
from strix.interface.audit import parse_audit_args, run_audit


main_mod = importlib.import_module("strix.interface.main")


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


def test_isolation_codex_git_uses_detach(tmp_path: Path) -> None:
    plan = plan_isolation(
        "codex", "recon", tmp_path / "src", tmp_path, tmp_path / "wt", is_git=True
    )
    assert plan.sequential is False
    assert plan.worktree == tmp_path / "wt" / "recon"
    assert "--detach" in codex_worktree_argv(plan.worktree)


def test_isolation_claude_has_no_diy_worktree(tmp_path: Path) -> None:
    src = tmp_path / "src"
    plan = plan_isolation("claude", "recon", src, tmp_path, tmp_path / "wt", is_git=True)
    assert plan.worktree is None
    assert plan.worker_cwd == src
    assert plan.sequential is False


def test_isolation_cursor_git_is_sequential(tmp_path: Path) -> None:
    src = tmp_path / "src"
    plan = plan_isolation("cursor", "recon", src, tmp_path, tmp_path / "wt", is_git=True)
    assert plan.worktree is None
    assert plan.worker_cwd == src
    assert plan.sequential is True


def test_isolation_nongit_is_sequential(tmp_path: Path) -> None:
    src = tmp_path / "src"
    plan = plan_isolation("claude", "recon", src, tmp_path, tmp_path / "wt", is_git=False)
    assert plan.sequential is True
    assert plan.worktree is None


def test_isolation_cursor_url_only_is_sequential(tmp_path: Path) -> None:
    plan = plan_isolation("cursor", "auth", None, tmp_path, tmp_path / "wt", is_git=False)
    assert plan.sequential is True
    assert plan.worker_cwd == tmp_path


def test_exit_codes() -> None:
    ok = JobResult("recon", 0, timed_out=False)
    bad = JobResult("auth", 1, timed_out=False)
    dead = JobResult("inj", 1, timed_out=True)
    assert audit_exit_code([ok], 0) == 0
    assert audit_exit_code([ok, bad], 2) == 2
    assert audit_exit_code([bad, dead], 0) == 1


def test_worker_prompt_includes_skills_and_no_subagents() -> None:
    job = AuditJob("auth", "Auth specialist", ("csrf",), "Test CSRF.")
    text = worker_prompt(job, [{"type": "local_code", "original": "./app"}], "focus login")
    assert "Auth specialist" in text
    assert "load_skill" in text and "csrf" in text
    assert "create_vulnerability_report" in text
    assert "Do not spawn sub-agents" in text
    assert "AUDIT_JOB_DONE" in text
    assert "focus login" in text
    assert "./app" in text


def test_first_local_path(tmp_path: Path) -> None:
    app = tmp_path / "app"
    info = [
        {"type": "web_application", "details": {}, "original": "https://x"},
        {"type": "local_code", "details": {"target_path": str(app)}, "original": "./app"},
    ]
    assert first_local_path(info) == app


def test_parse_audit_help() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_audit_args(["--help"])
    assert exc.value.code == 0


def test_parse_requires_target() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_audit_args(["--agent", "claude"])
    assert exc.value.code == 2


def test_parse_defaults_quick() -> None:
    args = parse_audit_args(["-t", "./"])
    assert args.scan_mode == "quick"
    assert args.max_workers == 3
    assert args.timeout == 3600


def test_targets_info_keeps_localhost() -> None:
    ns = Namespace(target=["http://127.0.0.1:8080"], target_list=None)
    info = targets_info_for_audit(ns)
    assert "127.0.0.1" in info[0]["details"]["target_url"]
    assert "host.docker.internal" not in info[0]["details"]["target_url"]


def test_run_name_rejects_dotdot() -> None:
    with pytest.raises(SystemExit):
        parse_audit_args(["-t", "./", "--run-name", "../escape"])


def test_main_audit_help_never_parses_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main_mod.sys, "argv", ["strix", "audit", "--help"])

    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("scan path must not run")

    monkeypatch.setattr(main_mod, "parse_arguments", boom)
    with pytest.raises(SystemExit) as exc:
        main_mod.main()
    assert exc.value.code == 0


def test_run_audit_fake_claude_exit_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "claude"
    fake.write_text("#!/bin/sh\necho AUDIT_JOB_DONE\nexit 0\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    (tmp_path / "app").mkdir()
    code = run_audit(["-t", str(tmp_path / "app"), "--agent", "claude", "--run-name", "t1"])
    assert code == 0
    recorded = (tmp_path / "strix_runs" / "t1" / "run.json").is_file()
    assert recorded


def test_run_audit_missing_agent_exits_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir()
    (tmp_path / "app").mkdir()
    assert run_audit(["-t", str(tmp_path / "app"), "--agent", "claude"]) == 1


def test_run_jobs_cursor_restores_workspace_mcp(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    (app / ".git").mkdir(parents=True)
    cursor_dir = app / ".cursor"
    cursor_dir.mkdir(parents=True)
    workspace_mcp = cursor_dir / "mcp.json"
    original = '{"mcpServers":{"existing":{}}}'
    workspace_mcp.write_text(original, encoding="utf-8")
    fake = tmp_path / "cursor-agent"
    active = tmp_path / "cursor-active"
    fake.write_text(
        f"#!/bin/sh\nmkdir {active!s} || exit 23\nsleep 0.1\nrmdir {active!s}\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    parent = tmp_path / "strix_runs" / "cursor-restore"
    jobs = [
        AuditJob("recon", "Recon specialist", ("asset_discovery",), "Map it."),
        AuditJob("auth", "Auth specialist", ("csrf",), "Test it."),
    ]

    results, findings = run_jobs(
        jobs,
        agent="cursor",
        binary=str(fake),
        targets_info=[
            {
                "type": "local_code",
                "details": {"target_path": str(app)},
                "original": str(app),
            }
        ],
        original_cwd=tmp_path,
        parent=parent,
        instruction="",
        max_workers=2,
        timeout=10,
    )

    assert results == [
        JobResult("recon", 0, timed_out=False),
        JobResult("auth", 0, timed_out=False),
    ]
    assert findings == 0
    assert workspace_mcp.read_text(encoding="utf-8") == original
    assert not (cursor_dir / ".mcp.json.strix-audit.bak").exists()


def test_run_jobs_kills_sequential_worker_on_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    pid_path = tmp_path / "worker.pid"
    fake = tmp_path / "claude"
    fake.write_text(
        f"#!/bin/sh\necho $$ > {pid_path!s}\nexec sleep 60\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    def interrupt_communicate(self: subprocess.Popen[bytes], timeout: int | None = None) -> None:
        del self, timeout
        deadline = time.monotonic() + 2
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        raise KeyboardInterrupt

    monkeypatch.setattr("subprocess.Popen.communicate", interrupt_communicate)
    try:
        with pytest.raises(KeyboardInterrupt):
            run_jobs(
                [AuditJob("recon", "Recon specialist", ("asset_discovery",), "Map it.")],
                agent="claude",
                binary=str(fake),
                targets_info=[
                    {
                        "type": "local_code",
                        "details": {"target_path": str(app)},
                        "original": str(app),
                    }
                ],
                original_cwd=tmp_path,
                parent=tmp_path / "strix_runs" / "interrupt",
                instruction="",
                max_workers=1,
                timeout=10,
            )
        pid = int(pid_path.read_text(encoding="utf-8"))
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    finally:
        if pid_path.exists():
            pid = int(pid_path.read_text(encoding="utf-8"))
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pid, signal.SIGKILL)


def test_run_jobs_does_not_spawn_parallel_worker_after_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app"
    (app / ".git").mkdir(parents=True)
    fake = tmp_path / "claude"
    fake.write_text("#!/bin/sh\nexec sleep 60\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    release_setup = threading.Event()
    config_calls = 0
    config_lock = threading.Lock()
    original_config = audit_mod.write_mcp_config_json

    def delayed_second_config(command: str, args: list[str]) -> dict[str, object]:
        nonlocal config_calls
        with config_lock:
            config_calls += 1
            call = config_calls
        if call == 2:
            assert release_setup.wait(2)
        return original_config(command, args)

    spawned: list[subprocess.Popen[bytes]] = []
    original_popen = audit_mod.subprocess.Popen

    def tracked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        proc = original_popen(*args, **kwargs)
        spawned.append(proc)
        return proc

    def interrupt_first_communicate(
        self: subprocess.Popen[bytes], timeout: int | None = None
    ) -> None:
        del self, timeout
        if not release_setup.is_set():
            release_setup.set()
            raise KeyboardInterrupt

    monkeypatch.setattr(audit_mod, "write_mcp_config_json", delayed_second_config)
    monkeypatch.setattr(original_popen, "communicate", interrupt_first_communicate)
    monkeypatch.setattr(audit_mod.subprocess, "Popen", tracked_popen)

    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        run_jobs(
            [
                AuditJob("recon", "Recon specialist", ("asset_discovery",), "Map it."),
                AuditJob("auth", "Auth specialist", ("csrf",), "Test it."),
            ],
            agent="claude",
            binary=str(fake),
            targets_info=[
                {
                    "type": "local_code",
                    "details": {"target_path": str(app)},
                    "original": str(app),
                }
            ],
            original_cwd=tmp_path,
            parent=tmp_path / "strix_runs" / "parallel-interrupt",
            instruction="",
            max_workers=2,
            timeout=3600,
        )

    assert time.monotonic() - started < 2
    assert len(spawned) == 1
