"""Playbook + vendor adapters for `strix audit`."""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.interface.scan_setup import _resolve_api_spec
from strix.interface.utils import (
    assign_workspace_subdirs,
    dedupe_local_targets,
    infer_target_type,
    read_target_list_file,
)
from strix.report.sarif import write_sarif
from strix.report.writer import write_executive_report, write_vulnerabilities


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

logger = logging.getLogger(__name__)


SCAN_MODES = ("quick", "standard", "deep")


@dataclass(frozen=True)
class AuditJob:
    id: str
    title: str
    skills: tuple[str, ...]
    task: str


_QUICK: tuple[AuditJob, ...] = (
    AuditJob(
        "recon",
        "Recon specialist",
        ("asset_discovery",),
        "Map the attack surface. Do not deep-exploit.",
    ),
    AuditJob(
        "auth",
        "Auth specialist",
        ("authentication_jwt", "csrf"),
        "Test authentication, session, JWT, and CSRF.",
    ),
    AuditJob(
        "injection",
        "Injection specialist",
        ("sql_injection", "xss", "rce"),
        "Test SQLi, XSS, and RCE. Prove with a PoC before filing.",
    ),
    AuditJob(
        "access",
        "Access-control specialist",
        ("idor", "broken_function_level_authorization"),
        "Test IDOR and broken function-level authorization.",
    ),
)
_STANDARD_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "ssrf_files",
        "SSRF and files specialist",
        ("ssrf", "path_traversal_lfi_rfi", "insecure_file_uploads"),
        "Test SSRF, path traversal, and file uploads.",
    ),
    AuditJob(
        "secrets_deps",
        "Secrets and deps specialist",
        ("information_disclosure", "dependency_cve_scanning"),
        "Find secrets and known-CVE dependencies.",
    ),
)
_DEEP_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "logic",
        "Logic specialist",
        ("business_logic", "race_conditions"),
        "Test business logic and race conditions.",
    ),
    AuditJob(
        "deser_ssti",
        "Deser/SSTI specialist",
        ("insecure_deserialization", "ssti"),
        "Test insecure deserialization and SSTI.",
    ),
)


def jobs_for_mode(mode: str) -> tuple[AuditJob, ...]:
    if mode == "quick":
        return _QUICK
    if mode == "standard":
        return _QUICK + _STANDARD_EXTRA
    if mode == "deep":
        return _QUICK + _STANDARD_EXTRA + _DEEP_EXTRA
    raise ValueError(f"unknown scan-mode {mode!r}; expected one of {SCAN_MODES}")


MCP_CHDIR_SNIPPET = (
    "import os,sys; os.chdir(sys.argv[1]); "
    "from strix.interface.mcp_server import run_mcp; "
    "raise SystemExit(run_mcp(sys.argv[2:]))"
)

VENDOR_BINARIES: dict[str, tuple[str, ...]] = {
    "claude": ("claude",),
    "cursor": ("cursor-agent", "agent"),
    "codex": ("codex",),
}
PATH_DEFAULT_ORDER = ("claude", "cursor", "codex")
AGENT_HINTS = {
    "claude": "Install Claude Code and ensure `claude` is on PATH.",
    "cursor": (
        "Install Cursor Agent (`cursor-agent` or `agent`). The `cursor` IDE binary is not an agent."
    ),
    "codex": "Install Codex and ensure `codex` is on PATH.",
}


def mcp_argv(original_cwd: str, run_name: str) -> list[str]:
    return [
        sys.executable,
        "-c",
        MCP_CHDIR_SNIPPET,
        original_cwd,
        "--run-name",
        run_name,
        "--no-seed",
    ]


def write_mcp_config_json(command: str, args: list[str]) -> dict[str, Any]:
    return {
        "mcpServers": {
            "strix": {"type": "stdio", "command": command, "args": args},
        }
    }


def resolve_agent(
    explicit: str | None,
    *,
    path_lookup: Callable[[str], str | None],
) -> tuple[str, str]:
    if explicit is not None:
        if explicit not in VENDOR_BINARIES:
            raise ValueError(f"unknown agent {explicit!r}")
        for name in VENDOR_BINARIES[explicit]:
            found = path_lookup(name)
            if found:
                return explicit, found
        raise FileNotFoundError(AGENT_HINTS[explicit])
    for agent in PATH_DEFAULT_ORDER:
        for name in VENDOR_BINARIES[agent]:
            found = path_lookup(name)
            if found:
                return agent, found
    raise FileNotFoundError(" ".join(AGENT_HINTS.values()))


def claude_argv(
    binary: str,
    prompt: str,
    mcp_config: Path,
    worktree_name: str | None = None,
) -> list[str]:
    argv = [
        binary,
        "-p",
        "--dangerously-skip-permissions",
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
        "--output-format",
        "json",
    ]
    if worktree_name:
        argv.extend(["-w", worktree_name])
    return [*argv, prompt]


def cursor_argv(binary: str, prompt: str, workspace: Path) -> list[str]:
    return [
        binary,
        "-p",
        "--force",
        "--sandbox",
        "disabled",
        "--approve-mcps",
        "--trust",
        "--workspace",
        str(workspace),
        prompt,
    ]


def codex_argv(
    binary: str,
    prompt: str,
    worker_cwd: Path,
    original_cwd: str,
    run_name: str,
) -> list[str]:
    mcp = mcp_argv(original_cwd, run_name)
    args_json = json.dumps(mcp[1:])
    return [
        binary,
        "exec",
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "-C",
        str(worker_cwd),
        "-c",
        f"mcp_servers.strix_audit.command={json.dumps(mcp[0])}",
        "-c",
        f"mcp_servers.strix_audit.args={args_json}",
        "-c",
        f"mcp_servers.strix_audit.cwd={json.dumps(original_cwd)}",
        prompt,
    ]


def load_worker_reports(parent: Path, job_ids: Sequence[str]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for job_id in job_ids:
        path = parent / "workers" / job_id / "vulnerabilities.json"
        if not path.is_file():
            logger.warning("audit merge: missing %s", path)
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("audit merge: corrupt %s", path)
            continue
        if not isinstance(payload, list):
            logger.warning("audit merge: not a list %s", path)
            continue
        reports.extend(item for item in payload if isinstance(item, dict))
    return reports


def remint_ids(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    minted: list[dict[str, Any]] = []
    for index, report in enumerate(reports, start=1):
        updated = dict(report)
        updated["id"] = f"vuln-{index:04d}"
        minted.append(updated)
    return minted


def write_parent_reports(
    parent: Path,
    reports: list[dict[str, Any]],
    *,
    jobs_summary: str,
) -> None:
    parent.mkdir(parents=True, exist_ok=True)
    write_vulnerabilities(parent, reports, saved_vuln_ids=set())
    write_sarif(parent, reports)
    lines = ["## Jobs\n", jobs_summary, "\n## Findings\n"]
    if not reports:
        lines.append("No validated findings.\n")
    lines.extend(
        f"- `{report.get('id')}` {str(report.get('severity', '')).upper()} "
        f"{report.get('title', '')}\n"
        for report in reports
    )
    write_executive_report(parent, "".join(lines))


@dataclass(frozen=True)
class IsolationPlan:
    sequential: bool
    worker_cwd: Path
    worktree: Path | None


@dataclass(frozen=True)
class JobResult:
    job_id: str
    exit_code: int
    timed_out: bool


def first_local_path(targets_info: list[dict[str, Any]]) -> Path | None:
    for item in targets_info:
        if item.get("type") == "local_code":
            raw = item.get("details", {}).get("target_path")
            if raw:
                return Path(raw)
    return None


def plan_isolation(
    agent: str,
    job_id: str,
    local_path: Path | None,
    original_cwd: Path,
    tmp: Path,
    *,
    is_git: bool,
) -> IsolationPlan:
    if agent == "cursor":
        return IsolationPlan(
            sequential=True,
            worker_cwd=local_path or original_cwd,
            worktree=None,
        )
    if local_path is None:
        return IsolationPlan(sequential=False, worker_cwd=original_cwd, worktree=None)
    if not is_git:
        return IsolationPlan(sequential=True, worker_cwd=local_path, worktree=None)
    if agent == "codex":
        tree = tmp / job_id
        return IsolationPlan(sequential=False, worker_cwd=tree, worktree=tree)
    return IsolationPlan(sequential=False, worker_cwd=local_path, worktree=None)


def codex_worktree_argv(path: Path) -> list[str]:
    return ["git", "worktree", "add", "--detach", str(path), "HEAD"]


def audit_exit_code(results: Sequence[JobResult], finding_count: int) -> int:
    if finding_count > 0:
        return 2
    if results and all(item.exit_code != 0 for item in results):
        return 1
    return 0


def worker_prompt(
    job: AuditJob,
    targets_info: list[dict[str, Any]],
    instruction: str,
) -> str:
    target_lines = "\n".join(
        f"- {item.get('original')} ({item.get('type')})" for item in targets_info
    )
    skills = ", ".join(job.skills)
    extra = f"\nAdditional instruction:\n{instruction}\n" if instruction else ""
    return (
        f"You are specialist {job.title} for this Strix audit.\n"
        f"Targets:\n{target_lines}\n"
        f"load_skill each of: {skills}\n"
        f"{job.task}\n"
        "File only validated findings with create_vulnerability_report.\n"
        "Coverage todos are not seeded. Do not try to cover every vuln class.\n"
        "Do not spawn sub-agents / Task tools / extra CLI agents.\n"
        f"{extra}"
        "When finished, print AUDIT_JOB_DONE and exit 0.\n"
    )


def targets_info_for_audit(args: Any) -> list[dict[str, Any]]:
    targets_info: list[dict[str, Any]] = []
    targets = list(args.target or [])
    for target_list_path in args.target_list or []:
        targets.extend(read_target_list_file(target_list_path))

    for target in targets:
        try:
            target_type, target_dict = infer_target_type(target)
        except ValueError as exc:
            raise ValueError(f"Invalid target '{target}': {exc}") from None

        display_target = (
            target_dict.get("target_path", target) if target_type == "local_code" else target
        )
        if target_type == "api_spec":
            _resolve_api_spec(target, target_dict)

        targets_info.append(
            {"type": target_type, "details": target_dict, "original": display_target}
        )

    targets_info = dedupe_local_targets(targets_info)
    assign_workspace_subdirs(targets_info)
    return targets_info


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


_live_procs: list[subprocess.Popen[bytes]] = []


def _kill_live_processes() -> None:
    for proc in _live_procs.copy():
        if proc.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)


def run_jobs(  # noqa: PLR0915
    jobs: Sequence[AuditJob],
    *,
    agent: str,
    binary: str,
    targets_info: list[dict[str, Any]],
    original_cwd: Path,
    parent: Path,
    instruction: str,
    max_workers: int,
    timeout: int,
) -> tuple[list[JobResult], int]:
    local = first_local_path(targets_info)
    git = bool(local and is_git_repo(local))
    tmp = parent / ".worktrees"
    tmp.mkdir(parents=True, exist_ok=True)
    added_worktrees: list[Path] = []
    plans = {
        job.id: plan_isolation(
            agent,
            job.id,
            local,
            original_cwd,
            tmp,
            is_git=git,
        )
        for job in jobs
    }
    worker_run_base = parent.relative_to(original_cwd / "strix_runs").as_posix()

    def run_job(job: AuditJob) -> JobResult:
        plan = plans[job.id]
        if plan.worktree:
            subprocess.run(  # noqa: S603
                codex_worktree_argv(plan.worktree),
                cwd=local or original_cwd,
                check=True,
            )
            added_worktrees.append(plan.worktree)

        worker_dir = parent / "workers" / job.id
        worker_dir.mkdir(parents=True, exist_ok=True)
        worker_run_name = f"{worker_run_base}/workers/{job.id}"
        mcp = mcp_argv(str(original_cwd), worker_run_name)
        mcp_config = write_mcp_config_json(sys.executable, mcp[1:])
        mcp_path = worker_dir / "mcp.json"
        mcp_path.write_text(json.dumps(mcp_config, indent=2), encoding="utf-8")

        prompt = worker_prompt(job, targets_info, instruction)
        cursor_path = plan.worker_cwd / ".cursor" / "mcp.json"
        cursor_backup = cursor_path.with_name(".mcp.json.strix-audit.bak")
        restore_cursor = False
        if agent == "claude":
            argv = claude_argv(
                binary,
                prompt,
                mcp_path,
                worktree_name=f"strix-audit-{job.id}" if git else None,
            )
        elif agent == "cursor":
            cursor_path.parent.mkdir(parents=True, exist_ok=True)
            if cursor_path.exists():
                shutil.copy2(cursor_path, cursor_backup)
                restore_cursor = True
            cursor_path.write_text(json.dumps(mcp_config, indent=2), encoding="utf-8")
            argv = cursor_argv(binary, prompt, plan.worker_cwd)
        else:
            argv = codex_argv(
                binary,
                prompt,
                plan.worker_cwd,
                str(original_cwd),
                worker_run_name,
            )

        proc: subprocess.Popen[bytes] | None = None
        try:
            proc = subprocess.Popen(  # noqa: S603
                argv,
                cwd=plan.worker_cwd,
                start_new_session=True,
            )
            _live_procs.append(proc)
            try:
                proc.communicate(timeout=timeout)
                return JobResult(job.id, proc.returncode, timed_out=False)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
                return JobResult(job.id, 1, timed_out=True)
        finally:
            if proc is not None and proc.poll() is None:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            if proc in _live_procs:
                _live_procs.remove(proc)
            if agent == "cursor":
                if restore_cursor:
                    shutil.move(cursor_backup, cursor_path)
                else:
                    cursor_path.unlink(missing_ok=True)

    try:
        if any(plan.sequential for plan in plans.values()):
            results = [run_job(job) for job in jobs]
        else:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
            try:
                futures = [executor.submit(run_job, job) for job in jobs]
                results = [future.result() for future in futures]
            except KeyboardInterrupt:
                _kill_live_processes()
                raise
            finally:
                executor.shutdown(wait=True, cancel_futures=True)

        reports = remint_ids(load_worker_reports(parent, [job.id for job in jobs]))
        jobs_summary = "\n".join(
            f"{result.job_id}: exit {result.exit_code}"
            + (" (timed out)" if result.timed_out else "")
            for result in results
        )
        write_parent_reports(parent, reports, jobs_summary=jobs_summary)
        return results, len(reports)
    except KeyboardInterrupt:
        _kill_live_processes()
        raise
    finally:
        for path in added_worktrees:
            subprocess.run(  # noqa: S603
                ["git", "worktree", "remove", "--force", str(path)],  # noqa: S607
                cwd=local or original_cwd,
                check=False,
            )
