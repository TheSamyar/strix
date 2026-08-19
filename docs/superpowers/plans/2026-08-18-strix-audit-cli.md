# `strix audit` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `strix audit` — a headless coordinator that runs a fixed playbook of specialist jobs via Claude / Cursor Agent / Codex CLIs and merges MCP findings into `strix_runs/<name>/`.

**Architecture:** Own argparse + dispatch before Docker. `strix/audit.py` holds playbook, frozen vendor argv, MCP argv (chdir to original cwd), remint merge. `strix/interface/audit.py` is the CLI loop. `strix mcp --no-seed` so specialists are not full-pentest checklists. No manager LLM. No Docker.

**Tech Stack:** Python 3.12, stdlib `argparse`/`subprocess`/`json`, existing `build_targets_info` pieces (`infer_target_type`, not the localhost rewrite), `write_vulnerabilities` / `write_sarif` / `write_executive_report`, pytest.

**Spec:** `docs/superpowers/specs/2026-08-18-strix-audit-cli-design.md`

## Global Constraints

- No Docker, no `STRIX_LLM`, no `parse_arguments()`, no `prepare_run()`, no `rewrite_localhost_targets`.
- No new dependencies.
- `--agent` values: `claude` | `cursor` | `codex`. Cursor binaries: `cursor-agent` then `agent`. Never the `cursor` IDE binary.
- Default `--scan-mode` is `quick` (4 jobs). `standard` = 6, `deep` = 8.
- MCP subprocess cwd is the original repo cwd, not the vendor worktree. `run_dir_for` uses `Path.cwd()`.
- Remint finding ids on merge (`vuln-0001` from every worker would otherwise collide).
- Unattended vendor flags are required (frozen argv below).
- Exit codes: `0` clean, `1` fatal / all jobs failed, `2` any findings.
- Tests never call a live vendor CLI. Fake binaries only.
- Do not mutate `~/.cursor` or `~/.codex`. Cursor `.cursor/mcp.json` in a workspace must be backed up and restored if it already existed.
- Do not `git worktree add` for Claude/Cursor. Codex only: `git worktree add --detach`. Remove only paths this process added.

## File structure

| File | Responsibility |
|---|---|
| `strix/interface/mcp_server.py` | `--no-seed` + specialist instructions |
| `strix/audit.py` | Playbook, MCP argv, adapters, isolation, merge, exit code |
| `strix/interface/audit.py` | Argparse, `run_audit()`, spawn loop, SIGINT |
| `strix/interface/main.py` | Dispatch `audit` before `parse_arguments()` |
| `tests/test_audit.py` | Playbook, adapters, merge, isolation, CLI, fake binary, exit codes |
| `tests/test_mcp_server.py` | `--no-seed` coverage |

---

### Task 1: `strix mcp --no-seed`

**Files:**
- Modify: `strix/interface/mcp_server.py` (`bootstrap_mcp_run`, `_initialize_result`, `run_mcp`)
- Test: `tests/test_mcp_server.py`

**Interfaces:**
- Consumes: existing `bootstrap_mcp_run(run_name)`, `MCP_INSTRUCTIONS`, `_seed_coverage_todos`
- Produces: `bootstrap_mcp_run(run_name: str = DEFAULT_RUN_NAME, *, seed_coverage: bool = True) -> ReportState`; `run_mcp` accepts `--no-seed`; initialize `instructions` switch to `SPECIALIST_MCP_INSTRUCTIONS` when `seed_coverage` is false

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mcp_server.py`:

```python
def test_no_seed_skips_coverage_todos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    from strix.tools.todo.tools import _get_agent_todos

    bootstrap_mcp_run("no-seed", seed_coverage=False)
    todos = _get_agent_todos("mcp")
    assert todos == {}
    instructions = handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})["result"][
        "instructions"
    ]
    assert "coverage checklist" not in instructions
    assert "specialist" in instructions.lower()
    report_state_mod._global_report_state = None


def test_seed_still_creates_coverage_todos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    from strix.tools.todo.tools import _get_agent_todos

    bootstrap_mcp_run("seeded")
    titles = [t["title"] for t in _get_agent_todos("mcp").values()]
    assert any("[coverage]" in title for title in titles)
    report_state_mod._global_report_state = None
```

Keep `test_initialize_advertises_strix` asserting `"pentester" in instructions` — default (seeded) path must stay the full pentest text.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_mcp_server.py::test_no_seed_skips_coverage_todos tests/test_mcp_server.py::test_seed_still_creates_coverage_todos -v`

Expected: FAIL (`seed_coverage` unexpected keyword, or todos still seeded).

- [ ] **Step 3: Write minimal implementation**

In `strix/interface/mcp_server.py`:

1. Add constant next to `MCP_INSTRUCTIONS`:

```python
SPECIALIST_MCP_INSTRUCTIONS = """\
You are a specialist on a Strix audit. Drive testing with your own shell, \
browser, grep, and HTTP tooling. Only test authorized targets. load_skill \
the packs named in your job prompt, prove exploits before filing, and call \
create_vulnerability_report only for validated findings. Coverage todos are \
not seeded — do not try to cover every vulnerability class. Do not spawn \
sub-agents. When the job is done, stop."""
```

2. Module flag, set in bootstrap:

```python
_seed_coverage = True


def bootstrap_mcp_run(run_name: str = DEFAULT_RUN_NAME, *, seed_coverage: bool = True) -> ReportState:
    global _seed_coverage
    _seed_coverage = seed_coverage
    existing = get_global_report_state()
    if existing is not None:
        return existing
    # ... existing body ...
    if seed_coverage:
        _seed_coverage_todos()
    state.save_run_data()
    return state
```

3. `_initialize_result` uses `MCP_INSTRUCTIONS if _seed_coverage else SPECIALIST_MCP_INSTRUCTIONS`.

4. `run_mcp` argparse:

```python
parser.add_argument(
    "--no-seed",
    action="store_true",
    help="Skip vuln-class coverage todos; specialist instructions (used by strix audit workers).",
)
args = parser.parse_args(argv)
bootstrap_mcp_run(args.run_name, seed_coverage=not args.no_seed)
```

Do not change default `strix mcp` behavior.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_mcp_server.py -v`

Expected: PASS (including existing initialize/tools tests).

- [ ] **Step 5: Commit**

```bash
git add strix/interface/mcp_server.py tests/test_mcp_server.py
git commit -m "$(cat <<'EOF'
feat: add strix mcp --no-seed for specialist audit workers

EOF
)"
```

---

### Task 2: Playbook

**Files:**
- Create: `strix/audit.py` (playbook section only in this task)
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: nothing from Task 1
- Produces: `AuditJob` dataclass; `jobs_for_mode(mode: str) -> tuple[AuditJob, ...]`; `SCAN_MODES = ("quick", "standard", "deep")`

- [ ] **Step 1: Write the failing test**

Create `tests/test_audit.py`:

```python
from __future__ import annotations

import pytest

from strix.audit import jobs_for_mode


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_audit.py::test_quick_has_four_jobs -v`

Expected: FAIL (`ModuleNotFoundError: strix.audit`).

- [ ] **Step 3: Write minimal implementation**

Create `strix/audit.py`:

```python
"""Playbook + vendor adapters for `strix audit`."""

from __future__ import annotations

from dataclasses import dataclass


SCAN_MODES = ("quick", "standard", "deep")


@dataclass(frozen=True)
class AuditJob:
    id: str
    title: str
    skills: tuple[str, ...]
    task: str


_QUICK: tuple[AuditJob, ...] = (
    AuditJob("recon", "Recon specialist", ("asset_discovery",), "Map the attack surface. Do not deep-exploit."),
    AuditJob("auth", "Auth specialist", ("authentication_jwt", "csrf"), "Test authentication, session, JWT, and CSRF."),
    AuditJob("injection", "Injection specialist", ("sql_injection", "xss", "rce"), "Test SQLi, XSS, and RCE. Prove with a PoC before filing."),
    AuditJob("access", "Access-control specialist", ("idor", "broken_function_level_authorization"), "Test IDOR and broken function-level authorization."),
)
_STANDARD_EXTRA: tuple[AuditJob, ...] = (
    AuditJob("ssrf_files", "SSRF and files specialist", ("ssrf", "path_traversal_lfi_rfi", "insecure_file_uploads"), "Test SSRF, path traversal, and file uploads."),
    AuditJob("secrets_deps", "Secrets and deps specialist", ("information_disclosure", "dependency_cve_scanning"), "Find secrets and known-CVE dependencies."),
)
_DEEP_EXTRA: tuple[AuditJob, ...] = (
    AuditJob("logic", "Logic specialist", ("business_logic", "race_conditions"), "Test business logic and race conditions."),
    AuditJob("deser_ssti", "Deser/SSTI specialist", ("insecure_deserialization", "ssti"), "Test insecure deserialization and SSTI."),
)


def jobs_for_mode(mode: str) -> tuple[AuditJob, ...]:
    if mode == "quick":
        return _QUICK
    if mode == "standard":
        return _QUICK + _STANDARD_EXTRA
    if mode == "deep":
        return _QUICK + _STANDARD_EXTRA + _DEEP_EXTRA
    raise ValueError(f"unknown scan-mode {mode!r}; expected one of {SCAN_MODES}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_audit.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add strix/audit.py tests/test_audit.py
git commit -m "$(cat <<'EOF'
feat: add strix audit playbook jobs by scan mode

EOF
)"
```

---

### Task 3: MCP argv, binary resolve, frozen adapters

**Files:**
- Modify: `strix/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: `AuditJob` (not required by adapters)
- Produces:
  - `MCP_CHDIR_SNIPPET: str`
  - `mcp_argv(original_cwd: str, run_name: str) -> list[str]`
  - `resolve_agent(explicit: str | None, *, path_lookup: Callable[[str], str | None]) -> tuple[str, str]`  # `(agent, binary)`
  - `write_mcp_config_json(command: str, args: list[str]) -> dict[str, Any]`
  - `claude_argv(binary: str, prompt: str, mcp_config: Path) -> list[str]`
  - `cursor_argv(binary: str, prompt: str, workspace: Path) -> list[str]`
  - `codex_argv(binary: str, prompt: str, worker_cwd: Path, original_cwd: str, run_name: str) -> list[str]`
  - `AGENT_HINTS: dict[str, str]`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_audit.py`:

```python
import json
import sys
from pathlib import Path

from strix.audit import (
    claude_argv,
    codex_argv,
    cursor_argv,
    mcp_argv,
    resolve_agent,
    write_mcp_config_json,
)


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
    argv = claude_argv("claude", "do the job", Path("/tmp/mcp.json"))
    assert argv[:2] == ["claude", "-p"]
    assert "--dangerously-skip-permissions" in argv
    assert "--strict-mcp-config" in argv
    assert argv[argv.index("--mcp-config") + 1] == "/tmp/mcp.json"
    assert "do the job" in argv


def test_cursor_argv_never_uses_ide_binary() -> None:
    argv = cursor_argv("cursor-agent", "do the job", Path("/ws"))
    assert argv[0] == "cursor-agent"
    assert "--force" in argv
    assert "--approve-mcps" in argv
    assert "--sandbox" in argv
    assert argv[argv.index("--workspace") + 1] == "/ws"
    assert "cursor" != argv[0] or argv[0] == "cursor-agent"


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_audit.py::test_mcp_argv_chdirs_then_passes_run_name tests/test_audit.py::test_resolve_agent_skips_cursor_ide tests/test_audit.py::test_claude_argv_is_unattended tests/test_audit.py::test_cursor_argv_never_uses_ide_binary tests/test_audit.py::test_codex_argv_injects_mcp_via_dash_c -v`

Expected: FAIL (import errors).

- [ ] **Step 3: Write minimal implementation**

Append to `strix/audit.py`:

```python
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

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
    "cursor": "Install Cursor Agent (`cursor-agent` or `agent`). The `cursor` IDE binary is not an agent.",
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


def claude_argv(binary: str, prompt: str, mcp_config: Path) -> list[str]:
    return [
        binary,
        "-p",
        "--dangerously-skip-permissions",
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
        "--output-format",
        "json",
        prompt,
    ]


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
```

`resolve_agent` default `path_lookup` in later tasks will be `shutil.which`. Tests inject a fake lookup.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_audit.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add strix/audit.py tests/test_audit.py
git commit -m "$(cat <<'EOF'
feat: freeze claude/cursor/codex argv and MCP chdir wrapper

EOF
)"
```

---

### Task 4: Merge remint

**Files:**
- Modify: `strix/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: worker dirs at `parent / "workers" / job_id / "vulnerabilities.json"`
- Produces: `load_worker_reports(parent: Path, job_ids: Sequence[str]) -> list[dict[str, Any]]`; `remint_ids(reports: list[dict[str, Any]]) -> list[dict[str, Any]]`; `write_parent_reports(parent: Path, reports: list[dict[str, Any]], *, jobs_summary: str) -> None`

- [ ] **Step 1: Write the failing test**

```python
from strix.audit import load_worker_reports, remint_ids, write_parent_reports


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_audit.py::test_remint_keeps_colliding_worker_ids -v`

Expected: FAIL (functions missing).

- [ ] **Step 3: Write minimal implementation**

Append to `strix/audit.py`:

```python
import logging
from collections.abc import Sequence

from strix.report.sarif import write_sarif
from strix.report.writer import write_executive_report, write_vulnerabilities

logger = logging.getLogger(__name__)


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
    for report in reports:
        lines.append(
            f"- `{report.get('id')}` {str(report.get('severity', '')).upper()} "
            f"{report.get('title', '')}\n"
        )
    write_executive_report(parent, "".join(lines))
```

Do not copy markdown files from worker dirs. Do not dedupe by original id.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_audit.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add strix/audit.py tests/test_audit.py
git commit -m "$(cat <<'EOF'
feat: remint worker finding ids when merging audit reports

EOF
)"
```

---

### Task 5: Isolation + prompt + exit code

**Files:**
- Modify: `strix/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: `AuditJob`
- Produces:
  - `IsolationPlan(sequential: bool, worker_cwd: Path, worktree: Path | None)`
  - `plan_isolation(agent: str, job_id: str, local_path: Path | None, original_cwd: Path, tmp: Path, *, is_git: bool) -> IsolationPlan`
  - `codex_worktree_argv(path: Path) -> list[str]`  # `git worktree add --detach <path> HEAD`
  - `worker_prompt(job: AuditJob, targets_info: list[dict[str, Any]], instruction: str) -> str`
  - `audit_exit_code(results: Sequence[JobResult], finding_count: int) -> int`
  - `JobResult(job_id: str, exit_code: int, timed_out: bool)`
  - `first_local_path(targets_info: list[dict[str, Any]]) -> Path | None`

- [ ] **Step 1: Write the failing tests**

```python
from strix.audit import (
    AuditJob,
    JobResult,
    audit_exit_code,
    codex_worktree_argv,
    first_local_path,
    plan_isolation,
    worker_prompt,
)


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


def test_isolation_nongit_is_sequential(tmp_path: Path) -> None:
    src = tmp_path / "src"
    plan = plan_isolation("claude", "recon", src, tmp_path, tmp_path / "wt", is_git=False)
    assert plan.sequential is True
    assert plan.worktree is None


def test_isolation_url_only_parallel(tmp_path: Path) -> None:
    plan = plan_isolation("cursor", "auth", None, tmp_path, tmp_path / "wt", is_git=False)
    assert plan.sequential is False
    assert plan.worker_cwd == tmp_path


def test_exit_codes() -> None:
    ok = JobResult("recon", 0, False)
    bad = JobResult("auth", 1, False)
    dead = JobResult("inj", 1, True)
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


def test_first_local_path() -> None:
    info = [
        {"type": "web_application", "details": {}, "original": "https://x"},
        {"type": "local_code", "details": {"target_path": "/tmp/app"}, "original": "./app"},
    ]
    assert first_local_path(info) == Path("/tmp/app")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_audit.py::test_isolation_codex_git_uses_detach tests/test_audit.py::test_exit_codes tests/test_audit.py::test_worker_prompt_includes_skills_and_no_subagents -v`

Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Append to `strix/audit.py`:

```python
from dataclasses import dataclass


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_audit.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add strix/audit.py tests/test_audit.py
git commit -m "$(cat <<'EOF'
feat: add audit isolation, worker prompt, and exit-code rules

EOF
)"
```

---

### Task 6: CLI dispatch + `run_audit` loop

**Files:**
- Create: `strix/interface/audit.py`
- Modify: `strix/interface/main.py` (insert `audit` dispatch immediately before the `mcp` block, still before `parse_arguments()`)
- Modify: `strix/audit.py` (add `targets_info_for_audit`, `is_git_repo`, `run_jobs`)
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: everything from Tasks 1–5; `infer_target_type`, `dedupe_local_targets`, `assign_workspace_subdirs`, `read_target_list_file` from `strix.interface.utils`; `generate_run_name`; `run_dir_for`; `write_run_record`
- Produces: `parse_audit_args(argv: list[str]) -> argparse.Namespace`; `run_audit(argv: list[str]) -> int`; `main()` dispatches `sys.argv[1] == "audit"`

`build_targets_info` in `scan_setup.py` always calls `rewrite_localhost_targets`. **Do not call it.** Copy its loop minus that last call into `targets_info_for_audit`.

- [ ] **Step 1: Write the failing tests**

```python
import os
import stat
import subprocess
from argparse import Namespace

from strix.audit import targets_info_for_audit
from strix.interface.audit import parse_audit_args, run_audit
from strix.interface import main as main_mod


def test_parse_audit_help() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_audit_args(["--help"])
    assert exc.value.code == 0


def test_parse_requires_target() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_audit_args(["--agent", "claude"])
    assert exc.value.code == 2  # argparse


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


def test_run_audit_fake_claude_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_run_audit_missing_agent_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir()
    (tmp_path / "app").mkdir()
    assert run_audit(["-t", str(tmp_path / "app"), "--agent", "claude"]) == 1
```

For `test_main_audit_help_never_parses_scan`: `main.py` currently imports `parse_arguments` at the top. If it is only used after dispatch, monkeypatch works. If `check_docker_installed` would run, the boom on `parse_arguments` is enough because Docker is after parse. Dispatch must happen first so `--help` never reaches parse.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_audit.py::test_parse_audit_help tests/test_audit.py::test_main_audit_help_never_parses_scan tests/test_audit.py::test_targets_info_keeps_localhost tests/test_audit.py::test_run_audit_fake_claude_exit_zero -v`

Expected: FAIL.

- [ ] **Step 3: Implement CLI + loop**

`strix/interface/audit.py` (full file):

```python
"""`strix audit` — hire Claude / Cursor Agent / Codex as playbook workers."""

from __future__ import annotations

import argparse
import logging
import shutil
import signal
import sys
from pathlib import Path

from strix.audit import (
    AGENT_HINTS,
    SCAN_MODES,
    audit_exit_code,
    jobs_for_mode,
    resolve_agent,
    run_jobs,
    targets_info_for_audit,
)
from strix.core.paths import run_dir_for
from strix.interface.utils import generate_run_name
from strix.report.writer import write_run_record

logger = logging.getLogger(__name__)


def parse_audit_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="strix audit",
        description="Run a playbook of specialist coding-agent workers. No Docker.",
    )
    parser.add_argument("-t", "--target", action="append", dest="target")
    parser.add_argument("--target-list", action="append", dest="target_list")
    parser.add_argument("--agent", choices=("claude", "cursor", "codex"))
    parser.add_argument("-m", "--scan-mode", choices=SCAN_MODES, default="quick")
    parser.add_argument("--run-name")
    parser.add_argument("--max-workers", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--instruction", default="")
    parser.add_argument("--instruction-file")
    args = parser.parse_args(argv)
    if not args.target and not args.target_list:
        parser.error("the following arguments are required: -t/--target")
    if args.run_name and ".." in args.run_name:
        parser.error("--run-name must not contain ..")
    if args.max_workers < 1:
        parser.error("--max-workers must be >= 1")
    if args.timeout < 1:
        parser.error("--timeout must be >= 1")
    if args.instruction_file:
        args.instruction = (
            (args.instruction + "\n" if args.instruction else "")
            + Path(args.instruction_file).read_text(encoding="utf-8")
        )
    return args


def run_audit(argv: list[str]) -> int:
    args = parse_audit_args(argv)
    try:
        targets_info = targets_info_for_audit(args)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    if not targets_info:
        print("No targets.", file=sys.stderr)
        return 1
    try:
        agent, binary = resolve_agent(args.agent, path_lookup=shutil.which)
    except (FileNotFoundError, ValueError) as exc:
        print(exc, file=sys.stderr)
        if args.agent:
            print(AGENT_HINTS.get(args.agent, ""), file=sys.stderr)
        else:
            print("\n".join(AGENT_HINTS.values()), file=sys.stderr)
        return 1
    run_name = args.run_name or generate_run_name(targets_info)
    original_cwd = Path.cwd()
    parent = run_dir_for(run_name, cwd=original_cwd)
    parent.mkdir(parents=True, exist_ok=True)
    jobs = jobs_for_mode(args.scan_mode)
    instruction = args.instruction or ""
    results, finding_count = run_jobs(
        jobs,
        agent=agent,
        binary=binary,
        targets_info=targets_info,
        original_cwd=original_cwd,
        parent=parent,
        instruction=instruction,
        max_workers=args.max_workers,
        timeout=args.timeout,
    )
    write_run_record(
        parent,
        {
            "status": "completed",
            "agent": agent,
            "scan_mode": args.scan_mode,
            "jobs": [
                {"id": r.job_id, "exit": r.exit_code, "timed_out": r.timed_out}
                for r in results
            ],
            "finding_count": finding_count,
        },
    )
    return audit_exit_code(results, finding_count)
```

In `strix/audit.py` add `targets_info_for_audit`, `is_git_repo`, and `run_jobs`.

`targets_info_for_audit`: copy the loop in `strix/interface/scan_setup.py` `build_targets_info` (lines 107–132) **except omit** `rewrite_localhost_targets`. For `api_spec` targets call `from strix.interface.scan_setup import _resolve_api_spec`. Do **not** import `build_targets_info`.

`is_git_repo(path: Path) -> bool`: `(path / ".git").exists()` is enough (covers worktrees that have `.git` file).

`run_jobs(...)` must:

1. `local = first_local_path(targets_info)`; `git = bool(local and is_git_repo(local))`.
2. `tmp = parent / ".worktrees"`; mkdir.
3. `added_worktrees: list[Path] = []`.
4. Build per-job `IsolationPlan` via `plan_isolation`. If any job is `sequential`, run all jobs one at a time (`max_workers` ignored). Else use `concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)`.
5. Per job:
   - If `plan.worktree` (Codex git): `subprocess.run(codex_worktree_argv(plan.worktree), cwd=local or original_cwd, check=True)` then `added_worktrees.append(plan.worktree)`.
   - Write Claude MCP json to `parent / "workers" / job.id / "mcp.json"` (mkdir) using `write_mcp_config_json(sys.executable, mcp_argv(...)[1:])` — command is `sys.executable`, args are the rest of `mcp_argv`.
   - Cursor: workspace = `plan.worker_cwd`. If `(workspace / ".cursor" / "mcp.json").exists()`, copy to `.mcp.json.strix-audit.bak`. Write `write_mcp_config_json(...)` there. Always restore the backup (or delete the file if we created it) in `finally`.
   - Build prompt with `worker_prompt`.
   - Argv: `claude_argv` / `cursor_argv` / `codex_argv`. For Claude + git local, add optional kwarg `worktree_name: str | None = None` to `claude_argv` (default `None` so Task 3 tests stay green). When set, insert `["-w", worktree_name]` before `prompt`. Call it with `worktree_name=f"strix-audit-{job.id}"`. Do not also `git worktree add`.
   - `subprocess.Popen(argv, cwd=plan.worker_cwd, start_new_session=True)`. `communicate(timeout=timeout)`. On `TimeoutExpired`: `os.killpg(proc.pid, signal.SIGKILL)` (Unix); mark `timed_out=True`, `exit_code=1`.
6. After all jobs: `reports = remint_ids(load_worker_reports(parent, [j.id for j in jobs]))`; `write_parent_reports(...)`; return `(results, len(reports))`.
7. `finally`: for each path in `added_worktrees`, `subprocess.run(["git", "worktree", "remove", "--force", str(path)], cwd=local or original_cwd, check=False)`. Never touch `.claude/worktrees/`.
8. SIGINT: `run_audit` can let KeyboardInterrupt propagate from `run_jobs`; `run_audit` catches it, kills remaining Popen process groups, writes `run.json` status `error`, returns `1`. Keep a module-level `_live_procs: list[subprocess.Popen[bytes]]` for that, or return kill handles from the executor. Smallest: sequential/executor tasks register the Popen on a list, SIGINT handler kills the list then re-raises.

Claude argv currently ends with `prompt`. When adding `-w`, insert before prompt:

```python
argv = claude_argv(binary, prompt, mcp_path)
if use_claude_worktree:
    prompt = argv.pop()
    argv.extend(["-w", f"strix-audit-{job_id}", prompt])
```

`main.py` insert **before** the mcp block (still before `parse_arguments()`):

```python
    if len(sys.argv) > 1 and sys.argv[1] == "audit":
        from strix.interface.audit import run_audit

        sys.exit(run_audit(sys.argv[2:]))
```

Do not call `check_docker_installed` on this path.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_audit.py tests/test_mcp_server.py -v`

Expected: PASS.

If `test_run_audit_fake_claude_exit_zero` hangs: the fake `claude` must ignore extra args (`#!/bin/sh` does). Timeout in `run_jobs` for tests can stay 3600; fake exits immediately.

If Cursor backup tests are not in this task, skip — Claude fake path is enough. Add one unit test that `run_jobs` for cursor writes and restores mcp.json if you touch Cursor in this loop — otherwise Cursor restore is still required in `run_jobs` even if the fake-binary test is Claude-only.

- [ ] **Step 5: Commit**

```bash
git add strix/audit.py strix/interface/audit.py strix/interface/main.py tests/test_audit.py
git commit -m "$(cat <<'EOF'
feat: add strix audit CLI that hires coding-agent workers

EOF
)"
```

---

## Spec coverage

| Spec section | Task |
|---|---|
| Dispatch before `parse_arguments` / no Docker | 6 |
| Own argparse, default quick, `--agent`, `--max-workers`, `--timeout`, `generate_run_name`, reject `..` | 6 |
| No localhost rewrite | 6 (`targets_info_for_audit`) |
| Playbook quick/standard/deep | 2 |
| No manager | — omitted on purpose |
| MCP chdir argv + `--no-seed` | 1, 3 |
| Specialist instructions | 1 |
| Frozen vendor argv / no `cursor` IDE | 3 |
| Cursor mcp.json in workspace + `--approve-mcps` | 3, 6 |
| Codex `--detach` worktree only | 5, 6 |
| Remint ids / no md copy | 4 |
| Exit 0/1/2 | 5, 6 |
| SIGINT kills workers, exit 1 | 6 |
| Fake binary + help tests | 6 |
| `--no-seed` tests | 1 |

Deferred (spec): `--run-dir`, clone repository URL targets, manager JSON, `strix view` nested titles.
