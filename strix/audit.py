"""Playbook + vendor adapters for `strix audit`."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


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
