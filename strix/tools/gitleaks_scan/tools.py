"""``gitleaks_scan`` — wrap the ``gitleaks`` binary to hunt leaked secrets."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 180


def _redact(secret: str | None) -> str:
    """Mask a matched secret so the raw value never leaves this process."""
    if not secret:
        return ""
    return f"{secret[:2]}***"


def _scan_impl(path: str, no_git: bool) -> dict[str, Any]:
    if shutil.which("gitleaks") is None:
        return {"error": "gitleaks binary not found on PATH", "hint": "install gitleaks"}

    report_path = Path(tempfile.mkstemp(prefix="gitleaks-", suffix=".json")[1])
    try:
        argv = [
            "gitleaks",
            "detect",
            "--source",
            path,
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--exit-code",
            "0",
        ]
        if no_git:
            argv.append("--no-git")
        try:
            subprocess.run(argv, capture_output=True, timeout=_TIMEOUT_SECONDS, check=False)  # noqa: S603
        except subprocess.TimeoutExpired:
            return {"error": f"gitleaks timed out after {_TIMEOUT_SECONDS}s", "path": path}

        try:
            raw = report_path.read_text(encoding="utf-8")
        except OSError as e:
            return {"error": f"could not read gitleaks report: {e}", "path": path}
        report = json.loads(raw) if raw.strip() else []
    except json.JSONDecodeError as e:
        return {"error": f"invalid gitleaks report: {e}", "path": path}
    finally:
        report_path.unlink(missing_ok=True)

    findings = [
        {
            "rule": f.get("RuleID"),
            "file": f.get("File"),
            "line": f.get("StartLine"),
            "commit": f.get("Commit"),
            "author": f.get("Author"),
            "date": f.get("Date"),
            "secret": _redact(f.get("Secret")),
        }
        for f in report
    ]
    return {"path": path, "count": len(findings), "findings": findings}


@function_tool(timeout=_TIMEOUT_SECONDS + 20)
async def gitleaks_scan(ctx: RunContextWrapper, path: str, no_git: bool = False) -> str:
    """Scan a repository for leaked secrets with the ``gitleaks`` binary.

    Runs ``gitleaks detect`` over the given repo, walking its git history
    by default. Matched secret values are REDACTED before returning — you
    get the rule, file, line, commit, author, and date, plus a masked
    marker instead of the raw secret.

    Requires the ``gitleaks`` binary on PATH; if it is missing the tool
    returns ``{error, hint}`` rather than raising.

    Args:
        path: Path to the repository directory to scan.
        no_git: When True, scan the filesystem only (``--no-git``) and
            skip git history.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_scan_impl, path, no_git),
        ensure_ascii=False,
        default=str,
    )
