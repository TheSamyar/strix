"""Run allowlisted source, dependency, and secret scanners on local paths."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


_TIMEOUT_SECONDS = 600
_OUTPUT_CAP_CHARS = 100_000

_SCANNERS: dict[str, list[str]] = {
    "trivy_fs": [
        "trivy", "fs", "--format", "json", "--scanners", "vuln,misconfig,secret", "{target}"
    ],
    "semgrep": ["semgrep", "scan", "--json", "--metrics=off", "{target}"],
    "bandit": ["bandit", "-r", "{target}", "-f", "json"],
    "trufflehog": [
        "trufflehog", "filesystem", "{target}", "--json", "--no-update", "--no-verification"
    ],
    "retire": ["retire", "--path", "{target}", "--outputformat", "json"],
}


def _scan_impl(scanner: str, target: str, timeout: int) -> dict[str, Any]:  # noqa: PLR0911
    if scanner not in _SCANNERS:
        return {
            "success": False,
            "error": f"Scanner '{scanner}' is not allowlisted",
            "allowed": sorted(_SCANNERS),
        }
    if not target.strip():
        return {"success": False, "error": "target cannot be empty"}
    path = Path(target).expanduser()
    if not path.exists():
        return {"success": False, "error": f"Path not found: {target}"}

    binary = _SCANNERS[scanner][0]
    if shutil.which(binary) is None:
        return {
            "success": False,
            "error": f"'{binary}' is not installed on this host",
            "scanner": scanner,
        }

    argv = [str(path) if item == "{target}" else item for item in _SCANNERS[scanner]]
    try:
        proc = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=max(1, min(timeout, _TIMEOUT_SECONDS)),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "success": False,
            "scanner": scanner,
            "target": str(path),
            "argv": argv,
            "timed_out": True,
            "error": f"scan timed out after {timeout}s",
            "stdout": (exc.stdout or "")[:_OUTPUT_CAP_CHARS] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[:_OUTPUT_CAP_CHARS] if isinstance(exc.stderr, str) else "",
        }
    except OSError as exc:
        return {"success": False, "scanner": scanner, "error": f"{type(exc).__name__}: {exc}"}

    return {
        "success": True,
        "scanner": scanner,
        "target": str(path),
        "argv": argv,
        "returncode": proc.returncode,
        "timed_out": False,
        "stdout": proc.stdout[:_OUTPUT_CAP_CHARS],
        "stderr": proc.stderr[:_OUTPUT_CAP_CHARS],
    }


@function_tool(timeout=_TIMEOUT_SECONDS + 30, strict_mode=False)
async def local_security_scan(
    ctx: RunContextWrapper,
    scanner: str,
    target: str,
    timeout: int = _TIMEOUT_SECONDS,
) -> str:
    """Run an allowlisted local source, dependency, or secret scanner.

    Supported scanners: ``trivy_fs``, ``semgrep``, ``bandit``, ``trufflehog``,
    and ``retire``. The target must be an existing local file or directory.
    Commands use argv lists and never invoke a shell. Native scanner JSON is
    returned in ``stdout`` for downstream report conversion.
    """
    del ctx
    result = await asyncio.to_thread(_scan_impl, scanner, target, timeout)
    return json.dumps(result, ensure_ascii=False, default=str)
