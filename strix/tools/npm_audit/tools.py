"""Run ``npm audit`` on a node project and return parsed results — stateless."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 120
_TOP_ADVISORY_CAP = 25
_SEVERITIES = ("critical", "high", "moderate", "low", "info")


def _parse_new_schema(vulns: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the current npm audit ``vulnerabilities`` map into advisories."""
    advisories: list[dict[str, Any]] = []
    for name, info in vulns.items():
        if not isinstance(info, dict):
            continue
        via = info.get("via", [])
        title = ""
        for entry in via if isinstance(via, list) else []:
            if isinstance(entry, dict) and entry.get("title"):
                title = str(entry["title"])
                break
        fix = info.get("fixAvailable", False)
        advisories.append(
            {
                "package": name,
                "severity": info.get("severity", ""),
                "title": title,
                "vulnerable_range": info.get("range", ""),
                "fix_available": bool(fix),
            }
        )
    return advisories


def _parse_legacy_schema(advisories_map: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the legacy npm audit ``advisories`` map."""
    advisories: list[dict[str, Any]] = []
    for info in advisories_map.values():
        if not isinstance(info, dict):
            continue
        advisories.append(
            {
                "package": info.get("module_name", ""),
                "severity": info.get("severity", ""),
                "title": info.get("title", ""),
                "vulnerable_range": info.get("vulnerable_versions", ""),
                "fix_available": bool(info.get("patched_versions", "").strip("<>")),
            }
        )
    return advisories


def _audit_impl(path: str, production_only: bool) -> dict[str, Any]:
    if shutil.which("npm") is None:
        return {
            "success": False,
            "error": "npm binary not found on PATH",
            "hint": "install Node/npm",
        }
    argv = ["npm", "audit", "--json"]
    if production_only:
        argv.append("--omit=dev")
    try:
        # npm audit exits non-zero when vulns exist; parse stdout regardless.
        proc = subprocess.run(  # noqa: S603
            argv,
            cwd=path,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"npm audit timed out after {_TIMEOUT_SECONDS}s"}
    except OSError as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "could not parse npm audit JSON output",
            "stderr": proc.stderr.strip()[:2000],
        }

    if isinstance(data.get("vulnerabilities"), dict):
        advisories = _parse_new_schema(data["vulnerabilities"])
        schema = "new"
    elif isinstance(data.get("advisories"), dict):
        advisories = _parse_legacy_schema(data["advisories"])
        schema = "legacy"
    else:
        return {
            "success": False,
            "error": "unrecognized npm audit schema",
            "stderr": proc.stderr.strip()[:2000],
        }

    counts = dict.fromkeys(_SEVERITIES, 0)
    for adv in advisories:
        sev = adv.get("severity")
        if sev in counts:
            counts[sev] += 1
    order = {sev: i for i, sev in enumerate(_SEVERITIES)}
    advisories.sort(key=lambda a: order.get(a.get("severity", ""), len(_SEVERITIES)))

    return {
        "success": True,
        "schema": schema,
        "severity_counts": counts,
        "total": len(advisories),
        "advisories": advisories[:_TOP_ADVISORY_CAP],
    }


@function_tool(timeout=_TIMEOUT_SECONDS + 30, strict_mode=False)
async def npm_audit(
    ctx: RunContextWrapper,
    path: str,
    production_only: bool = False,
) -> str:
    """Run ``npm audit --json`` on a node project and return parsed results.

    Point this at a repo directory containing ``package.json`` /
    ``package-lock.json`` to surface known-CVE dependency vulnerabilities.
    ``npm audit`` exits non-zero when vulnerabilities exist — that's normal;
    the output is parsed regardless of exit code.

    Returns JSON with ``severity_counts`` (critical/high/moderate/low/info),
    ``total``, and ``advisories`` — a compact list (top 25) of
    ``{package, severity, title, vulnerable_range, fix_available}``. If the
    ``npm`` binary is missing it returns
    ``{"success": false, "error": ..., "hint": "install Node/npm"}`` instead
    of raising.

    Args:
        path: Repo directory containing package.json/package-lock.json.
        production_only: When True, pass ``--omit=dev`` to skip devDependencies.
    """
    return json.dumps(
        await asyncio.to_thread(_audit_impl, path, production_only),
        ensure_ascii=False,
        default=str,
    )
