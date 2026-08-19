"""Run the Nuclei scanner against a live URL — stateless CVE/misconfig scan."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_FINDINGS_CAP = 200


def _parse_jsonl(stdout: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        raw_info = obj.get("info")
        info = raw_info if isinstance(raw_info, dict) else {}
        findings.append(
            {
                "template_id": obj.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": obj.get("matched-at"),
                "description": info.get("description"),
            }
        )
        if len(findings) >= _FINDINGS_CAP:
            break
    return findings


def _scan_impl(
    url: str,
    severity: str | None,
    tags: str | None,
    timeout: int,
) -> dict[str, Any]:
    if shutil.which("nuclei") is None:
        return {"success": False, "error": "nuclei not found", "hint": "install nuclei"}

    argv = ["nuclei", "-u", url, "-jsonl", "-silent"]
    if severity:
        argv += ["-severity", severity]
    if tags:
        argv += ["-tags", tags]

    try:
        proc = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        partial = _parse_jsonl(e.stdout or "" if isinstance(e.stdout, str) else "")
        return {
            "success": False,
            "error": f"nuclei timed out after {timeout}s",
            "count": len(partial),
            "findings": partial,
        }

    findings = _parse_jsonl(proc.stdout)
    return {"success": True, "count": len(findings), "findings": findings}


@function_tool(timeout=360)
async def nuclei_scan(
    ctx: RunContextWrapper,
    url: str,
    severity: str | None = None,
    tags: str | None = None,
    timeout: int = 300,
) -> str:
    """Run the Nuclei scanner against a URL for known CVEs and misconfigurations.

    Wraps the local ``nuclei`` binary. Only scan targets you are authorized to
    test — there are no scope guardrails; the operator owns scope.

    If ``nuclei`` is not installed, returns
    ``{"success": false, "error": ..., "hint": "install nuclei"}`` instead of
    raising. On timeout it returns any findings parsed so far with
    ``success: false``.

    Returns JSON with ``count`` and a ``findings`` list of
    ``{template_id, name, severity, matched_at, description}`` (capped at 200).

    Args:
        url: Target URL to scan.
        severity: Optional comma-separated severities, e.g. ``"critical,high"``.
        tags: Optional comma-separated Nuclei template tags, e.g. ``"cve,rce"``.
        timeout: Scan timeout in seconds (default 300).
    """
    return json.dumps(
        await asyncio.to_thread(_scan_impl, url, severity, tags, timeout),
        ensure_ascii=False,
        default=str,
    )
