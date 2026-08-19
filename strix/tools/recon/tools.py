"""Recon macro — subfinder → httpx → nuclei against one target in a single call."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.nuclei_scan.tools import _parse_jsonl


logger = logging.getLogger(__name__)

# ponytail: caps keep a wildcard domain from fanning out into a multi-hour scan.
# Raise them if a real engagement needs deeper enumeration.
_HOST_CAP = 100
_URL_CAP = 100


def _run(argv: list[str], *, stdin: str | None, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        argv,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _lines(stdout: str, cap: int) -> list[str]:
    out: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if line:
            out.append(line)
        if len(out) >= cap:
            break
    return out


def _is_bare_domain(target: str) -> bool:
    return "://" not in target and "/" not in target


def _recon_impl(target: str, severity: str | None, timeout: int) -> dict[str, Any]:
    for tool in ("httpx", "nuclei"):
        if shutil.which(tool) is None:
            return {"success": False, "error": f"{tool} not found", "hint": f"install {tool}"}

    # Split the budget: enumerate (25%) → probe (25%) → scan (the rest).
    enum_budget = max(30, timeout // 4)
    probe_budget = max(30, timeout // 4)
    scan_budget = max(60, timeout - enum_budget - probe_budget)

    # Stage 1 — hosts. A bare domain fans out via subfinder; a URL scans as-is.
    if _is_bare_domain(target):
        hosts = [target]
        if shutil.which("subfinder") is not None:
            try:
                sub = _run(
                    ["subfinder", "-d", target, "-silent"], stdin=None, timeout=enum_budget
                )
                hosts = _lines(sub.stdout, _HOST_CAP) or [target]
                if target not in hosts:
                    hosts.append(target)
            except subprocess.TimeoutExpired:
                logger.warning("subfinder timed out for %s", target)
    else:
        hosts = [target]

    # Stage 2 — probe which hosts are live HTTP(S) services.
    try:
        probe = _run(
            ["httpx", "-silent", "-no-color"], stdin="\n".join(hosts), timeout=probe_budget
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"httpx timed out after {probe_budget}s", "hosts": hosts}
    live = _lines(probe.stdout, _URL_CAP)
    if not live:
        return {"success": True, "hosts": len(hosts), "live": 0, "count": 0, "findings": []}

    # Stage 3 — scan live URLs with nuclei.
    argv = ["nuclei", "-jsonl", "-silent"]
    if severity:
        argv += ["-severity", severity]
    try:
        scan = _run(argv, stdin="\n".join(live), timeout=scan_budget)
        findings = _parse_jsonl(scan.stdout)
        timed_out = False
    except subprocess.TimeoutExpired as e:
        findings = _parse_jsonl(e.stdout or "" if isinstance(e.stdout, str) else "")
        timed_out = True

    return {
        "success": not timed_out,
        "hosts": len(hosts),
        "live": len(live),
        "live_urls": live,
        "count": len(findings),
        "findings": findings,
        **({"error": f"nuclei timed out after {scan_budget}s"} if timed_out else {}),
    }


@function_tool(timeout=960)
async def recon_chain(
    ctx: RunContextWrapper,
    target: str,
    severity: str | None = "critical,high,medium",
    timeout: int = 900,
) -> str:
    """Run a full recon chain against one target: subfinder → httpx → nuclei.

    One call does what three tools do in sequence:

    1. **subfinder** — if ``target`` is a bare domain (``example.com``),
       enumerate subdomains. A URL (``https://example.com/app``) skips this and
       is scanned directly.
    2. **httpx** — probe every host to find the live HTTP(S) services.
    3. **nuclei** — scan the live URLs for known CVEs and misconfigurations.

    Only run against targets you are authorized to test — there are no scope
    guardrails; the operator owns scope. Results are capped (100 hosts, 100
    live URLs, 200 findings) so a wildcard domain can't run away.

    If ``httpx`` or ``nuclei`` is missing, returns
    ``{"success": false, "error": ..., "hint": "install <tool>"}``. On a
    per-stage timeout it returns whatever was gathered so far with
    ``success: false``. ``subfinder`` is optional — without it a bare domain is
    scanned on its own.

    Returns JSON with ``hosts``, ``live``, ``live_urls``, ``count``, and a
    ``findings`` list of ``{template_id, name, severity, matched_at,
    description}``.

    Args:
        target: A bare domain (``example.com``) or a URL
            (``https://example.com/app``).
        severity: Comma-separated nuclei severities (default
            ``"critical,high,medium"``). Pass ``None`` for all severities.
        timeout: Total budget in seconds (default 900), split across the three
            stages.
    """
    return json.dumps(
        await asyncio.to_thread(_recon_impl, target, severity, timeout),
        ensure_ascii=False,
        default=str,
    )
