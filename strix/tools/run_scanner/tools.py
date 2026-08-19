"""Run an allowlisted site-audit scanner against an authorized target — stateless."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_OUTPUT_CAP_CHARS = 20_000

# tool -> argv template. {target} and {extra} are placeholders substituted below.
# argv is always built as a LIST (never a shell string) so extra_args land as
# discrete elements and shell metacharacters carry no meaning.
_ALLOWLIST: dict[str, list[str]] = {
    "nmap": ["nmap", "{target}", "{extra}"],
    "nuclei": ["nuclei", "-u", "{target}", "{extra}"],
    "wapiti": ["wapiti", "-u", "{target}", "{extra}"],
    "gospider": ["gospider", "-s", "{target}", "{extra}"],
    "sqlmap": ["sqlmap", "-u", "{target}", "--batch", "{extra}"],
    "nikto": ["nikto", "-host", "{target}", "{extra}"],
    "httpx": ["httpx", "-u", "{target}", "{extra}"],
    "ffuf": ["ffuf", "-u", "{target}", "{extra}"],
    "wpscan": ["wpscan", "--url", "{target}", "{extra}"],
    "sslscan": ["sslscan", "{target}", "{extra}"],
    "sstimap": ["sstimap", "-u", "{target}", "{extra}"],
    "commix": ["commix", "-u", "{target}", "--batch", "{extra}"],
    "whatweb": ["whatweb", "{target}", "{extra}"],
    "crlfuzz": ["crlfuzz", "-u", "{target}", "{extra}"],
    "searchsploit": ["searchsploit", "{target}", "{extra}"],
    "hashid": ["hashid", "{target}", "{extra}"],
    "dalfox": ["dalfox", "url", "{target}", "{extra}"],
    "katana": ["katana", "-u", "{target}", "{extra}"],
    "subfinder": ["subfinder", "-d", "{target}", "{extra}"],
    "arjun": ["arjun", "-u", "{target}", "{extra}"],
    "naabu": ["naabu", "-host", "{target}", "{extra}"],
    "gau": ["gau", "{target}", "{extra}"],
    "dnsx": ["dnsx", "-d", "{target}", "{extra}"],
    "dirsearch": ["dirsearch", "-u", "{target}", "{extra}"],
    "wafw00f": ["wafw00f", "{target}", "{extra}"],
    "trufflehog": ["trufflehog", "filesystem", "{target}", "{extra}"],
    "retire": ["retire", "--path", "{target}", "{extra}"],
    "amass": ["amass", "enum", "-d", "{target}", "{extra}"],
}


def _build_argv(tool: str, target: str, extra: list[str]) -> list[str]:
    argv: list[str] = []
    for part in _ALLOWLIST[tool]:
        if part == "{target}":
            argv.append(target)
        elif part == "{extra}":
            argv.extend(extra)
        else:
            argv.append(part)
    return argv


def _run_scanner_impl(
    tool: str,
    target: str,
    extra_args: list[str] | None,
    timeout: int,
) -> dict[str, Any]:
    if tool not in _ALLOWLIST:
        return {
            "success": False,
            "error": f"Tool '{tool}' is not allowlisted. Allowed: {', '.join(sorted(_ALLOWLIST))}",
        }
    if not target or not target.strip():
        return {"success": False, "error": "target cannot be empty"}
    if shutil.which(tool) is None:
        return {"success": False, "error": f"'{tool}' is not installed on this host"}

    argv = _build_argv(tool, target, extra_args or [])
    try:
        # ponytail: never shell=True — argv is a list, so no metachar injection.
        proc = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return {
            "success": True,
            "tool": tool,
            "argv": argv,
            "returncode": None,
            "stdout": (e.stdout or "")[:_OUTPUT_CAP_CHARS] if isinstance(e.stdout, str) else "",
            "stderr": (e.stderr or "")[:_OUTPUT_CAP_CHARS] if isinstance(e.stderr, str) else "",
            "timed_out": True,
        }
    return {
        "success": True,
        "tool": tool,
        "argv": argv,
        "returncode": proc.returncode,
        "stdout": proc.stdout[:_OUTPUT_CAP_CHARS],
        "stderr": proc.stderr[:_OUTPUT_CAP_CHARS],
        "timed_out": False,
    }


@function_tool(timeout=600, strict_mode=False)
async def run_scanner(
    ctx: RunContextWrapper,
    tool: str,
    target: str,
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> str:
    """Run one allowlisted site-audit scanner against an authorized target.

    Only runs scanners on a hardcoded allowlist — ``nmap``, ``nuclei``
    (CVE/misconfig templates), ``wapiti`` (full web-app DAST),
    ``gospider`` (crawler), ``sqlmap``,
    ``nikto``, ``httpx``, ``ffuf``, ``wpscan``, ``sslscan``, ``sstimap``,
    ``commix``, ``whatweb``, ``crlfuzz``, ``searchsploit``, ``hashid``,
    ``dalfox`` (XSS), ``katana`` (crawler), ``subfinder`` (subdomain
    enum), ``arjun`` (hidden-param discovery), ``naabu`` (port scan),
    ``gau`` (known URLs), ``dnsx`` (DNS toolkit), ``amass`` (deep
    subdomain enum) — against targets the
    operator is authorized to test; there are no scope guardrails, the
    operator owns scope. Any other ``tool`` is rejected with a structured
    error. argv is built as a list and run without a shell, so
    ``extra_args`` are passed as discrete arguments (no shell-metacharacter
    injection). ``searchsploit`` / ``hashid`` take a query or hash in
    ``target``, not a URL; ``subfinder`` / ``gau`` / ``dnsx`` take a bare
    domain (e.g. ``example.com``), not a URL. ``trufflehog`` and ``retire``
    take a local path rather than a URL.

    Returns JSON with ``tool``, ``argv``, ``returncode``, ``stdout`` and
    ``stderr`` (each truncated to 20k chars), and ``timed_out``. If the tool
    is off the allowlist or not installed it returns
    ``{"success": false, "error": ...}`` instead of raising.

    Args:
        tool: Scanner name — one of the allowlisted binaries above.
        target: URL or host to scan.
        extra_args: Extra CLI flags, each a separate list element.
        timeout: Seconds before the scanner is killed (default 300).
    """
    return json.dumps(
        await asyncio.to_thread(_run_scanner_impl, tool, target, extra_args, timeout),
        ensure_ascii=False,
        default=str,
    )
