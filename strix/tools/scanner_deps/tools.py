"""Scanner dependency registry + installer.

The MCP server's active-testing tools (``nuclei_scan``, ``run_scanner``,
``gitleaks_scan``, …) shell out to third-party CLI binaries. Those are OS
packages, not Python deps, so ``pip install`` can't pull them. This module
holds the registry and the install/check logic behind
``strix mcp --install-tools`` and the MCP ``check_tools`` tool.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

# Per-tool install candidates, tried in order; the first whose manager is
# present on the host is used. `go`/`pipx`/`gem` fallbacks cover distros whose
# package repos lack the tool (e.g. gitleaks/httpx on Debian stable).
#
# Each candidate: (manager, argv-without-sudo). apt/gem get sudo prepended when
# not root; brew/go/pipx never do.
_INSTALL_TIMEOUT = 600  # per tool

Candidate = tuple[str, list[str]]


class Scanner:
    __slots__ = ("binary", "candidates", "name", "note")

    def __init__(self, name: str, binary: str, candidates: list[Candidate], note: str = "") -> None:
        self.name = name
        self.binary = binary
        self.candidates = candidates
        self.note = note


# ponytail: go module paths pinned to major versions the tools actually publish.
SCANNERS: tuple[Scanner, ...] = (
    Scanner(
        "nuclei",
        "nuclei",
        [
            ("brew", ["brew", "install", "nuclei"]),
            ("apt-get", ["apt-get", "install", "-y", "nuclei"]),
            ("go", ["go", "install", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"]),
        ],
    ),
    Scanner(
        "httpx",
        "httpx",
        [
            # go first: brew/pip "httpx" collide with the Python HTTP client.
            ("go", ["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"]),
        ],
        note="ProjectDiscovery httpx (not the Python library of the same name).",
    ),
    Scanner(
        "nmap",
        "nmap",
        [
            ("brew", ["brew", "install", "nmap"]),
            ("apt-get", ["apt-get", "install", "-y", "nmap"]),
        ],
    ),
    Scanner(
        "ffuf",
        "ffuf",
        [
            ("brew", ["brew", "install", "ffuf"]),
            ("apt-get", ["apt-get", "install", "-y", "ffuf"]),
            ("go", ["go", "install", "github.com/ffuf/ffuf/v2@latest"]),
        ],
    ),
    Scanner(
        "gitleaks",
        "gitleaks",
        [
            ("brew", ["brew", "install", "gitleaks"]),
            ("go", ["go", "install", "github.com/gitleaks/gitleaks/v8@latest"]),
        ],
    ),
    Scanner(
        "sqlmap",
        "sqlmap",
        [
            ("brew", ["brew", "install", "sqlmap"]),
            ("apt-get", ["apt-get", "install", "-y", "sqlmap"]),
            ("pipx", ["pipx", "install", "sqlmap"]),
        ],
    ),
    Scanner(
        "nikto",
        "nikto",
        [
            ("brew", ["brew", "install", "nikto"]),
            ("apt-get", ["apt-get", "install", "-y", "nikto"]),
        ],
    ),
    Scanner(
        "wpscan",
        "wpscan",
        [
            ("gem", ["gem", "install", "wpscan"]),
            ("apt-get", ["apt-get", "install", "-y", "wpscan"]),
        ],
        note="Needs Ruby; `gem install wpscan` pulls it into the user gem dir.",
    ),
)

_BY_NAME = {s.name: s for s in SCANNERS}


def _available_managers() -> set[str]:
    return {m for m in ("brew", "apt-get", "go", "pipx", "gem") if shutil.which(m)}


def tool_status() -> dict[str, dict[str, object]]:
    """Return {name: {installed, binary, path, note}} for every scanner."""
    status: dict[str, dict[str, object]] = {}
    for s in SCANNERS:
        path = shutil.which(s.binary)
        status[s.name] = {
            "installed": path is not None,
            "binary": s.binary,
            "path": path,
            "note": s.note,
        }
    return status


def _run_install(argv: list[str]) -> tuple[bool, str]:
    """Run one install command, prepending sudo for apt/gem when not root."""
    manager = argv[0]
    cmd = list(argv)
    if manager in {"apt-get", "gem"} and os.geteuid() != 0 and shutil.which("sudo"):
        cmd = ["sudo", *cmd]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv from the registry, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=_INSTALL_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return False, f"{manager} not found"
    except subprocess.TimeoutExpired:
        return False, f"{' '.join(cmd)} timed out after {_INSTALL_TIMEOUT}s"
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-400:]
        return False, f"{' '.join(cmd)} exited {proc.returncode}: {tail}"
    return True, " ".join(cmd)


def install_tools(names: list[str] | None = None) -> dict[str, dict[str, object]]:
    """Install missing scanner binaries. Returns a per-tool result map.

    `names=None` installs all. Already-present tools are skipped. Each tool
    tries its candidates in order until one whose manager is available
    succeeds.
    """
    managers = _available_managers()
    targets = [_BY_NAME[n] for n in names if n in _BY_NAME] if names else list(SCANNERS)
    results: dict[str, dict[str, object]] = {}
    for s in targets:
        if shutil.which(s.binary):
            results[s.name] = {"status": "already", "detail": shutil.which(s.binary)}
            continue
        usable = [(m, argv) for m, argv in s.candidates if m in managers]
        if not usable:
            wanted = sorted({m for m, _ in s.candidates})
            results[s.name] = {
                "status": "skipped",
                "detail": f"no available installer; needs one of: {', '.join(wanted)}",
            }
            continue
        errors = []
        for _manager, argv in usable:
            logger.info("Installing %s via: %s", s.name, " ".join(argv))
            ok, detail = _run_install(argv)
            if ok:
                results[s.name] = {"status": "installed", "detail": detail}
                break
            errors.append(detail)
        else:
            results[s.name] = {"status": "failed", "detail": " | ".join(errors)}
    return results


def render_install_report(results: dict[str, dict[str, object]]) -> str:
    """Human-readable summary for the CLI."""
    order = {"installed": 0, "already": 1, "skipped": 2, "failed": 3}
    icon = {"installed": "✓", "already": "•", "skipped": "-", "failed": "✗"}
    lines = ["Scanner tools:"]

    def _sort_key(kv: tuple[str, dict[str, object]]) -> tuple[int, str]:
        return order.get(str(kv[1]["status"]), 9), kv[0]

    for name, r in sorted(results.items(), key=_sort_key):
        status = str(r["status"])
        lines.append(f"  {icon.get(status, '?')} {name}: {status} — {r['detail']}")
    failed = [n for n, r in results.items() if r["status"] in {"failed", "skipped"}]
    if failed:
        lines.append("")
        lines.append(f"Install manually: {', '.join(sorted(failed))}. See registry for commands.")
    return "\n".join(lines)


def missing_tools() -> list[str]:
    """Names of scanners whose binary is not on PATH."""
    return [name for name, s in tool_status().items() if not s["installed"]]


@function_tool
async def check_tools(ctx: RunContextWrapper) -> dict[str, object]:
    """Report which external scanner binaries are installed on this host.

    The active-testing tools (``nuclei_scan``, ``run_scanner``,
    ``gitleaks_scan``, …) need their CLI installed. Call this to see what you
    can actually run before you try; missing ones can be installed with
    ``strix mcp --install-tools`` on the host.
    """
    del ctx
    status = tool_status()
    installed = sorted(n for n, s in status.items() if s["installed"])
    missing = sorted(n for n, s in status.items() if not s["installed"])
    return {"installed": installed, "missing": missing, "detail": status}
