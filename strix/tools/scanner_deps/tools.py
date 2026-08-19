"""Scanner dependency registry + installer.

The MCP server's active-testing tools (``nuclei_scan``, ``run_scanner``,
``gitleaks_scan``, …) shell out to third-party CLI binaries. Those are OS
packages, not Python deps, so ``pip install`` can't pull them. This module
holds the registry and the install/check logic behind
``strix mcp --install-tools`` and the MCP ``check_tools`` tool.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

# Auto-update on server start when the last update is older than this many days.
# Set STRIX_TOOL_AUTOUPDATE_DAYS=0 to disable. The auto path skips sudo installers
# so it never blocks startup on a password prompt; `--update-tools` still does them.
_DEFAULT_AUTOUPDATE_DAYS = 7
_MARKER = Path.home() / ".strix" / "tool_update.json"

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
    Scanner(
        "dalfox",
        "dalfox",
        [
            ("brew", ["brew", "install", "dalfox"]),
            ("go", ["go", "install", "github.com/hahwul/dalfox/v2@latest"]),
        ],
        note="Parameter-aware XSS scanner.",
    ),
    Scanner(
        "katana",
        "katana",
        [
            ("brew", ["brew", "install", "katana"]),
            ("go", ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"]),
        ],
        note="ProjectDiscovery crawler.",
    ),
    Scanner(
        "subfinder",
        "subfinder",
        [
            ("brew", ["brew", "install", "subfinder"]),
            (
                "go",
                ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            ),
        ],
        note="Passive subdomain enumeration.",
    ),
    Scanner(
        "arjun",
        "arjun",
        [
            ("pipx", ["pipx", "install", "arjun"]),
        ],
        note="Hidden HTTP-parameter discovery.",
    ),
    Scanner(
        "naabu",
        "naabu",
        [
            ("brew", ["brew", "install", "naabu"]),
            ("go", ["go", "install", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"]),
        ],
        note="Fast port scanner; may need libpcap for SYN scans.",
    ),
    Scanner(
        "gau",
        "gau",
        [
            ("go", ["go", "install", "github.com/lc/gau/v2/cmd/gau@latest"]),
        ],
        note="Fetch known URLs from Wayback/Common Crawl/etc.",
    ),
    Scanner(
        "dnsx",
        "dnsx",
        [
            ("brew", ["brew", "install", "dnsx"]),
            ("go", ["go", "install", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"]),
        ],
        note="Fast DNS toolkit (resolve, brute, records).",
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


def _run_install(argv: list[str], *, allow_sudo: bool = True) -> tuple[bool, str]:
    """Run one install command, prepending sudo for apt/gem when not root.

    With ``allow_sudo=False`` a command that would need sudo is skipped rather
    than run — used by the non-interactive auto-update so it never blocks on a
    password prompt.
    """
    manager = argv[0]
    cmd = list(argv)
    needs_sudo = manager in {"apt-get", "gem"} and os.geteuid() != 0
    if needs_sudo:
        if not allow_sudo:
            return False, f"{manager} needs sudo; skipped (run `strix mcp --update-tools`)"
        if shutil.which("sudo"):
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


def _to_upgrade(argv: list[str]) -> list[str]:
    """Map an install command to its upgrade form for the same manager.

    Registry argv follow a fixed shape, so the transform is per-manager:
    brew/pipx `install`→`upgrade`, gem `install`→`update`, apt-get gets
    `--only-upgrade`, and go `install …@latest` already fetches latest.
    """
    manager = argv[0]
    if manager in {"brew", "pipx"}:
        return [("upgrade" if a == "install" else a) for a in argv]
    if manager == "gem":
        return [("update" if a == "install" else a) for a in argv]
    if manager == "apt-get":
        return ["apt-get", "install", "--only-upgrade", *argv[2:]]
    return argv  # go: `@latest` reinstall already upgrades


def _refresh_nuclei_templates() -> tuple[bool, str]:
    """Best-effort `nuclei -update-templates` so template CVEs stay current."""
    if not shutil.which("nuclei"):
        return False, "nuclei not installed"
    return _run_install(["nuclei", "-update-templates"])


def install_tools(
    names: list[str] | None = None, *, upgrade: bool = False, allow_sudo: bool = True
) -> dict[str, dict[str, object]]:
    """Install missing scanner binaries, and optionally upgrade present ones.

    `names=None` covers all scanners. Each tool tries its candidates in order
    until one whose manager is available succeeds. With `upgrade=False` an
    already-present tool is left alone (`already`); with `upgrade=True` it is
    re-run through the manager's upgrade command (`upgraded`), and nuclei's
    templates are refreshed. With `allow_sudo=False` sudo-needing installers are
    skipped instead of run (non-interactive auto-update path).
    """
    managers = _available_managers()
    targets = [_BY_NAME[n] for n in names if n in _BY_NAME] if names else list(SCANNERS)
    results: dict[str, dict[str, object]] = {}
    for s in targets:
        present = shutil.which(s.binary) is not None
        if present and not upgrade:
            results[s.name] = {"status": "already", "detail": shutil.which(s.binary)}
            continue
        usable = [(m, argv) for m, argv in s.candidates if m in managers]
        if not usable:
            wanted = sorted({m for m, _ in s.candidates})
            if present:
                # Installed some other way; can't upgrade it, but it works.
                results[s.name] = {"status": "already", "detail": shutil.which(s.binary)}
            else:
                results[s.name] = {
                    "status": "skipped",
                    "detail": f"no available installer; needs one of: {', '.join(wanted)}",
                }
            continue
        errors = []
        for _manager, argv in usable:
            run_argv = _to_upgrade(argv) if present else argv
            verb = "Upgrading" if present else "Installing"
            logger.info("%s %s via: %s", verb, s.name, " ".join(run_argv))
            ok, detail = _run_install(run_argv, allow_sudo=allow_sudo)
            if ok:
                results[s.name] = {
                    "status": "upgraded" if present else "installed",
                    "detail": detail,
                }
                break
            errors.append(detail)
        else:
            results[s.name] = {"status": "failed", "detail": " | ".join(errors)}

    if upgrade and (names is None or "nuclei" in names):
        ok, detail = _refresh_nuclei_templates()
        results["nuclei-templates"] = {
            "status": "upgraded" if ok else "skipped",
            "detail": detail,
        }
    return results


def render_install_report(results: dict[str, dict[str, object]]) -> str:
    """Human-readable summary for the CLI."""
    order = {"installed": 0, "upgraded": 0, "already": 1, "skipped": 2, "failed": 3}
    icon = {"installed": "✓", "upgraded": "↑", "already": "•", "skipped": "-", "failed": "✗"}
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


def _last_update_epoch() -> float | None:
    try:
        return float(json.loads(_MARKER.read_text())["updated_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _mark_updated() -> None:
    try:
        _MARKER.parent.mkdir(parents=True, exist_ok=True)
        _MARKER.write_text(json.dumps({"updated_at": time.time()}))
    except OSError as exc:
        logger.warning("Could not write tool-update marker: %s", exc)


def _autoupdate_days() -> int:
    raw = os.environ.get("STRIX_TOOL_AUTOUPDATE_DAYS")
    if raw is None:
        return _DEFAULT_AUTOUPDATE_DAYS
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_AUTOUPDATE_DAYS


def is_stale(days: int | None = None) -> bool:
    """True if tools have never been updated or the last update is older than `days`."""
    days = _autoupdate_days() if days is None else days
    last = _last_update_epoch()
    if last is None:
        return True
    return (time.time() - last) > days * 86400


def auto_update_if_stale() -> dict[str, dict[str, object]] | None:
    """Upgrade scanners in-place if the last update is stale. Returns results, or
    None when disabled (days=0) or still fresh.

    Non-interactive: skips sudo installers so it never hangs startup. Safe to
    run in a background thread. Writes the marker regardless of per-tool outcome
    so a transient failure doesn't retry on every launch.
    """
    days = _autoupdate_days()
    if days == 0 or not is_stale(days):
        return None
    logger.info("Scanner tools stale (>%dd); auto-updating in the background…", days)
    results = install_tools(upgrade=True, allow_sudo=False)
    _mark_updated()
    upgraded = [n for n, r in results.items() if r["status"] in {"installed", "upgraded"}]
    logger.info("Auto-update done. Updated: %s", ", ".join(upgraded) or "nothing")
    return results


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
