"""``git_recon`` — mine a git repo's history for audit-relevant intel."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from agents import function_tool


logger = logging.getLogger(__name__)

_GIT_TIMEOUT = 30
_MAX_CONTRIBUTORS = 100
_MAX_SENSITIVE = 200
_UNIT = "\x1f"  # per-field separator inside a commit line

# Filenames that shouldn't be in a repo. Matched against the lowercased path.
_SENSITIVE_SUBSTRINGS = ("credentials", "secrets", ".aws/", "id_rsa")
_SENSITIVE_BASENAMES = (".npmrc", "config.json")


def _is_sensitive(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    return (
        base == ".env"
        or base.startswith(".env.")
        or low.endswith(".pem")
        or base in _SENSITIVE_BASENAMES
        or any(s in low for s in _SENSITIVE_SUBSTRINGS)
    )


def _run_git(git: str, path: str, args: list[str]) -> str | None:
    try:
        proc = subprocess.run(  # noqa: S603
            [git, *args],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        logger.exception("git %s failed in %s", args[0] if args else "?", path)
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _contributors(git: str, path: str) -> list[dict[str, str]]:
    out = _run_git(git, path, ["log", f"--pretty=format:%an{_UNIT}%ae"])
    if not out:
        return []
    seen: dict[tuple[str, str], dict[str, str]] = {}
    for line in out.splitlines():
        name, _, email = line.partition(_UNIT)
        key = (name, email)
        if key not in seen:
            seen[key] = {"name": name, "email": email}
    return list(seen.values())[:_MAX_CONTRIBUTORS]


def _recent_commits(git: str, path: str, max_commits: int) -> list[dict[str, str]]:
    fmt = f"%H{_UNIT}%an{_UNIT}%aI{_UNIT}%s"
    out = _run_git(git, path, ["log", f"-n{max_commits}", f"--pretty=format:{fmt}"])
    if not out:
        return []
    commits: list[dict[str, str]] = []
    for line in out.splitlines():
        h, author, date, subject = [*line.split(_UNIT), "", "", "", ""][:4]
        commits.append({"hash": h, "author": author, "date": date, "subject": subject})
    return commits


def _sensitive_files(git: str, path: str) -> list[dict[str, str]]:
    # name-status across all refs: a %H line per commit, then "A\tpath" rows.
    out = _run_git(git, path, ["log", "--all", "--name-status", "--pretty=format:%H"])
    if not out:
        return []
    found: list[dict[str, str]] = []
    commit = ""
    for line in out.splitlines():
        if "\t" not in line:
            commit = line.strip()
            continue
        parts = line.split("\t")
        action, fname = parts[0], parts[-1]  # renames give status\told\tnew
        if _is_sensitive(fname):
            found.append({"path": fname, "commit": commit, "action": action})
            if len(found) >= _MAX_SENSITIVE:
                break
    return found


def _git_recon_impl(path: str, max_commits: int = 50) -> dict[str, Any]:
    git = shutil.which("git")
    if git is None:
        return {"success": False, "error": "git binary not found on PATH"}
    if not Path(path).is_dir():
        return {"success": False, "error": f"Not a directory: {path}"}
    if _run_git(git, path, ["rev-parse", "--is-inside-work-tree"]) is None:
        return {"success": False, "error": f"Not a git repository: {path}"}
    max_commits = max(1, min(max_commits, 1000))
    return {
        "success": True,
        "path": path,
        "contributors": _contributors(git, path),
        "recent_commits": _recent_commits(git, path, max_commits),
        "sensitive_files": _sensitive_files(git, path),
    }


@function_tool(timeout=60)
async def git_recon(path: str, max_commits: int = 50) -> str:
    """Recon a local git repository's history for audit-relevant intel.

    Runs read-only ``git`` commands against an already-cloned repo to
    surface who touched it, what changed recently, and whether any
    secret-shaped files were ever committed (across all branches — even
    if later deleted). Reports filenames only, never file contents.

    Returns JSON with:

    - ``contributors`` — distinct author names + emails.
    - ``recent_commits`` — last ``max_commits`` commits
      (``hash``, ``author``, ``date``, ``subject``).
    - ``sensitive_files`` — files matching secret-ish patterns
      (``.env``, ``id_rsa``, ``*.pem``, ``credentials``, ``.npmrc``,
      ``config.json``, ``.aws/``, ``secrets``), each with the ``commit``
      and ``action`` (A/M/D) that touched it.

    On a missing ``git`` binary or a non-git path this returns
    ``{"success": false, "error": ...}`` rather than raising.

    Args:
        path: Path to the local git repository directory.
        max_commits: How many recent commits to list. Default 50.
    """
    return json.dumps(
        await asyncio.to_thread(_git_recon_impl, path, max_commits),
        ensure_ascii=False,
        default=str,
    )
