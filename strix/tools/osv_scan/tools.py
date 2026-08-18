"""Scan project dependencies for known CVEs via the OSV.dev API — stateless."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import tomllib
from pathlib import Path
from typing import Any

import requests
from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_TIMEOUT = 30
# ponytail: cap detail lookups so a huge lockfile can't fan out to thousands of GETs.
_MAX_DETAIL_LOOKUPS = 200
# Filename -> OSV ecosystem string.
_SUPPORTED_LOCKFILES = {
    "package-lock.json": "npm",
    "requirements.txt": "PyPI",
    "go.sum": "Go",
    "Cargo.lock": "crates.io",
}


def _parse_package_lock(text: str) -> list[dict[str, str]]:
    data = json.loads(text)
    out: list[dict[str, str]] = []
    # npm lockfile v2/v3 keeps everything under "packages"; v1 under "dependencies".
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project, skip it
            name = path.split("node_modules/")[-1]
            version = meta.get("version")
            if name and isinstance(version, str):
                out.append({"name": name, "version": version, "ecosystem": "npm"})
        return out
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            version = meta.get("version") if isinstance(meta, dict) else None
            if isinstance(version, str):
                out.append({"name": name, "version": version, "ecosystem": "npm"})
    return out


def _parse_requirements(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "==" not in line:
            continue  # only exact pins are queryable
        name, _, version = line.partition("==")
        name = re.split(r"[\[;\s]", name, maxsplit=1)[0].strip()
        version = version.strip()
        if name and version:
            out.append({"name": name, "version": version, "ecosystem": "PyPI"})
    return out


def _parse_go_sum(text: str) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1].removesuffix("/go.mod")
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "version": version.lstrip("v"), "ecosystem": "Go"})
    return out


def _parse_cargo_lock(text: str) -> list[dict[str, str]]:
    data = tomllib.loads(text)
    out: list[dict[str, str]] = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if isinstance(name, str) and isinstance(version, str):
            out.append({"name": name, "version": version, "ecosystem": "crates.io"})
    return out


_PARSERS = {
    "package-lock.json": _parse_package_lock,
    "requirements.txt": _parse_requirements,
    "go.sum": _parse_go_sum,
    "Cargo.lock": _parse_cargo_lock,
}


def _collect_packages(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    """Return (packages, lockfiles_scanned) for a dir or single lockfile."""
    if path.is_file():
        files = [path] if path.name in _PARSERS else []
    else:
        files = [f for name in _PARSERS for f in path.rglob(name) if f.is_file()]
    packages: list[dict[str, str]] = []
    scanned: list[str] = []
    for f in files:
        try:
            parsed = _PARSERS[f.name](f.read_text(encoding="utf-8"))
        except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError):
            logger.exception("failed to parse lockfile %s", f)
            continue
        scanned.append(str(f))
        packages.extend(parsed)
    return packages, scanned


def _query_osv(packages: list[dict[str, str]]) -> tuple[list[list[str]], str | None]:
    """Batch-query OSV; return per-package lists of vuln IDs (aligned to input)."""
    queries = [
        {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
        for p in packages
    ]
    resp = requests.post(_OSV_BATCH_URL, json={"queries": queries}, timeout=_TIMEOUT)
    resp.raise_for_status()
    results = resp.json().get("results", [])
    ids: list[list[str]] = []
    for r in results:
        vulns = r.get("vulns", []) if isinstance(r, dict) else []
        ids.append([v["id"] for v in vulns if isinstance(v, dict) and v.get("id")])
    return ids, None


def _vuln_details(vuln_id: str) -> tuple[str, str]:
    """Best-effort (summary, severity) for one vuln id; empty strings on failure."""
    try:
        resp = requests.get(f"{_OSV_VULN_URL}{vuln_id}", timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return "", ""
    summary = data.get("summary") or data.get("details") or ""
    severity = ""
    sev_list = data.get("severity")
    if isinstance(sev_list, list) and sev_list and isinstance(sev_list[0], dict):
        severity = str(sev_list[0].get("score", ""))
    return str(summary)[:500], severity


def _scan_impl(path: str | None, packages: list[dict[str, str]] | None) -> dict[str, Any]:
    pkgs = list(packages) if packages else []
    scanned: list[str] = []
    if path:
        p = Path(path).expanduser()
        if not p.exists():
            return {"success": False, "error": f"Path not found: {path}"}
        found, scanned = _collect_packages(p)
        pkgs.extend(found)

    if not pkgs:
        return {
            "success": True,
            "lockfiles_scanned": scanned,
            "packages_checked": 0,
            "vulnerable_count": 0,
            "vulnerable_packages": [],
            "message": "No supported lockfiles or packages found "
            f"(supported: {', '.join(_SUPPORTED_LOCKFILES)}).",
        }

    try:
        id_lists, _ = _query_osv(pkgs)
    except (requests.RequestException, ValueError) as e:
        return {
            "success": False,
            "error": f"OSV API request failed: {type(e).__name__}: {e}",
            "lockfiles_scanned": scanned,
            "packages_checked": len(pkgs),
        }

    detail_cache: dict[str, tuple[str, str]] = {}
    lookups = 0
    vulnerable: list[dict[str, Any]] = []
    for pkg, vuln_ids in zip(pkgs, id_lists, strict=False):
        if not vuln_ids:
            continue
        summaries: list[str] = []
        severities: list[str] = []
        for vid in vuln_ids:
            if vid not in detail_cache and lookups < _MAX_DETAIL_LOOKUPS:
                detail_cache[vid] = _vuln_details(vid)
                lookups += 1
            summary, severity = detail_cache.get(vid, ("", ""))
            if summary:
                summaries.append(summary)
            if severity:
                severities.append(severity)
        vulnerable.append(
            {
                "package": pkg["name"],
                "version": pkg["version"],
                "ecosystem": pkg["ecosystem"],
                "vuln_ids": vuln_ids,
                "summary": summaries[0] if summaries else "",
                "severity": severities[0] if severities else "",
            }
        )

    return {
        "success": True,
        "lockfiles_scanned": scanned,
        "packages_checked": len(pkgs),
        "vulnerable_count": len(vulnerable),
        "vulnerable_packages": vulnerable,
    }


@function_tool(timeout=180, strict_mode=False)
async def osv_scan(
    ctx: RunContextWrapper,
    path: str | None = None,
    packages: list[dict[str, str]] | None = None,
) -> str:
    """Scan a project's dependencies for known vulnerabilities via OSV.dev.

    Point ``path`` at a repo directory (lockfiles are found recursively) or a
    single lockfile. Supported lockfiles: ``package-lock.json`` (npm),
    ``requirements.txt`` (PyPI), ``go.sum`` (Go), ``Cargo.lock`` (crates.io).
    Alternatively pass ``packages`` to query specific dependencies directly.

    Returns JSON: ``vulnerable_packages`` — a list of
    ``{package, version, ecosystem, vuln_ids, summary, severity}`` — plus
    ``lockfiles_scanned``, ``packages_checked``, and ``vulnerable_count``. If
    nothing was found it says so in ``message``. Network/timeout errors return
    ``{"success": false, "error": ...}`` instead of raising.

    Args:
        path: Repo directory or single lockfile path to scan.
        packages: Optional explicit deps, each ``{name, version, ecosystem}``
            where ecosystem is an OSV name like ``"npm"`` or ``"PyPI"``.
    """
    return json.dumps(
        await asyncio.to_thread(_scan_impl, path, packages),
        ensure_ascii=False,
        default=str,
    )
