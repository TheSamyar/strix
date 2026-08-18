"""Online CVE / advisory lookup — stateless, keyless (NVD + OSV.dev)."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import requests
from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 20


def _parse_cvss(metrics: dict[str, Any]) -> dict[str, Any] | None:
    # NVD nests CVSS v3.1/v3.0 under cvssMetricV31 / cvssMetricV30; take the first.
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "version": data.get("version"),
                "vector": data.get("vectorString"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or entries[0].get("baseSeverity"),
            }
    return None


def _lookup_cve(cve: str) -> dict[str, Any]:
    try:
        resp = requests.get(_NVD_URL, params={"cveId": cve}, timeout=_TIMEOUT)
    except requests.RequestException as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    if resp.status_code in (403, 429):
        return {
            "success": False,
            "error": f"NVD rate-limited (HTTP {resp.status_code}); retry later",
        }
    if resp.status_code != 200:
        return {"success": False, "error": f"NVD returned HTTP {resp.status_code}"}
    try:
        vulns = resp.json().get("vulnerabilities", [])
    except ValueError as e:
        return {"success": False, "error": f"NVD returned invalid JSON: {e}"}
    if not vulns:
        return {"success": False, "error": f"No NVD record for {cve}"}

    cve_obj = vulns[0].get("cve", {})
    descriptions = cve_obj.get("descriptions", [])
    description = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value") if descriptions else None,
    )
    references = [r.get("url") for r in cve_obj.get("references", []) if r.get("url")]
    cwes = [
        desc.get("value")
        for weakness in cve_obj.get("weaknesses", [])
        for desc in weakness.get("description", [])
        if desc.get("value")
    ]
    return {
        "success": True,
        "cve": cve_obj.get("id", cve),
        "description": description,
        "cvss": _parse_cvss(cve_obj.get("metrics", {})),
        "cwe": sorted(set(cwes)),
        "references": references,
        "published": cve_obj.get("published"),
        "modified": cve_obj.get("lastModified"),
    }


def _lookup_package(package: str, ecosystem: str) -> dict[str, Any]:
    try:
        resp = requests.post(
            _OSV_URL,
            json={"package": {"name": package, "ecosystem": ecosystem}},
            timeout=_TIMEOUT,
        )
    except requests.RequestException as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    if resp.status_code != 200:
        return {"success": False, "error": f"OSV returned HTTP {resp.status_code}"}
    try:
        vulns = resp.json().get("vulns", [])
    except ValueError as e:
        return {"success": False, "error": f"OSV returned invalid JSON: {e}"}

    advisories = [
        {
            "id": v.get("id"),
            "aliases": v.get("aliases", []),
            "summary": v.get("summary"),
            "affected": [
                {
                    "package": a.get("package", {}).get("name"),
                    "ranges": a.get("ranges", []),
                    "versions": a.get("versions", []),
                }
                for a in v.get("affected", [])
            ],
        }
        for v in vulns
    ]
    return {
        "success": True,
        "package": package,
        "ecosystem": ecosystem,
        "advisory_count": len(advisories),
        "advisories": advisories,
    }


def _cve_lookup_impl(
    cve: str | None, package: str | None, ecosystem: str | None
) -> dict[str, Any]:
    if cve:
        return _lookup_cve(cve.strip().upper())
    if package and ecosystem:
        return _lookup_package(package.strip(), ecosystem.strip())
    return {
        "success": False,
        "error": "Provide either `cve`, or both `package` and `ecosystem`.",
    }


@function_tool(timeout=60, strict_mode=False)
async def cve_lookup(
    ctx: RunContextWrapper,
    cve: str | None = None,
    package: str | None = None,
    ecosystem: str | None = None,
) -> str:
    """Look up vulnerability details online — no target or API key needed.

    Two modes:

    - Pass ``cve`` (e.g. ``"CVE-2021-44228"``) to query NVD 2.0 and return
      the description, CVSS v3 vector/score/severity, CWE(s), references,
      and published/modified dates.
    - Pass ``package`` + ``ecosystem`` (e.g. ``"log4j-core"`` /
      ``"Maven"``, or ``"requests"`` / ``"PyPI"``) to query OSV.dev for
      advisories affecting that package: advisory ids, aliases, summaries,
      and affected version ranges.

    At least one mode's args are required. Network, timeout, and
    rate-limit conditions (NVD is rate-limited without a key) return
    ``{"success": false, "error": ...}`` instead of raising.

    Args:
        cve: A CVE id to look up in NVD.
        package: Package name to look up in OSV (requires ``ecosystem``).
        ecosystem: OSV ecosystem for ``package`` (e.g. ``"PyPI"``,
            ``"npm"``, ``"Maven"``, ``"Go"``).
    """
    return json.dumps(
        await asyncio.to_thread(_cve_lookup_impl, cve, package, ecosystem),
        ensure_ascii=False,
        default=str,
    )
