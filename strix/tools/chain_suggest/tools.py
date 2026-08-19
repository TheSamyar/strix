"""Turn isolated findings into multi-step exploit chains (think like a hacker).

A scanner lists bugs; an attacker connects them. This reads the findings filed
so far and proposes chains that raise impact — a leaked service_role key becomes
full-DB takeover, an IDOR becomes mass exfiltration, an SSRF becomes cloud-
credential theft. Each suggestion names the findings it builds on and the steps.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.report.state import get_global_report_state


# A rule fires when EVERY keyword-group is matched by some finding. Each group
# matches if ANY of its keywords appears in a finding's title/cwe/class.
_RULES: tuple[dict[str, Any], ...] = (
    {
        "name": "Leaked service_role key → full database takeover",
        "needs": [["service_role", "service role"]],
        "steps": [
            "Use the leaked service_role key against /rest/v1 (bypasses RLS)",
            "Read and modify every table — users, payments, secrets",
            "Escalate: create/modify an admin account",
        ],
        "severity": "critical",
    },
    {
        "name": "IDOR/BOLA → mass data exfiltration",
        "needs": [["idor", "bola", "broken object", "access control", "broken function"]],
        "steps": [
            "Enumerate the object id across the full range",
            "Harvest every tenant's/user's records via the unscoped endpoint",
            "Pivot to PII/export/download endpoints with the same flaw",
        ],
        "severity": "high",
    },
    {
        "name": "SSRF → cloud metadata → credential theft → account pivot",
        "needs": [["ssrf", "server-side request"]],
        "steps": [
            "Point the SSRF at http://169.254.169.254/latest/meta-data/",
            "Steal the instance IAM role credentials",
            "Use the creds to read S3/other services and pivot",
        ],
        "severity": "critical",
    },
    {
        "name": "JWT forge → admin takeover",
        "needs": [["alg=none", "jwt", "json web token", "weak secret", "authentication_jwt"]],
        "steps": [
            "Forge a token (alg=none or cracked secret) with role=admin",
            "Replay it against admin-only endpoints",
            "Perform privileged actions / read all data",
        ],
        "severity": "critical",
    },
    {
        "name": "XSS + session cookie → account takeover",
        "needs": [
            ["xss", "cross-site scripting"],
            ["session", "cookie", "auth", "jwt"],
        ],
        "steps": [
            "Deliver the XSS to a logged-in victim",
            "Exfiltrate the session cookie / token",
            "Replay it to take over the account",
        ],
        "severity": "high",
    },
    {
        "name": "Exposed .env / debug → DB creds → direct database access",
        "needs": [["information disclosure", ".env", "debug", "stack trace", "verbose error"]],
        "steps": [
            "Pull DB/connection strings and API keys from the exposed config",
            "Connect directly to the database / third-party APIs",
            "Exfiltrate or tamper with data outside the app's controls",
        ],
        "severity": "high",
    },
    {
        "name": "Open redirect + OAuth → authorization-code theft",
        "needs": [["open redirect"], ["oauth", "sso", "openid"]],
        "steps": [
            "Set redirect_uri / return path to an attacker host via the open redirect",
            "Capture the leaked OAuth code/token",
            "Exchange it for the victim's session",
        ],
        "severity": "high",
    },
    {
        "name": "File upload + path traversal → webshell / RCE",
        "needs": [["upload", "file upload"], ["traversal", "lfi", "path"]],
        "steps": [
            "Upload a payload to a path you control via the traversal",
            "Reach it as an executable/script",
            "Gain code execution on the host",
        ],
        "severity": "critical",
    },
    {
        "name": "Broken logout → session replay after 'logout'",
        "needs": [["session invalidation", "broken logout", "logout"]],
        "steps": [
            "Capture a token, then log the victim out",
            "Replay the token — still valid server-side",
            "Maintain persistent access",
        ],
        "severity": "medium",
    },
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding_signal(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("title", ""),
        finding.get("cwe", ""),
        finding.get("finding_class", ""),
        finding.get("area", ""),
    ]
    return " ".join(str(p) for p in parts).lower()


def _chain_suggest_impl(findings: list[dict[str, Any]] | None) -> dict[str, Any]:
    if findings is None:
        state = get_global_report_state()
        findings = state.get_existing_vulnerabilities() if state is not None else []
    if not findings:
        return {"success": True, "chains": [], "note": "no findings yet — nothing to chain"}

    signals = [(f.get("id") or f.get("title") or "?", _finding_signal(f)) for f in findings]

    chains: list[dict[str, Any]] = []
    for rule in _RULES:
        matched_ids: list[str] = []
        satisfied = True
        for group in rule["needs"]:
            hits = [fid for fid, sig in signals if any(kw in sig for kw in group)]
            if not hits:
                satisfied = False
                break
            matched_ids.extend(hits)
        if satisfied:
            chains.append(
                {
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "builds_on": sorted(set(matched_ids)),
                    "steps": rule["steps"],
                }
            )
    chains.sort(key=lambda c: _SEVERITY_ORDER.get(c["severity"], 5))
    return {
        "success": True,
        "findings_considered": len(findings),
        "chain_count": len(chains),
        "chains": chains,
    }


@function_tool(timeout=30, strict_mode=False)
async def suggest_chains(
    ctx: RunContextWrapper, findings: list[dict[str, Any]] | None = None
) -> str:
    """Propose multi-step exploit chains from the findings filed so far.

    Reads this run's vulnerability reports (or a ``findings`` list you pass) and
    matches them against known escalation patterns — leaked service_role →
    DB takeover, IDOR → mass exfiltration, SSRF → cloud-cred theft, JWT forge →
    admin, XSS+session → ATO, etc. Each chain names the findings it ``builds_on``
    and the steps, so you can pursue maximum impact instead of stopping at
    isolated bugs.

    Returns JSON with ``chains`` (name/severity/builds_on/steps), sorted
    most-severe first.

    Args:
        findings: Optional list of finding dicts; defaults to the run's filed
            vulnerability reports.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_chain_suggest_impl, findings), ensure_ascii=False, default=str
    )
