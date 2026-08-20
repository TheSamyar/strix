"""Coverage critic — say what has NOT been tested yet, so 'done' means thorough.

A finding list shows what was found; it can't show what was skipped. This
cross-references the run's pending [plan]/[coverage]/[data-leak] todos, the
key probe tools that never ran (from the audit log), and the findings filed,
then gives a blunt thoroughness verdict — shallow vs looks-thorough.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from strix.core.paths import runtime_state_dir
from strix.report.state import get_global_report_state
from strix.tools.attack_surface.tools import _auth_matrix_impl, _list_attack_surface_impl
from strix.tools.endpoint_risk.tools import _score_endpoint
from strix.tools.todo.tools import _get_agent_todos


# Audit filename mirrors mcp_server.AUDIT_LOG_NAME (kept local to avoid importing
# the server module into a tool — that would be circular).
_AUDIT_LOG_NAME = "mcp_audit.jsonl"

# A deep web audit should exercise these at least once regardless of target
# shape — recon, injection, access control, data exposure, misconfig, secrets.
# Surface-specific probes (graphql/upload/authz-grid/…) are required
# conditionally by ``_surface_gaps`` based on what was actually mapped.
_KEY_TOOLS = (
    "profile_target",
    "endpoint_risk_rank",
    "param_discover",
    "content_discover",
    "injection_fuzz",
    "authz_probe",
    "data_exposure_probe",
    "ssr_leak_scan",
    "security_headers_probe",
    "header_leak",
    "frontend_secret_scan",
    "jwt_audit",
    "cors_probe",
    "rate_limit_probe",
)


def _tools_run() -> set[str] | None:
    """Tool names seen in the audit log, or None if there's no log to read."""
    state = get_global_report_state()
    if state is None:
        return None
    path = runtime_state_dir(state.get_run_dir()) / _AUDIT_LOG_NAME
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    names: set[str] = set()
    for line in lines:
        try:
            names.add(str(json.loads(line).get("tool")))
        except (json.JSONDecodeError, ValueError):
            continue
    return names


def _surface_gaps(ran: set[str] | None) -> list[str]:  # noqa: PLR0912, PLR0915
    """Depth requirements implied by the mapped attack surface.

    Reads the attack-surface store (endpoints/roles/authz matrix) and returns
    the deep tests the *actual* surface demands but that never ran — the bugs
    most often missed: cross-identity authz (IDOR/BOLA), GraphQL abuse, upload
    bypass, injection on mapped params, second-order/stored injection. Advisory
    only; ``ran is None`` (no audit log) yields no gaps.
    """
    if ran is None:
        return []
    try:
        endpoints = _list_attack_surface_impl().get("endpoints", [])
        matrix = _auth_matrix_impl()
    except Exception:  # noqa: BLE001 — the critic must never break a run
        return []

    gaps: list[str] = []
    blob = " ".join(f"{e.get('path', '')} {e.get('notes', '')}".lower() for e in endpoints)
    has_params = any(e.get("params") for e in endpoints)
    has_auth_gated = any(e.get("auth_required") for e in endpoints)
    _write_methods = {"POST", "PUT", "DELETE", "PATCH"}
    write_eps = [e for e in endpoints if str(e.get("method", "GET")).upper() in _write_methods]
    has_write = bool(write_eps)
    has_write_params = any(e.get("params") for e in write_eps)
    has_write_authed = any(e.get("auth_required") for e in write_eps)
    _redirect_names = {
        "redirect", "next", "return", "return_to", "returnto", "url", "callback",
        "continue", "dest", "destination", "goto", "redirect_uri", "redir",
    }
    params_lower_all = {str(p).lower() for e in endpoints for p in (e.get("params") or [])}
    has_redirect_param = bool(params_lower_all & _redirect_names) or any(
        w in blob for w in ("redirect", "return_to", "callback")
    )
    is_ai_app = any(
        w in blob
        for w in (
            "/chat", "/ai", "llm", "completion", "prompt", "assistant",
            "/agent", "message", "conversation",
        )
    )
    _ssrf_names = {
        "url",
        "uri",
        "link",
        "src",
        "image",
        "img",
        "file",
        "path",
        "dest",
        "redirect",
        "next",
        "target",
        "webhook",
        "callback",
        "feed",
        "proxy",
        "host",
    }
    _lfi_names = {
        "file",
        "path",
        "page",
        "template",
        "include",
        "doc",
        "download",
        "filename",
        "dir",
        "folder",
        "view",
        "lang",
        "locale",
        "load",
        "read",
        "src",
    }
    params_lower = {str(p).lower() for e in endpoints for p in (e.get("params") or [])}
    has_ssrf_param = bool(params_lower & _ssrf_names)
    has_lfi_param = bool(params_lower & _lfi_names)
    roles = int(matrix.get("roles", 0))

    if roles >= 2 and not ({"authz_probe", "authz_matrix"} & ran):
        gaps.append(
            f"{roles} identities mapped but authorization never tested across "
            "endpoints — run authz_probe/authz_matrix (IDOR/BOLA live here)"
        )
    if "graphql" in blob and not ({"graphql_abuse", "graphql_introspection"} & ran):
        gaps.append("GraphQL endpoint mapped but graphql_abuse/introspection never ran")
    if any(w in blob for w in ("xml", "soap", "saml", ".svg")) and "xxe_probe" not in ran:
        gaps.append("XML/SOAP endpoint mapped but xxe_probe never ran (XXE file read/SSRF)")
    if any(w in blob for w in ("upload", "attachment", "/file", "multipart")) and (
        "upload_probe" not in ran
    ):
        gaps.append("upload/file endpoint mapped but upload_probe never ran")
    if has_params and not ({"injection_fuzz", "deep_fuzz"} & ran):
        gaps.append("endpoints with params mapped but no injection_fuzz/deep_fuzz on them")
    if has_ssrf_param and "ssrf_probe" not in ran:
        gaps.append(
            "SSRF-prone param (url/redirect/webhook/…) mapped but ssrf_probe never "
            "ran — deep-test for metadata/internal/file:// SSRF"
        )
    if has_lfi_param and "lfi_probe" not in ran:
        gaps.append(
            "file/path param (file/path/template/include/…) mapped but lfi_probe "
            "never ran — deep-test path traversal / LFI"
        )
    if has_auth_gated and not ({"authz_probe", "walk_unauth"} & ran):
        gaps.append("auth-gated endpoints mapped but broken-access-control never tested")
    if any(w in blob for w in ("login", "signin", "sign-in", "/auth", "authenticate")) and (
        "nosql_probe" not in ran
    ):
        gaps.append("login/auth endpoint mapped but nosql_probe never ran (NoSQLi auth bypass)")
    if endpoints and "stored_probe" not in ran:
        gaps.append("second-order/stored injection (stored_probe) never attempted")
    if has_redirect_param and "redirect_probe" not in ran:
        gaps.append(
            "redirect/return/callback param mapped but redirect_probe never ran "
            "(open redirect → phishing/token theft)"
        )
    if has_write_authed and "csrf_probe" not in ran:
        gaps.append(
            "authenticated state-changing endpoints mapped but csrf_probe never ran (CSRF)"
        )
    if has_write_params and "mass_assignment_probe" not in ran:
        gaps.append(
            "write endpoints with params mapped but mass_assignment_probe never ran "
            "(privilege/field over-posting)"
        )
    if is_ai_app and not ({"prompt_injection_probe", "mcp_tool_poisoning_audit"} & ran):
        gaps.append(
            "AI/LLM surface mapped but prompt_injection_probe/mcp_tool_poisoning_audit "
            "never ran (direct/indirect prompt injection)"
        )
    if any(w in blob for w in ("oauth", "sso", "openid", "/callback", "authorize")) and (
        "oauth_probe" not in ran
    ):
        gaps.append("OAuth/SSO flow mapped but oauth_probe never ran (redirect/state/code abuse)")
    if any(w in blob for w in ("login", "signin", "sign-in", "register", "signup")) and (
        "user_enumeration_probe" not in ran
    ):
        gaps.append("auth/registration endpoint mapped but user_enumeration_probe never ran")
    _race_nouns = (
        "balance", "wallet", "coupon", "credit", "payment",
        "order", "vote", "transfer", "redeem",
    )
    if has_write and "race_probe" not in ran and any(w in blob for w in _race_nouns):
        gaps.append("money/limited-resource write mapped but race_probe never ran (TOCTOU/race)")
    return gaps


def _norm_path(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" in text or text.startswith("//"):
        split = urlsplit(text if "://" in text else f"http:{text}")
        text = split.path or "/"
    else:
        text = text.split("?", 1)[0].split("#", 1)[0]
        method, _, rest = text.partition(" ")
        if rest.startswith("/") and method.isalpha() and method.isupper():
            text = rest
    if not text.startswith("/"):
        text = "/" + text
    text = text.casefold()
    if len(text) > 1:
        text = text.rstrip("/")
    return text or "/"


def _is_param_seg(seg: str) -> bool:
    return (seg.startswith("{") and seg.endswith("}") and len(seg) > 2) or (
        seg.startswith(":") and len(seg) > 1
    )


def _path_covers(observed: str, mapped: str) -> bool:
    # prefix at a slash, or {param}/:param as one segment (finding /users/2 covers /users/{id})
    obs, mapped_n = _norm_path(observed), _norm_path(mapped)
    if not obs or not mapped_n:
        return False
    if obs == mapped_n:
        return True
    if (
        obs != "/"
        and mapped_n != "/"
        and (obs.startswith(mapped_n + "/") or mapped_n.startswith(obs + "/"))
    ):
        return True
    left = [s for s in obs.split("/") if s]
    right = [s for s in mapped_n.split("/") if s]
    if len(left) != len(right):
        return False
    return all(
        a == b or _is_param_seg(a) or _is_param_seg(b) for a, b in zip(left, right, strict=True)
    )


def _mapped_paths() -> list[str]:
    try:
        endpoints = _list_attack_surface_impl().get("endpoints") or []
    except Exception:  # noqa: BLE001 — critic must never break a run
        return []
    paths: list[str] = []
    for item in endpoints:
        path = item.get("path") or item.get("url") or ""
        if path:
            paths.append(str(path))
    return paths


def _walk_observed_paths(state: Any) -> list[str]:
    if state is None:
        return []
    path = state.get_run_dir() / "walk.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    found: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        url = row.get("url")
        if url:
            found.append(str(url))
        eid = row.get("endpoint_id")
        if eid:
            parts = str(eid).split(" ", 1)
            found.append(parts[-1])
    return found


def _observed_cover_paths(state: Any) -> list[str]:
    observed: list[str] = []
    if state is not None:
        for vuln in state.get_existing_vulnerabilities():
            for key in ("endpoint", "target"):
                val = vuln.get(key)
                if val:
                    observed.append(str(val))
    observed.extend(_walk_observed_paths(state))
    return observed


def _endpoint_coverage(state: Any) -> tuple[int, list[str], int, float]:
    mapped = _mapped_paths()
    n = len(mapped)
    if n == 0:
        return 0, [], 0, 1.0
    observed = _observed_cover_paths(state)
    untested = [p for p in mapped if not any(_path_covers(o, p) for o in observed)]
    ratio = (n - len(untested)) / n
    return n, untested[:25], len(untested), ratio


# One strong signal (IDOR id, auth/admin, SSRF/traversal param) scores >= 3 in
# endpoint_risk. Ratio-only coverage lets an agent hit 0.7 on cheap static routes
# while skipping exactly these — so a high-risk endpoint left untested blocks
# "looks_thorough" regardless of the ratio.
_HIGH_RISK_SCORE = 3


def _untested_high_risk(state: Any) -> list[dict[str, Any]]:
    """Mapped endpoints with a strong risk signal that were never tested."""
    try:
        endpoints = _list_attack_surface_impl().get("endpoints") or []
    except Exception:  # noqa: BLE001 — critic must never break a run
        return []
    observed = _observed_cover_paths(state)
    risky: list[dict[str, Any]] = []
    for ep in endpoints:
        path = str(ep.get("path") or ep.get("url") or ep.get("endpoint") or "")
        if not path or any(_path_covers(o, path) for o in observed):
            continue
        scored = _score_endpoint(
            str(ep.get("method") or "GET"),
            path,
            [str(p) for p in (ep.get("params") or [])],
        )
        if scored["score"] >= _HIGH_RISK_SCORE:
            risky.append(scored)
    risky.sort(key=lambda r: r["score"], reverse=True)
    return risky[:25]


def _coverage_gaps_impl(agent_id: str) -> dict[str, Any]:
    todos = _get_agent_todos(agent_id)
    pending: dict[str, list[str]] = {"plan": [], "coverage": [], "data_leak": [], "other": []}
    for todo in todos.values():
        if todo.get("status") == "done":
            continue
        title = str(todo.get("title", ""))
        if "[plan]" in title:
            pending["plan"].append(title)
        elif "[coverage]" in title:
            pending["coverage"].append(title)
        elif "[data-leak]" in title:
            pending["data_leak"].append(title)
        else:
            pending["other"].append(title)
    pending_count = sum(len(v) for v in pending.values())

    state = get_global_report_state()
    findings = len(state.get_existing_vulnerabilities()) if state is not None else 0

    ran = _tools_run()
    if ran is None:
        key_tools_not_run: list[str] | str = "unknown (no audit log yet)"
        unrun_count = 0
    else:
        missing = [t for t in _KEY_TOOLS if t not in ran]
        key_tools_not_run = missing
        unrun_count = len(missing)

    surface_gaps = _surface_gaps(ran)
    mapped_n, untested_endpoints, untested_n, ratio = _endpoint_coverage(state)
    untested_high_risk = _untested_high_risk(state)

    # Thoroughness is endpoint coverage, not "a tool name appeared once". A
    # high-risk endpoint left untested blocks "thorough" no matter the ratio —
    # ratio padding on cheap routes must not hide a skipped admin/IDOR/SSRF path.
    if (
        pending_count == 0
        and unrun_count <= 2
        and not surface_gaps
        and not untested_high_risk
        and (mapped_n == 0 or ratio >= 0.85)
    ):
        verdict = "looks_thorough"
        rec = "Coverage looks complete; dedupe_reports then wrap up."
    elif (
        pending_count > 5
        or unrun_count >= 6
        or len(surface_gaps) >= 2
        or len(untested_high_risk) >= 2
        or (mapped_n >= 5 and ratio < 0.3)
    ):
        verdict = "shallow"
        rec = "Many classes/tools untouched — keep testing before declaring done."
    else:
        verdict = "in_progress"
        rec = "Some gaps remain; clear the pending items, unrun key probes, and surface gaps."

    return {
        "success": True,
        "findings_filed": findings,
        "pending_todo_count": pending_count,
        "pending_by_type": pending,
        "key_tools_not_run": key_tools_not_run,
        "surface_gaps": surface_gaps,
        "mapped_endpoint_count": mapped_n,
        "untested_endpoints": untested_endpoints,
        "untested_endpoint_count": untested_n,
        "untested_high_risk": untested_high_risk,
        "endpoint_coverage_ratio": ratio,
        "thoroughness": verdict,
        "recommendation": (
            f"{rec} Test the high-risk endpoints still untested first: "
            + ", ".join(f"{r['method']} {r['endpoint']}" for r in untested_high_risk)
            if untested_high_risk
            else rec
        ),
    }


@function_tool(timeout=30, strict_mode=False)
async def coverage_gaps(ctx: RunContextWrapper) -> str:
    """Report what has NOT been tested yet — the coverage critic.

    Cross-references pending ``[plan]``/``[coverage]``/``[data-leak]`` todos, the
    key probe tools that never appear in the audit log, and the findings filed,
    then returns a blunt ``thoroughness`` verdict (shallow / in_progress /
    looks_thorough) so you know whether a scan is actually done or just shallow.

    Also reports ``surface_gaps`` — deep tests the *mapped* attack surface
    demands but that never ran (multi-identity authorization/IDOR, GraphQL
    abuse, upload bypass, injection on mapped params, stored/second-order).
    Any surface gap blocks a ``looks_thorough`` verdict.

    ``untested_high_risk`` lists mapped endpoints with a strong risk signal
    (object id/IDOR, auth/admin, SSRF/traversal, upload, money/PII) that were
    never tested. Any high-risk endpoint left untested blocks ``looks_thorough``
    regardless of the overall coverage ratio — so cheap static routes can't pad
    the ratio while the endpoints that actually matter go unprobed.

    Returns JSON with ``pending_by_type``, ``key_tools_not_run``,
    ``surface_gaps``, ``findings_filed``, ``mapped_endpoint_count``,
    ``untested_endpoints`` (capped at 25), ``untested_endpoint_count``,
    ``untested_high_risk``, ``endpoint_coverage_ratio``, ``thoroughness``, and a
    ``recommendation``.
    """
    agent_id = "mcp"
    if isinstance(ctx.context, dict):
        agent_id = str(ctx.context.get("agent_id") or "mcp")
    return json.dumps(
        await asyncio.to_thread(_coverage_gaps_impl, agent_id), ensure_ascii=False, default=str
    )
