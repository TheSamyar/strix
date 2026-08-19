"""Per-run attack-surface map + auth/role matrix — mirrored to
{state_dir}/attack_surface.json.

Gives the client somewhere durable to record what it mapped (endpoints /
params) and which (role x endpoint) access-control cells it has worked
through, so testing is systematic and survives a restart instead of
resetting each turn.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


# Single store, three sections. Endpoints keyed by "METHOD path" (the dedup
# key, also the endpoint id used by the matrix); roles keyed by name; matrix
# cells keyed by "role\x1fendpoint_id".
_store: dict[str, dict[str, Any]] = {"endpoints": {}, "roles": {}, "matrix": {}}
_lock = threading.RLock()
_store_path: Path | None = None

_VALID_CELL_RESULTS = ["tested_ok", "vuln", "skipped"]
_CELL_SEP = "\x1f"


def _endpoint_id(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def _cell_key(role: str, endpoint_id: str) -> str:
    return f"{role}{_CELL_SEP}{endpoint_id}"


def hydrate_attack_surface_from_disk(state_dir: Path) -> None:
    global _store_path  # noqa: PLW0603
    _store_path = state_dir / "attack_surface.json"
    with _lock:
        for section in _store.values():
            section.clear()
        if not _store_path.exists():
            return
        try:
            data = json.loads(_store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "attack_surface.json at %s is unreadable; starting empty",
                _store_path,
            )
            return
        if not isinstance(data, dict):
            return
        for name in ("endpoints", "roles", "matrix"):
            loaded = data.get(name)
            if isinstance(loaded, dict):
                _store[name].update(
                    {k: v for k, v in loaded.items() if isinstance(k, str) and isinstance(v, dict)}
                )
        logger.info(
            "attack surface hydrated from %s (%d endpoint(s), %d role(s))",
            _store_path,
            len(_store["endpoints"]),
            len(_store["roles"]),
        )


def _persist() -> None:
    path = _store_path
    if path is None:
        return
    try:
        payload = json.dumps(_store, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _lock,
            tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp,
        ):
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("attack surface persist to %s failed", path)


def _record_endpoint_impl(
    path: str,
    method: str = "GET",
    params: list[str] | None = None,
    auth_required: bool = False,
    notes: str = "",
) -> dict[str, Any]:
    with _lock:
        if not path or not path.strip():
            return {"success": False, "error": "path/url cannot be empty", "endpoint_id": None}
        path = path.strip()
        method = (method or "GET").strip().upper()
        endpoint_id = _endpoint_id(method, path)
        now = datetime.now(UTC).isoformat()
        existing = _store["endpoints"].get(endpoint_id)
        entry = {
            "path": path,
            "method": method,
            "params": params or [],
            "auth_required": auth_required,
            "notes": notes,
            "created_at": existing.get("created_at", now) if existing else now,
            "updated_at": now,
        }
        _store["endpoints"][endpoint_id] = entry
        _persist()
        return {
            "success": True,
            "endpoint_id": endpoint_id,
            "updated": existing is not None,
            "total_count": len(_store["endpoints"]),
        }


def _list_attack_surface_impl() -> dict[str, Any]:
    with _lock:
        endpoints = [{"endpoint_id": eid, **entry} for eid, entry in _store["endpoints"].items()]
        endpoints.sort(key=lambda e: e.get("endpoint_id", ""))
        return {"success": True, "endpoints": endpoints, "total_count": len(endpoints)}


def _record_role_impl(
    name: str,
    description: str = "",
    credentials_ref: str = "",
) -> dict[str, Any]:
    with _lock:
        if not name or not name.strip():
            return {"success": False, "error": "role name cannot be empty"}
        name = name.strip()
        _store["roles"][name] = {
            "name": name,
            "description": description,
            # A label/reference the client resolves to real creds itself — the
            # tool docstring tells the client never to pass the secret here.
            "credentials_ref": credentials_ref,
            "created_at": datetime.now(UTC).isoformat(),
        }
        _persist()
        return {"success": True, "role": name, "total_count": len(_store["roles"])}


def _auth_matrix_impl() -> dict[str, Any]:
    with _lock:
        cells: list[dict[str, Any]] = []
        for role in sorted(_store["roles"]):
            for endpoint_id in sorted(_store["endpoints"]):
                endpoint = _store["endpoints"][endpoint_id]
                stored = _store["matrix"].get(_cell_key(role, endpoint_id))
                cells.append(
                    {
                        "role": role,
                        "endpoint": endpoint_id,
                        "method": endpoint.get("method"),
                        "path": endpoint.get("path"),
                        "auth_required": endpoint.get("auth_required", False),
                        "result": stored.get("result", "untested") if stored else "untested",
                    }
                )
        return {
            "success": True,
            "cells": cells,
            "roles": len(_store["roles"]),
            "endpoints": len(_store["endpoints"]),
            "count": len(cells),
        }


def _mark_matrix_cell_impl(role: str, endpoint: str, result: str) -> dict[str, Any]:
    with _lock:
        if role not in _store["roles"]:
            return {"success": False, "error": f"Unknown role '{role}' — record_role first"}
        if endpoint not in _store["endpoints"]:
            return {
                "success": False,
                "error": f"Unknown endpoint '{endpoint}' — record_endpoint first",
            }
        if result not in _VALID_CELL_RESULTS:
            return {
                "success": False,
                "error": f"result must be one of: {', '.join(_VALID_CELL_RESULTS)}",
            }
        _store["matrix"][_cell_key(role, endpoint)] = {
            "result": result,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        _persist()
        return {"success": True, "role": role, "endpoint": endpoint, "result": result}


@function_tool(timeout=30)
async def record_endpoint(
    ctx: RunContextWrapper,
    path: str,
    method: str = "GET",
    params: list[str] | None = None,
    auth_required: bool = False,
    notes: str = "",
) -> str:
    """Record one endpoint/parameter entry in the attack-surface map.

    Build this during recon so you can later iterate "test each of these
    N params x each vuln class". Deduped on (method, path): recording the
    same pair again updates the entry in place. Persists for the lifetime
    of the run and survives a restart.

    Args:
        path: URL or path (e.g. ``/api/users/{id}`` or a full URL).
        method: HTTP method. Default ``"GET"``.
        params: Parameters worth fuzzing (query/body/header names).
        auth_required: Whether the endpoint needs authentication.
        notes: Free-form observations (content type, roles seen, etc.).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _record_endpoint_impl, path, method, params, auth_required, notes
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_attack_surface(ctx: RunContextWrapper) -> str:
    """Return the recorded attack surface as JSON.

    Each entry has ``endpoint_id`` (``"METHOD path"``), ``params``,
    ``auth_required`` and ``notes`` — iterate it to drive per-endpoint x
    per-class testing. The ``endpoint_id`` is what ``mark_matrix_cell``
    expects as its ``endpoint`` argument.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_list_attack_surface_impl),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def record_role(
    ctx: RunContextWrapper,
    name: str,
    description: str = "",
    credentials_ref: str = "",
) -> str:
    """Register a role/principal for access-control testing.

    Do NOT pass raw secrets. ``credentials_ref`` is a label/reference you
    resolve to real credentials yourself (e.g. ``"admin-session-in-my-notes"``
    or an env-var name) — it is persisted to disk in plain text, so keep it
    a pointer, never the token/password.

    Args:
        name: Role/principal name (e.g. ``"admin"``, ``"user-a"``).
        description: What this role can do / why it matters.
        credentials_ref: A reference/label for the creds — never the secret.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_record_role_impl, name, description, credentials_ref),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def auth_matrix(ctx: RunContextWrapper) -> str:
    """Cross recorded roles x recorded endpoints into a test matrix.

    Returns one cell per (role, endpoint) with a ``result`` you update via
    ``mark_matrix_cell`` (``untested`` until you do). Work every cell to
    cover IDOR and horizontal/vertical privilege escalation: try each
    endpoint as each role and check access is what it should be.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_auth_matrix_impl),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def mark_matrix_cell(
    ctx: RunContextWrapper,
    role: str,
    endpoint: str,
    result: str,
) -> str:
    """Update one (role, endpoint) cell of the auth matrix.

    Args:
        role: A role name from ``record_role``.
        endpoint: An ``endpoint_id`` (``"METHOD path"``) from
            ``list_attack_surface`` / ``auth_matrix``.
        result: One of ``tested_ok`` (access correct), ``vuln`` (access
            control broken — file a report), or ``skipped``.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_mark_matrix_cell_impl, role, endpoint, result),
        ensure_ascii=False,
        default=str,
    )
