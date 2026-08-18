"""Per-run attack-chain storage — mirrored to {state_dir}/chains.json.

A chain links filed findings (and optional free-text preconditions) into an
ordered attack path: bug A unlocks bug B unlocks C. Steps reference report ids
from the shared reporting store (``get_global_report_state``); list/read
resolve each id to its current title/severity for readability.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import function_tool

from strix.report.state import get_global_report_state


logger = logging.getLogger(__name__)


_chains_storage: dict[str, dict[str, Any]] = {}
_chains_lock = threading.RLock()
_CHAIN_ID_GENERATION_ATTEMPTS = 1024

_chains_path: Path | None = None


def _generate_chain_id() -> str | None:
    for _ in range(_CHAIN_ID_GENERATION_ATTEMPTS):
        chain_id = uuid.uuid4().hex[:6]
        if chain_id not in _chains_storage:
            return chain_id
    return None


def _report_index() -> dict[str, dict[str, Any]]:
    """Map report id -> report dict from the shared reporting store."""
    state = get_global_report_state()
    if state is None:
        return {}
    return {
        r["id"]: r
        for r in state.get_existing_vulnerabilities()
        if isinstance(r, dict) and isinstance(r.get("id"), str)
    }


def _normalize_step(step: Any) -> dict[str, Any] | None:
    """A step is either a finding id (str) or ``{"note": "..."}``."""
    if isinstance(step, str):
        text = step.strip()
        return {"finding_id": text} if text else None
    if isinstance(step, dict):
        note = step.get("note")
        if isinstance(note, str) and note.strip():
            return {"note": note.strip()}
        fid = step.get("finding_id") or step.get("id")
        if isinstance(fid, str) and fid.strip():
            return {"finding_id": fid.strip()}
    return None


def _resolve_step(step: dict[str, Any], index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Attach title/severity for a finding step, or flag it unknown."""
    entry = dict(step)
    fid = step.get("finding_id")
    if fid is not None:
        report = index.get(fid)
        if report is None:
            entry["unknown"] = True
        else:
            entry["title"] = report.get("title", "")
            entry["severity"] = report.get("severity", "")
    return entry


def hydrate_chains_from_disk(state_dir: Path) -> None:
    global _chains_path  # noqa: PLW0603
    _chains_path = state_dir / "chains.json"
    with _chains_lock:
        _chains_storage.clear()
        if not _chains_path.exists():
            return
        try:
            data = json.loads(_chains_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "chains.json at %s is unreadable; starting with empty chains",
                _chains_path,
            )
            return
        if not isinstance(data, dict):
            return
        _chains_storage.update(
            {
                cid: chain
                for cid, chain in data.items()
                if isinstance(cid, str) and isinstance(chain, dict)
            }
        )
        logger.info(
            "chains hydrated from %s (%d chain(s))",
            _chains_path,
            len(_chains_storage),
        )


def _persist() -> None:
    path = _chains_path
    if path is None:
        return
    try:
        payload = json.dumps(_chains_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _chains_lock,
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
        logger.exception("chains persist to %s failed", path)


def _unknown_finding_ids(
    steps: list[dict[str, Any]], index: dict[str, dict[str, Any]]
) -> list[str]:
    return [
        s["finding_id"]
        for s in steps
        if s.get("finding_id") is not None and s["finding_id"] not in index
    ]


def _create_chain_impl(
    name: str,
    steps: list[Any],
    description: str = "",
) -> dict[str, Any]:
    with _chains_lock:
        if not name or not name.strip():
            return {"success": False, "error": "Chain name cannot be empty", "chain_id": None}
        normalized = [n for n in (_normalize_step(s) for s in (steps or [])) if n is not None]
        if not normalized:
            return {
                "success": False,
                "error": "steps must contain at least one finding id or {'note': ...} step",
                "chain_id": None,
            }
        chain_id = _generate_chain_id()
        if chain_id is None:
            return {
                "success": False,
                "error": "Failed to generate a unique chain ID",
                "chain_id": None,
            }
        timestamp = datetime.now(UTC).isoformat()
        _chains_storage[chain_id] = {
            "name": name.strip(),
            "description": description.strip(),
            "steps": normalized,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        _persist()
        unknown = _unknown_finding_ids(normalized, _report_index())
        result: dict[str, Any] = {
            "success": True,
            "chain_id": chain_id,
            "message": f"Attack chain '{name}' created with {len(normalized)} step(s)",
            "total_count": len(_chains_storage),
        }
        if unknown:
            result["warning"] = f"Unknown finding id(s) recorded and flagged: {', '.join(unknown)}"
            result["unknown_finding_ids"] = unknown
        return result


def _add_chain_step_impl(chain_id: str, step: Any) -> dict[str, Any]:
    with _chains_lock:
        chain = _chains_storage.get(chain_id)
        if chain is None:
            return {"success": False, "error": f"Chain with ID '{chain_id}' not found"}
        normalized = _normalize_step(step)
        if normalized is None:
            return {
                "success": False,
                "error": "step must be a finding id or {'note': ...}",
            }
        chain["steps"].append(normalized)
        chain["updated_at"] = datetime.now(UTC).isoformat()
        _persist()
        result: dict[str, Any] = {
            "success": True,
            "chain_id": chain_id,
            "message": f"Step added; chain now has {len(chain['steps'])} step(s)",
        }
        fid = normalized.get("finding_id")
        if fid is not None and fid not in _report_index():
            result["warning"] = f"Unknown finding id recorded and flagged: {fid}"
        return result


def _list_chains_impl() -> dict[str, Any]:
    with _chains_lock:
        index = _report_index()
        chains = [
            {
                "chain_id": cid,
                "name": chain.get("name", ""),
                "description": chain.get("description", ""),
                "created_at": chain.get("created_at", ""),
                "updated_at": chain.get("updated_at", ""),
                "steps": [_resolve_step(s, index) for s in chain.get("steps", [])],
            }
            for cid, chain in _chains_storage.items()
        ]
        chains.sort(key=lambda c: c.get("created_at", ""), reverse=True)
        return {"success": True, "chains": chains, "total_count": len(chains)}


def _delete_chain_impl(chain_id: str) -> dict[str, Any]:
    with _chains_lock:
        chain = _chains_storage.pop(chain_id, None)
        if chain is None:
            return {"success": False, "error": f"Chain with ID '{chain_id}' not found"}
        _persist()
        return {
            "success": True,
            "chain_id": chain_id,
            "message": f"Chain '{chain.get('name', '')}' deleted successfully",
            "total_count": len(_chains_storage),
        }


@function_tool(timeout=30, strict_mode=False)
async def chain_finding(
    name: str,
    steps: list[Any],
    description: str = "",
) -> str:
    """Link filed findings into a named attack chain (bug A unlocks bug B unlocks C).

    A chain models a real attack path and is worth more than the sum of
    its isolated findings. Create one once you can connect two or more
    findings into an ordered exploitation sequence.

    Each entry in ``steps`` is either:

    - a finding id from a filed report (e.g. ``"vuln-0001"``), or
    - ``{"note": "..."}`` for a precondition that isn't itself a filed
      finding (e.g. ``{"note": "attacker has a low-priv account"}``).

    Unknown finding ids are still recorded but flagged in the response and
    in ``list_chains`` output — file the underlying report, then the id
    resolves automatically.

    Args:
        name: Short chain name (e.g. ``"IDOR -> account takeover"``).
        steps: Ordered list of finding ids and/or ``{"note": ...}`` steps.
        description: Optional free-text description of the attack path.
    """
    return json.dumps(
        await asyncio.to_thread(_create_chain_impl, name, steps, description),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_chains() -> str:
    """List all attack chains with their ordered steps.

    Each finding-id step is resolved to its current ``title`` and
    ``severity`` from the filed reports; steps whose id no longer matches
    a report are flagged ``unknown: true``. ``{"note": ...}`` steps are
    returned as-is.
    """
    return json.dumps(
        await asyncio.to_thread(_list_chains_impl),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30, strict_mode=False)
async def add_chain_step(chain_id: str, step: Any) -> str:
    """Append one step to an existing attack chain.

    Args:
        chain_id: Target chain id from ``chain_finding`` / ``list_chains``.
        step: A finding id (str) or ``{"note": "..."}`` precondition.
    """
    return json.dumps(
        await asyncio.to_thread(_add_chain_step_impl, chain_id, step),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def delete_chain(chain_id: str) -> str:
    """Delete an attack chain.

    Args:
        chain_id: Chain id to delete.
    """
    return json.dumps(
        await asyncio.to_thread(_delete_chain_impl, chain_id),
        ensure_ascii=False,
        default=str,
    )
