"""Per-run credential store — mirrored to {state_dir}/credentials.json (0o600).

Local, operator-owned store for the authorized-test accounts the operator
supplies for a run. It lives under the run directory so those test logins are
referenced by label (see the auth/role matrix in ``attack_surface``) instead of
being re-pasted into every tool call and copied into reports. Stored values are
never logged and are never returned by ``list_credentials``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agents import function_tool

from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


_credentials_storage: dict[str, dict[str, Any]] = {}
_credentials_lock = threading.RLock()
_credentials_path: Path | None = None


def hydrate_credentials_from_disk(state_dir: Path) -> None:
    global _credentials_path  # noqa: PLW0603
    _credentials_path = state_dir / "credentials.json"
    with _credentials_lock:
        _credentials_storage.clear()
        if not _credentials_path.exists():
            return
        try:
            data = json.loads(_credentials_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "credentials.json at %s is unreadable; starting empty",
                _credentials_path,
            )
            return
        if not isinstance(data, dict):
            return
        _credentials_storage.update(
            {
                label: entry
                for label, entry in data.items()
                if isinstance(label, str) and isinstance(entry, dict)
            }
        )
        logger.info(
            "credentials hydrated from %s (%d label(s))",
            _credentials_path,
            len(_credentials_storage),
        )


def _persist() -> None:
    path = _credentials_path
    if path is None:
        return
    try:
        # write_secret_text does the atomic tmp-file write + chmod 0o600.
        write_secret_text(path, json.dumps(_credentials_storage, ensure_ascii=False, default=str))
    except Exception:
        logger.exception("credentials persist to %s failed", path)


def _store_credential_impl(label: str, value: str, note: str = "") -> dict[str, Any]:
    with _credentials_lock:
        if not label or not label.strip():
            return {"success": False, "error": "Label cannot be empty"}
        if not value:
            return {"success": False, "error": "Value cannot be empty"}
        label = label.strip()
        existed = label in _credentials_storage
        _credentials_storage[label] = {
            "value": value,
            "note": note,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        _persist()
        return {
            "success": True,
            "label": label,
            "message": f"Credential '{label}' {'updated' if existed else 'stored'}",
            "total_count": len(_credentials_storage),
        }


def _list_credentials_impl() -> dict[str, Any]:
    with _credentials_lock:
        credentials = [
            {
                "label": label,
                "note": entry.get("note", ""),
                "updated_at": entry.get("updated_at", ""),
            }
            for label, entry in _credentials_storage.items()
        ]
    credentials.sort(key=lambda c: c["label"])
    return {"success": True, "credentials": credentials, "total_count": len(credentials)}


def _get_credential_impl(label: str) -> dict[str, Any]:
    with _credentials_lock:
        entry = _credentials_storage.get(label.strip() if label else label)
        if entry is None:
            return {"success": False, "error": f"Credential '{label}' not found", "value": None}
        return {"success": True, "label": label.strip(), "value": entry.get("value")}


def _delete_credential_impl(label: str) -> dict[str, Any]:
    with _credentials_lock:
        key = label.strip() if label else label
        if key not in _credentials_storage:
            return {"success": False, "error": f"Credential '{label}' not found"}
        del _credentials_storage[key]
        _persist()
        return {
            "success": True,
            "label": key,
            "message": f"Credential '{key}' deleted",
            "total_count": len(_credentials_storage),
        }


@function_tool(timeout=30)
async def store_credential(label: str, value: str, note: str = "") -> str:
    """Save one of the operator's own authorized-test-account logins under a label.

    This is a LOCAL store for the operator's own test accounts, kept in the run
    directory (``{run}/credentials.json``, 0o600). It exists so test logins are
    referenced by label — e.g. from the auth/role matrix — instead of being
    re-pasted into every tool call or copied into reports. Upserts on label.

    Args:
        label: Short handle for this login (e.g. ``"admin"``, ``"low-priv"``).
        value: The secret to store (password, token, cookie, or full credential).
        note: Optional non-secret note (e.g. ``"role=admin, MFA disabled"``).
    """
    return json.dumps(
        await asyncio.to_thread(_store_credential_impl, label, value, note),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_credentials() -> str:
    """List stored credential labels and notes only — never the stored values.

    Local store of the operator's own authorized-test accounts, kept in the run
    directory. Use ``get_credential`` to retrieve a value when a test needs it.
    """
    return json.dumps(
        await asyncio.to_thread(_list_credentials_impl), ensure_ascii=False, default=str
    )


@function_tool(timeout=30)
async def get_credential(label: str) -> str:
    """Return the stored value for a label, to authenticate during a test.

    Reads from the local run-directory store of the operator's own
    authorized-test accounts.

    Args:
        label: Label the credential was stored under.
    """
    return json.dumps(
        await asyncio.to_thread(_get_credential_impl, label), ensure_ascii=False, default=str
    )


@function_tool(timeout=30)
async def delete_credential(label: str) -> str:
    """Delete a stored credential from the local run-directory store.

    Args:
        label: Label to delete.
    """
    return json.dumps(
        await asyncio.to_thread(_delete_credential_impl, label), ensure_ascii=False, default=str
    )
