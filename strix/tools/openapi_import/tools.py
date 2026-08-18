"""Parse an OpenAPI/Swagger spec and populate the attack-surface store.

Recon shortcut: instead of hand-recording every endpoint, feed the target's
OpenAPI 3.x or Swagger 2.0 document here and each path x method lands in the
attack-surface map (with its params and inferred auth) via the existing
``record_endpoint`` path.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import yaml
from agents import RunContextWrapper, function_tool

from strix.tools.attack_surface.tools import _record_endpoint_impl


logger = logging.getLogger(__name__)

_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


def _load_spec(text: str) -> dict[str, Any]:
    """Parse spec text: JSON first, then YAML (pyyaml is a dependency)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    loaded = yaml.safe_load(text)
    if not isinstance(loaded, dict):
        raise ValueError("spec did not parse to a mapping")  # noqa: TRY004
    return loaded


def _body_param_names(schema: dict[str, Any]) -> list[str]:
    props = schema.get("properties")
    return list(props) if isinstance(props, dict) else []


def _operation_params(
    path_params: list[dict[str, Any]],
    operation: dict[str, Any],
) -> list[str]:
    """Collect param names: path/query/header/body across OpenAPI 3 + Swagger 2."""
    names: list[str] = []
    op_params = operation.get("parameters")
    for param in [*path_params, *(op_params if isinstance(op_params, list) else [])]:
        if not isinstance(param, dict):
            continue
        # Swagger 2.0 body parameter carries a schema instead of a name.
        if param.get("in") == "body" and isinstance(param.get("schema"), dict):
            names.extend(_body_param_names(param["schema"]))
        elif isinstance(param.get("name"), str):
            names.append(param["name"])
    # OpenAPI 3.x request body.
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    names.extend(_body_param_names(media["schema"]))
    # Dedup, preserve order.
    return list(dict.fromkeys(names))


def _auth_required(operation: dict[str, Any], global_security: Any) -> bool:
    """A non-empty ``security`` (operation overrides global) means auth is required.

    An operation-level ``security: []`` explicitly opts out even if a global
    requirement exists.
    """
    security = operation.get("security", global_security)
    return isinstance(security, list) and len(security) > 0


def _import_openapi_impl(
    spec: str | None = None,
    spec_path: str | None = None,
) -> dict[str, Any]:
    if spec_path:  # spec_path takes precedence when both are given
        try:
            spec = Path(spec_path).read_text(encoding="utf-8")
        except OSError as e:
            return {"success": False, "error": f"could not read spec_path: {e}"}
    if not spec or not spec.strip():
        return {"success": False, "error": "provide spec (JSON/YAML text) or spec_path"}

    try:
        doc = _load_spec(spec)
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"failed to parse spec (JSON or YAML): {e}"}

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return {"success": False, "error": "spec has no 'paths' object"}

    global_security = doc.get("security")
    imported: list[tuple[str, str]] = []
    warnings: list[str] = []

    for path, item in paths.items():
        if not isinstance(item, dict):
            warnings.append(f"skipped non-object path: {path!r}")
            continue
        shared = item.get("parameters")
        shared_params = shared if isinstance(shared, list) else []
        for method in _HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            params = _operation_params(shared_params, operation)
            result = _record_endpoint_impl(
                path=str(path),
                method=method,
                params=params,
                auth_required=_auth_required(operation, global_security),
                notes="imported from OpenAPI spec",
            )
            if result.get("success"):
                imported.append((method.upper(), str(path)))
            else:
                warnings.append(f"{method.upper()} {path}: {result.get('error')}")

    return {
        "success": True,
        "imported_count": len(imported),
        "endpoints": [{"method": m, "path": p} for m, p in imported],
        "warnings": warnings,
    }


@function_tool(timeout=30)
async def import_openapi(
    ctx: RunContextWrapper,
    spec: str | None = None,
    spec_path: str | None = None,
) -> str:
    """Import an OpenAPI 3.x / Swagger 2.0 spec into the attack-surface map.

    Every path x method becomes an endpoint (via ``record_endpoint``) with its
    path/query/header/body param names and ``auth_required`` inferred from the
    operation's ``security`` (falling back to the global ``security``). Both
    JSON and YAML specs are accepted. After importing, drive testing off
    ``list_attack_surface`` / ``auth_matrix`` as usual.

    Args:
        spec: Raw OpenAPI/Swagger content, JSON or YAML.
        spec_path: Local path to a spec file. Takes precedence over ``spec``
            when both are provided.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_import_openapi_impl, spec, spec_path),
        ensure_ascii=False,
        default=str,
    )
