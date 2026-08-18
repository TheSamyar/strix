"""import_openapi: parse a spec into the attack-surface store."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

import strix.report.state as report_state_mod
from strix.interface.mcp_server import bootstrap_mcp_run
from strix.tools.attack_surface import tools as attack_surface
from strix.tools.openapi_import import tools as openapi_import


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from agents.tool import FunctionTool


@pytest.fixture
def as_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    bootstrap_mcp_run("mcp-test")
    yield tmp_path
    report_state_mod._global_report_state = None


async def _call(tool: FunctionTool, **kwargs: Any) -> dict[str, Any]:
    raw = json.dumps(kwargs)
    ctx = ToolContext(
        context={"agent_id": "mcp"},
        tool_name=tool.name,
        tool_call_id="t",
        tool_arguments=raw,
    )
    return json.loads(await tool.on_invoke_tool(ctx, raw))


_SPEC = {
    "openapi": "3.0.0",
    "security": [{"apiKey": []}],  # global default: auth required
    "paths": {
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path"},
                    {"name": "verbose", "in": "query"},
                ]
            }
        },
        "/login": {
            "post": {
                "security": [],  # explicit opt-out of the global requirement
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"properties": {"username": {}, "password": {}}}
                        }
                    }
                },
            }
        },
    },
}


@pytest.mark.usefixtures("as_run")
async def test_imports_endpoints_with_params_and_auth() -> None:
    result = await _call(openapi_import.import_openapi, spec=json.dumps(_SPEC))
    assert result["success"] is True
    assert result["imported_count"] == 2

    surface = await _call(attack_surface.list_attack_surface)
    by_id = {e["endpoint_id"]: e for e in surface["endpoints"]}
    assert set(by_id) == {"GET /users/{id}", "POST /login"}

    get_users = by_id["GET /users/{id}"]
    assert get_users["auth_required"] is True  # inherits global security
    assert set(get_users["params"]) == {"id", "verbose"}

    login = by_id["POST /login"]
    assert login["auth_required"] is False  # security: [] overrides global
    assert set(login["params"]) == {"username", "password"}


@pytest.mark.usefixtures("as_run")
async def test_yaml_and_bad_input() -> None:
    yaml_spec = (
        "openapi: 3.0.0\n"
        "paths:\n"
        "  /ping:\n"
        "    get: {}\n"
    )
    result = await _call(openapi_import.import_openapi, spec=yaml_spec)
    assert result["imported_count"] == 1
    assert result["endpoints"][0] == {"method": "GET", "path": "/ping"}

    empty = await _call(openapi_import.import_openapi)
    assert empty["success"] is False
