"""Attack-surface map + auth/role matrix MCP tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

import strix.report.state as report_state_mod
from strix.core.paths import runtime_state_dir
from strix.interface.mcp_server import bootstrap_mcp_run
from strix.tools.attack_surface import tools as attack_surface


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


@pytest.mark.usefixtures("as_run")
async def test_record_and_list_dedups_on_method_path() -> None:
    await _call(attack_surface.record_endpoint, path="/api/users/{id}", method="get", params=["id"])
    await _call(attack_surface.record_endpoint, path="/login", method="POST")
    dupe = await _call(attack_surface.record_endpoint, path="/login", method="post", notes="again")
    assert dupe["updated"] is True

    surface = await _call(attack_surface.list_attack_surface)
    assert surface["total_count"] == 2
    ids = {e["endpoint_id"] for e in surface["endpoints"]}
    assert ids == {"GET /api/users/{id}", "POST /login"}


@pytest.mark.usefixtures("as_run")
async def test_matrix_crosses_roles_and_endpoints_and_marks_cells() -> None:
    await _call(attack_surface.record_endpoint, path="/a", method="GET")
    await _call(attack_surface.record_endpoint, path="/b", method="GET")
    await _call(attack_surface.record_role, name="admin", credentials_ref="admin-ref")
    await _call(attack_surface.record_role, name="user", credentials_ref="user-ref")

    matrix = await _call(attack_surface.auth_matrix)
    assert matrix["count"] == 4
    assert all(cell["result"] == "untested" for cell in matrix["cells"])

    marked = await _call(
        attack_surface.mark_matrix_cell, role="admin", endpoint="GET /a", result="vuln"
    )
    assert marked["success"] is True

    assert (
        await _call(attack_surface.mark_matrix_cell, role="admin", endpoint="GET /a", result="nope")
    )["success"] is False
    assert (
        await _call(attack_surface.mark_matrix_cell, role="ghost", endpoint="GET /a", result="vuln")
    )["success"] is False

    updated = await _call(attack_surface.auth_matrix)
    cell = next(c for c in updated["cells"] if c["role"] == "admin" and c["endpoint"] == "GET /a")
    assert cell["result"] == "vuln"


@pytest.mark.usefixtures("as_run")
async def test_credentials_ref_never_stores_secret_inline() -> None:
    await _call(attack_surface.record_role, name="admin", credentials_ref="env:ADMIN_TOKEN")
    # The stored value is exactly the reference the client passed — a pointer,
    # not a resolved secret.
    assert attack_surface._store["roles"]["admin"]["credentials_ref"] == "env:ADMIN_TOKEN"


async def test_survives_rehydrate(as_run: Path) -> None:
    await _call(attack_surface.record_endpoint, path="/a", method="GET")
    await _call(attack_surface.record_role, name="admin", credentials_ref="ref")
    await _call(attack_surface.mark_matrix_cell, role="admin", endpoint="GET /a", result="vuln")

    state_dir = runtime_state_dir(as_run / "strix_runs" / "mcp-test")
    assert (state_dir / "attack_surface.json").is_file()

    # Simulate a restart: drop in-memory state, reload from disk.
    attack_surface.hydrate_attack_surface_from_disk(state_dir)

    surface = await _call(attack_surface.list_attack_surface)
    assert surface["total_count"] == 1
    matrix = await _call(attack_surface.auth_matrix)
    assert matrix["cells"][0]["result"] == "vuln"
