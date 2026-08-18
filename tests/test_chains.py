"""Attack-chain store: chaining findings, resolving titles, re-hydrate, delete."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

import strix.report.state as report_state_mod
from strix.core.paths import runtime_state_dir
from strix.interface.mcp_server import bootstrap_mcp_run
from strix.tools.chains import tools as chains


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def mcp_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    bootstrap_mcp_run("mcp-test")
    yield
    report_state_mod._global_report_state = None


def _file_report(title: str, severity: str) -> str:
    state = report_state_mod.get_global_report_state()
    assert state is not None
    return state.add_vulnerability_report(title=title, severity=severity, target="example.com")


@pytest.mark.usefixtures("mcp_run")
def test_chain_resolves_titles_and_flags_unknown() -> None:
    a = _file_report("IDOR in /orders", "high")
    b = _file_report("Account takeover", "critical")

    created = chains._create_chain_impl(
        "IDOR -> takeover",
        [a, {"note": "attacker has a low-priv account"}, b, "vuln-9999"],
    )
    assert created["success"] is True
    assert created["unknown_finding_ids"] == ["vuln-9999"]

    listing = chains._list_chains_impl()
    assert listing["total_count"] == 1
    steps = listing["chains"][0]["steps"]

    assert steps[0] == {"finding_id": a, "title": "IDOR in /orders", "severity": "high"}
    assert steps[1] == {"note": "attacker has a low-priv account"}
    assert steps[2]["title"] == "Account takeover"
    assert steps[2]["severity"] == "critical"
    assert steps[3] == {"finding_id": "vuln-9999", "unknown": True}


@pytest.mark.usefixtures("mcp_run")
def test_survives_rehydrate_and_add_step() -> None:
    a = _file_report("SSRF", "medium")
    chain_id = chains._create_chain_impl("SSRF chain", [a])["chain_id"]
    chains._add_chain_step_impl(chain_id, {"note": "pivot to metadata endpoint"})

    state = report_state_mod.get_global_report_state()
    assert state is not None
    state_dir = runtime_state_dir(state.get_run_dir())

    chains._chains_storage.clear()
    chains.hydrate_chains_from_disk(state_dir)

    listing = chains._list_chains_impl()
    assert listing["total_count"] == 1
    assert len(listing["chains"][0]["steps"]) == 2


@pytest.mark.usefixtures("mcp_run")
def test_delete_chain() -> None:
    a = _file_report("XSS", "low")
    chain_id = chains._create_chain_impl("XSS chain", [a])["chain_id"]

    assert chains._delete_chain_impl(chain_id)["success"] is True
    assert chains._list_chains_impl()["total_count"] == 0
    assert chains._delete_chain_impl(chain_id)["success"] is False


@pytest.mark.usefixtures("mcp_run")
def test_tool_wrapper_returns_json() -> None:
    a = _file_report("Open redirect", "low")
    raw = chains._create_chain_impl("wrapper", [a])
    assert json.loads(json.dumps(raw))["success"] is True
