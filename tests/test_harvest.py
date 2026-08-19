"""Deterministic domain harvest: expand, ingest, walk, coverage gate."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

import strix.report.state as report_state_mod
from strix.audit import (
    CONCRETE_SITE_PROFILES,
    SITE_PROFILES,
    FetchResult,
    JobResult,
    audit_exit_code,
    detect_site_profile,
    jobs_for_mode,
    jobs_for_profiles,
)
from strix.harvest import (
    HostRecord,
    WalkResult,
    classify_response,
    expand_hosts,
    expand_tool_catalog,
    extract_linked_hosts,
    file_harvest_findings,
    group_leak_candidates,
    ingest_openapi,
    persist_hosts,
    registrable_domain,
    related_apex_www,
    run_harvest,
    targets_from_hosts,
    walk_unauth,
    write_walk_jsonl,
)
from strix.interface.mcp_server import bootstrap_mcp_run, mcp_tool_descriptors
from strix.tools.attack_surface import tools as attack_surface
from strix.tools.coverage.tools import _do_coverage_report


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def as_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.chdir(tmp_path)
    report_state_mod._global_report_state = None
    bootstrap_mcp_run("mcp-test")
    yield tmp_path
    report_state_mod._global_report_state = None


def test_extract_linked_hosts_keeps_same_reg_and_linked_siblings() -> None:
    html = (
        '<a href="https://mcp.adspirer.com/mcp">mcp</a>'
        '<a href="https://adspirer.ai/sign-in">auth</a>'
        '<a href="https://www.google.com">out</a>'
    )
    hosts = extract_linked_hosts(html, "www.adspirer.com")
    assert "mcp.adspirer.com" in hosts
    assert "adspirer.ai" in hosts
    assert "www.google.com" not in hosts


def test_related_apex_www() -> None:
    assert related_apex_www("www.adspirer.com") == {"www.adspirer.com", "adspirer.com"}
    assert related_apex_www("adspirer.com") == {"adspirer.com", "www.adspirer.com"}


def test_expand_hosts_from_html_and_san(tmp_path: Path) -> None:
    pages = {
        "https://www.example.com/": FetchResult(
            url="https://www.example.com/",
            status=200,
            headers={"server": "Vercel"},
            body='<a href="https://mcp.example.com/docs">mcp</a>'
            '<a href="https://example.ai/sign-in">ai</a>',
        ),
        "https://example.com/": FetchResult(
            url="https://example.com/",
            status=308,
            headers={"location": "https://www.example.com/"},
            body="",
        ),
        "https://mcp.example.com/": FetchResult(
            url="https://mcp.example.com/",
            status=200,
            headers={"server": "uvicorn"},
            body='{"name":"mcp"}',
        ),
        "https://example.ai/": FetchResult(
            url="https://example.ai/",
            status=200,
            headers={},
            body="ok",
        ),
        "https://jenkins.example.ai/": FetchResult(
            url="https://jenkins.example.ai/",
            status=200,
            headers={"x-jenkins": "2.528.1"},
            body="Sign in - Jenkins",
        ),
    }

    def fetch2(url: str, _headers: dict[str, str] | None = None) -> FetchResult:
        key = url if url.endswith("/") else url + "/"
        if key in pages:
            return pages[key]
        return FetchResult(url=url, status=0, headers={}, body="")

    hosts = expand_hosts(
        ["https://www.example.com/"],
        fetch=fetch2,
        sans_for=lambda host: (
            ["jenkins.example.ai", "example.ai"] if host.endswith("example.ai") else []
        ),
        crt_names_for=lambda _reg: [],
    )
    names = {h.hostname for h in hosts}
    assert "mcp.example.com" in names
    assert "example.ai" in names
    assert "jenkins.example.ai" in names
    persist_hosts(tmp_path / "hosts.json", hosts)
    saved = json.loads((tmp_path / "hosts.json").read_text(encoding="utf-8"))
    assert any(item["hostname"] == "mcp.example.com" for item in saved["hosts"])


@pytest.mark.usefixtures("as_run")
def test_openapi_and_tool_catalog_expand_adspirer_shape() -> None:
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/mcp/test/check-schema": {"get": {}},
            "/api/v1/tools/{tool_name}/execute": {"post": {}},
        },
    }
    imported = ingest_openapi(json.dumps(spec))
    assert imported["success"] is True
    added = expand_tool_catalog(["start_here", "audit_account", "list_campaigns"])
    assert added == 3
    surface = attack_surface._list_attack_surface_impl()
    ids = {e["endpoint_id"] for e in surface["endpoints"]}
    assert "GET /mcp/test/check-schema" in ids
    assert "POST /api/v1/tools/start_here/execute" in ids
    assert "POST /api/v1/tools/audit_account/execute" in ids
    assert "POST /api/v1/tools/list_campaigns/execute" in ids


def test_classify_200_schema_is_leak_401_is_enforced() -> None:
    kind, _reason = classify_response(200, '{"oauth_authorization_codes":{"columns":[]}}')
    assert kind == "leak_candidate"
    kind, _reason = classify_response(401, '{"detail":"Unauthorized"}')
    assert kind == "auth_enforced"
    kind, _reason = classify_response(
        500, 'Traceback (most recent call last):\n  File "/app/server.py"'
    )
    assert kind == "leak_candidate"
    kind, _reason = classify_response(404, "not found")
    assert kind == "skip"


@pytest.mark.usefixtures("as_run")
def test_walker_records_jsonl_and_skips_401(tmp_path: Path) -> None:
    ingest_openapi(
        json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {
                    "/mcp/test/check-schema": {"get": {}},
                    "/mcp": {"get": {}},
                },
            }
        )
    )
    expand_tool_catalog(["start_here"])

    def request(_method: str, url: str) -> tuple[int, str]:
        if url.endswith("/check-schema"):
            return 200, '{"tables":["oauth_authorization_codes"]}'
        if url.endswith("/mcp"):
            return 401, '{"detail":"Unauthorized"}'
        if url.endswith("/execute"):
            return 200, '{"success":true,"data":{"text":"Please connect your Adspirer account"}}'
        return 404, ""

    results = walk_unauth(
        attack_surface._list_attack_surface_impl()["endpoints"],
        base_url="https://mcp.example.com",
        request=request,
        walk_path=tmp_path / "walk.jsonl",
    )
    by_id = {r.endpoint_id: r for r in results}
    assert by_id["GET /mcp/test/check-schema"].classification == "leak_candidate"
    assert by_id["GET /mcp"].classification == "auth_enforced"
    lines = (tmp_path / "walk.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3


def test_group_identical_tool_executes() -> None:
    same = "Please connect your account first"
    rows = [
        WalkResult(
            "POST /api/v1/tools/a/execute",
            "POST",
            "https://x/api/v1/tools/a/execute",
            200,
            "leak_candidate",
            "unauth_2xx",
            same,
        ),
        WalkResult(
            "POST /api/v1/tools/b/execute",
            "POST",
            "https://x/api/v1/tools/b/execute",
            200,
            "leak_candidate",
            "unauth_2xx",
            same,
        ),
        WalkResult(
            "GET /schema",
            "GET",
            "https://x/schema",
            200,
            "leak_candidate",
            "unauth_data",
            '{"clerk_jwt":true}',
        ),
    ]
    grouped = group_leak_candidates(rows)
    assert len(grouped) == 2
    counts = {g["endpoint_id"]: g.get("count", 1) for g in grouped}
    assert 2 in counts.values()


def test_harvest_findings_keep_full_body(tmp_path: Path) -> None:
    body = "leaked-secret=" + ("A" * 3000)
    groups = [
        {
            "endpoint_id": "GET /export",
            "method": "GET",
            "url": "https://x/export",
            "status": 200,
            "reason": "unauth_data",
            "body_preview": body,
            "count": 1,
        }
    ]
    reports = file_harvest_findings(tmp_path / "strix_runs" / "mcp-test", groups)
    assert reports[0]["evidence"] == body


@pytest.mark.usefixtures("as_run")
def test_coverage_incomplete_when_endpoint_unwalked(tmp_path: Path) -> None:
    ingest_openapi(json.dumps({"openapi": "3.0.0", "paths": {"/secret": {"get": {}}}}))
    report = _do_coverage_report()
    assert report["walk"]["incomplete"] is True
    assert "GET /secret" in report["walk"]["unwalked_endpoints"]

    write_walk_jsonl(
        tmp_path / "strix_runs" / "mcp-test" / "walk.jsonl",
        [
            {
                "endpoint_id": "GET /secret",
                "classification": "auth_enforced",
                "status": 401,
            }
        ],
    )
    report = _do_coverage_report()
    assert report["walk"]["incomplete"] is False


def test_audit_exit_incomplete_walk_is_nonzero() -> None:
    ok = JobResult("recon", 0, timed_out=False)
    assert audit_exit_code([ok], 0) == 0
    assert audit_exit_code([ok], 0, walk_incomplete=True) == 1
    assert audit_exit_code([ok], 2, walk_incomplete=True) == 2


def test_fastapi_jobs_start_with_harvest() -> None:
    jobs = jobs_for_mode("quick", site_profile="fastapi")
    assert jobs[0].id == "harvest"
    assert jobs[1].id == "fastapi_auth"
    assert "fastapi" in jobs[1].skills
    assert "oauth" in jobs[1].skills
    assert [j.id for j in jobs[2:6]] == ["recon", "auth", "injection", "access"]


def test_jobs_for_profiles_mixed_nextjs_and_fastapi() -> None:
    jobs = jobs_for_profiles("quick", ("nextjs", "fastapi"))
    ids = [j.id for j in jobs]
    assert ids[0] == "harvest"
    assert "fastapi_auth" in ids
    assert "nextjs_recon" in ids
    assert ids.count("harvest") == 1


def test_auto_detects_fastapi_from_uvicorn_and_openapi() -> None:
    def fetcher(url: str, _headers: dict[str, str]) -> FetchResult:
        if url.endswith("/openapi.json"):
            return FetchResult(
                url=url,
                status=200,
                headers={"content-type": "application/json"},
                body='{"openapi":"3.1.0","info":{"title":"adspirer-mcp"}}',
            )
        return FetchResult(
            url=url,
            status=200,
            headers={"server": "uvicorn"},
            body='{"mcp_url":"/mcp"}',
        )

    detected = detect_site_profile(["https://mcp.test"], "auto", fetcher=fetcher)
    assert detected.resolved == "fastapi"


def test_site_profiles_include_fastapi() -> None:
    assert "fastapi" in SITE_PROFILES
    assert "fastapi" in CONCRETE_SITE_PROFILES


def test_targets_from_hosts_appends_live_urls() -> None:
    existing = [
        {
            "type": "web_application",
            "details": {"target_url": "https://www.example.com"},
            "original": "https://www.example.com",
        }
    ]
    hosts = [
        HostRecord(
            url="https://www.example.com/",
            hostname="www.example.com",
            live=True,
            status=200,
            server="Vercel",
            fingerprints=("nextjs",),
            source="seed",
            probed=True,
        ),
        HostRecord(
            url="https://mcp.example.com/",
            hostname="mcp.example.com",
            live=True,
            status=200,
            server="uvicorn",
            fingerprints=("fastapi",),
            source="html",
            probed=True,
        ),
        HostRecord(
            url="https://dead.example.com/",
            hostname="dead.example.com",
            live=False,
            status=None,
            server=None,
            fingerprints=(),
            source="crt",
            probed=True,
        ),
    ]
    out = targets_from_hosts(hosts, existing)
    urls = [item["details"]["target_url"] for item in out]
    assert "https://mcp.example.com/" in urls
    assert "https://dead.example.com/" not in urls


@pytest.mark.usefixtures("as_run")
def test_run_harvest_writes_artifacts(tmp_path: Path) -> None:
    spec = json.dumps({"openapi": "3.0.0", "paths": {"/health": {"get": {}}}})

    def fetch(url: str, _headers: dict[str, str] | None = None) -> FetchResult:
        if url.rstrip("/").endswith("/openapi.json"):
            return FetchResult(url=url, status=200, headers={}, body=spec)
        if "example.com" in url:
            return FetchResult(
                url=url,
                status=200,
                headers={"server": "uvicorn"},
                body='{"openapi":"hint"} <a href="https://mcp.example.com/">x</a>',
            )
        return FetchResult(url=url, status=0, headers={}, body="")

    def request(_method: str, url: str) -> tuple[int, str]:
        if url.endswith("/health"):
            return 200, '{"status":"ok"}'
        return 404, ""

    parent = tmp_path / "strix_runs" / "mcp-test"
    result = run_harvest(
        ["https://www.example.com/"],
        parent,
        fetch=fetch,
        request=request,
        sans_for=lambda _h: [],
        crt_names_for=lambda _r: [],
    )
    assert (parent / "hosts.json").is_file()
    assert (parent / "walk.jsonl").is_file()
    assert result.walked >= 1
    assert (parent / "workers" / "harvest" / "vulnerabilities.json").is_file()


def test_mcp_lists_discover_and_walk() -> None:
    names = {tool["name"] for tool in mcp_tool_descriptors()}
    assert "discover_assets" in names
    assert "walk_unauth" in names
    assert "check_tools" in names
    for tool in mcp_tool_descriptors():
        assert len(tool["description"]) <= 400


def test_registrable_domain() -> None:
    assert registrable_domain("www.adspirer.com") == "adspirer.com"
    assert registrable_domain("mcp.adspirer.com") == "adspirer.com"
    assert registrable_domain("adspirer.ai") == "adspirer.ai"
