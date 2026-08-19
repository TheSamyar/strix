"""Tests for the shared Caido client lifecycle and proxy call serialization.

Covers the caching + serialization guarantees of ``caido_api.call_with_client``
(the sandbox-imported path) and ``proxy.tools._call`` (the host-side path). The
Caido GraphQL transport is not concurrency-safe, so both paths must run one
call at a time against the shared client.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from strix.tools.proxy import caido_api, tools


if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    caido_api._CLIENT_CACHE.clear()
    yield
    caido_api._CLIENT_CACHE.clear()


async def test_call_with_client_reuses_cached_client(monkeypatch: pytest.MonkeyPatch) -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def _new() -> Any:
        raise AssertionError("_new_client must not run when a client is cached")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is cached


async def test_call_with_client_creates_and_caches_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _FakeClient("fresh")

    async def _new() -> Any:
        return created

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is created
    assert caido_api._CLIENT_CACHE["default"] is created


async def test_failed_init_does_not_poison_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _new() -> Any:
        raise ConnectionRefusedError("caido not up yet")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    async def fn(_client: Any) -> str:
        return "unreachable"

    with pytest.raises(ConnectionRefusedError):
        await caido_api.call_with_client(fn)
    assert "default" not in caido_api._CLIENT_CACHE


async def test_call_with_client_propagates_errors() -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def fn(_client: Any) -> str:
        raise ValueError("Invalid HTTPQL filter")

    with pytest.raises(ValueError, match="Invalid HTTPQL"):
        await caido_api.call_with_client(fn)
    assert caido_api._CLIENT_CACHE["default"] is cached


async def test_call_with_client_serializes_concurrent_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caido_api._CLIENT_CACHE["default"] = cast("Any", _FakeClient("shared"))

    async def _new() -> Any:
        raise AssertionError("no new client expected")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(caido_api.call_with_client(fn) for _ in range(6)))
    assert state["max"] == 1


async def test_host_call_serializes_concurrent_calls() -> None:
    client = _FakeClient("host")
    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(tools._call(cast("Any", client), fn) for _ in range(6)))
    assert state["max"] == 1


def _headers_named(raw: bytes, name: str) -> list[str]:
    head = raw.decode("utf-8").split("\r\n\r\n", 1)[0]
    return [
        line.split(":", 1)[1].strip()
        for line in head.split("\r\n")[1:]
        if line.split(":", 1)[0].strip().lower() == name.lower()
    ]


def test_build_raw_request_recomputes_content_length_for_modified_body() -> None:
    # The captured request declared Content-Length: 12 (original body); the
    # replayed body is longer. The emitted request must carry exactly one
    # Content-Length equal to the ACTUAL body length, or the target truncates
    # the modified payload (or the connection desyncs).
    body = '{"user":"a\' OR 1=1 -- injected long payload"}'
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://example.com/login",
        headers={"content-length": "12", "Content-Type": "application/json"},
        body=body,
    )
    sent_body = raw.decode("utf-8").split("\r\n\r\n", 1)[1]
    assert sent_body == body
    assert _headers_named(raw, "Content-Length") == [str(len(body.encode("utf-8")))]


def test_build_raw_request_drops_transfer_encoding_for_modified_body() -> None:
    body = '{"user":"updated"}'
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://example.com/login",
        headers={
            "tRaNsFeR-EnCoDiNg": "chunked",
            "Content-Length": "7",
            "Content-Type": "application/json",
        },
        body=body,
    )
    assert _headers_named(raw, "Transfer-Encoding") == []
    assert _headers_named(raw, "Content-Length") == [str(len(body.encode("utf-8")))]


def test_build_raw_request_drops_stale_content_length_for_empty_body() -> None:
    # A body cleared to empty must not keep the inherited (non-zero) length.
    _conn, raw = caido_api.build_raw_request(
        method="POST",
        url="https://example.com/x",
        headers={"Content-Length": "12"},
        body="",
    )
    assert _headers_named(raw, "Content-Length") == []


class _Ctx:
    def __init__(self, context: Any) -> None:
        self.context = context


@pytest.mark.asyncio
async def test_ctx_client_returns_client_when_present() -> None:
    client = _FakeClient("host")
    got = await tools._ctx_client(cast("Any", _Ctx({"caido_client": client})))
    assert got is client


@pytest.mark.asyncio
async def test_ctx_client_falls_back_to_shared_client(monkeypatch: pytest.MonkeyPatch) -> None:
    # No client on the context → fall back to the shared self-connecting client.
    shared = _FakeClient("shared")

    async def _fake_get_client() -> Any:
        return shared

    monkeypatch.setattr(caido_api, "get_client", _fake_get_client)
    got = await tools._ctx_client(cast("Any", _Ctx({})))
    assert got is shared


@pytest.mark.asyncio
async def test_ctx_client_returns_none_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom() -> Any:
        raise ConnectionError("no caido")

    monkeypatch.setattr(caido_api, "get_client", _boom)
    assert await tools._ctx_client(cast("Any", _Ctx({}))) is None
    assert await tools._ctx_client(cast("Any", _Ctx(None))) is None


def test_repeat_variant_summary_diffs_against_baseline() -> None:
    """repeat_request batch mode: each variant summary is diffed vs baseline."""
    from strix.tools.proxy import caido_api
    from strix.tools.proxy import tools as proxy_tools

    base_raw = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\ndenied"
    base_resp = caido_api.parse_raw_response(base_raw)

    idor = {
        "status": "DONE",
        "elapsed_ms": 12,
        "response_raw": b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"leaked" * 20,
    }
    hot = proxy_tools._summarize_repeat_variant("id=2", idor, base_resp)
    assert hot["status_code"] == 200
    assert hot["status_changed"] is True
    assert hot["len_delta"] > 0

    same = proxy_tools._summarize_repeat_variant(
        "id=1", {"status": "DONE", "elapsed_ms": 9, "response_raw": base_raw}, base_resp
    )
    assert same["status_changed"] is False
    assert same["len_delta"] == 0

    missing = proxy_tools._summarize_repeat_variant("x", None, base_resp)
    assert missing["success"] is False


async def test_list_requests_inlines_bodies_when_requested(
    monkeypatch: "pytest.MonkeyPatch",
) -> None:
    """include_bodies>0 inlines truncated request/response previews for the top N."""
    import datetime as _dt
    import json as _json
    from types import SimpleNamespace as NS

    from agents.tool_context import ToolContext

    from strix.tools.proxy import caido_api
    from strix.tools.proxy import tools as proxy_tools

    now = _dt.datetime(2024, 1, 1, tzinfo=_dt.timezone.utc)

    def _edge(rid: str) -> NS:
        req = NS(
            id=rid, host="x", port=443, method="GET", path=f"/api/{rid}",
            query="", is_tls=True, created_at=now,
        )
        resp = NS(id=f"r{rid}", status_code=200, length=5, created_at=now, roundtrip_time=0)
        return NS(cursor=f"c{rid}", node=NS(request=req, response=resp))

    connection = NS(
        edges=[_edge("1"), _edge("2"), _edge("3")],
        page_info=NS(
            has_next_page=False, has_previous_page=False,
            start_cursor="c1", end_cursor="c3",
        ),
    )

    async def _fake_call(_client: object, fn: object) -> object:
        return await fn(_client)  # type: ignore[operator]

    def _fake_list(_client: object, **_kw: object) -> object:
        async def _inner() -> object:
            return connection
        return _inner()

    big = b"HTTP body " * 500  # > 2k cap
    def _fake_get(_client: object, request_id: str, part: str = "request") -> object:
        async def _inner() -> object:
            return NS(request=NS(raw=b"GET /api/" + request_id.encode()), response=NS(raw=big))
        return _inner()

    async def _fake_ctx_client(_ctx: object) -> str:
        return "client"

    monkeypatch.setattr(proxy_tools, "_ctx_client", _fake_ctx_client)
    monkeypatch.setattr(proxy_tools, "_call", _fake_call)
    monkeypatch.setattr(caido_api, "list_requests_with_client", _fake_list)
    monkeypatch.setattr(caido_api, "get_request_with_client", _fake_get)

    args = _json.dumps({"include_bodies": 2})
    ctx = ToolContext(
        context={"agent_id": "mcp"}, tool_name="list_requests",
        tool_call_id="t", tool_arguments=args,
    )
    raw = await proxy_tools.list_requests.on_invoke_tool(ctx, args)
    out = _json.loads(raw)
    assert out["success"] is True
    entries = out["entries"]
    # first 2 have previews, truncated to cap; 3rd does not
    assert entries[0]["request_preview"].startswith("GET /api/1")
    assert len(entries[0]["response_preview"]) == proxy_tools._LIST_BODY_PREVIEW_CAP
    assert "request_preview" in entries[1]
    assert "request_preview" not in entries[2]
    assert "response_preview" not in entries[2]
