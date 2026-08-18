"""http_replay tool: replays a raw request via requests, no real network."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import requests
from agents.tool_context import ToolContext

from strix.tools.http_replay import tools as http_replay_tools


if TYPE_CHECKING:
    import pytest


class _FakeResponse:
    def __init__(self) -> None:
        self.status_code = 200
        self.headers = {"Content-Type": "text/plain"}
        self.text = "x" * (http_replay_tools._BODY_CAP_CHARS + 50)
        self.url = "https://example.com/final"


def test_replay_truncates_and_returns_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_request(method: str, url: str, **kwargs: Any) -> _FakeResponse:
        captured["method"] = method
        captured["url"] = url
        captured["kwargs"] = kwargs
        return _FakeResponse()

    monkeypatch.setattr(http_replay_tools.requests, "request", fake_request)

    result = http_replay_tools._replay_impl(
        "get", "https://example.com", {"X-Test": "1"}, "hi", 15, allow_redirects=False
    )

    assert captured["method"] == "GET"
    assert captured["kwargs"]["allow_redirects"] is False
    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["truncated"] is True
    assert len(result["body"]) == http_replay_tools._BODY_CAP_CHARS
    assert result["final_url"] == "https://example.com/final"


def test_replay_error_is_structured(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise requests.ConnectTimeout("timed out")

    monkeypatch.setattr(http_replay_tools.requests, "request", boom)

    result = http_replay_tools._replay_impl(
        "GET", "https://example.com", None, None, 1, allow_redirects=False
    )
    assert result["success"] is False
    assert "ConnectTimeout" in result["error"]


async def test_tool_wrapper_returns_json(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(*_args: Any, **_kwargs: Any) -> _FakeResponse:
        return _FakeResponse()

    monkeypatch.setattr(http_replay_tools.requests, "request", fake_request)
    args = json.dumps({"method": "GET", "url": "https://example.com"})
    ctx = ToolContext(
        context={"agent_id": "mcp"},
        tool_name="http_replay",
        tool_call_id="test",
        tool_arguments=args,
    )
    raw = await http_replay_tools.http_replay.on_invoke_tool(ctx, args)
    assert json.loads(raw)["status_code"] == 200
