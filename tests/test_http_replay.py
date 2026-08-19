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


def test_batch_baseline_and_variants_with_diff(monkeypatch: "pytest.MonkeyPatch") -> None:
    # baseline 403 short body; variant for id=2 returns 200 longer body (IDOR signal)
    def fake_request(method: str, url: str, **kwargs: Any) -> Any:
        r = _FakeResponse()
        if url.endswith("/2"):
            r.status_code = 200
            r.text = "leaked data " * 10
        else:
            r.status_code = 403
            r.text = "denied"
        r.url = url
        return r

    monkeypatch.setattr(http_replay_tools.requests, "request", fake_request)

    result = http_replay_tools._batch_impl(
        "GET", "https://x/api/users/1", None, None, 15, False,
        [{"label": "id=2", "url": "https://x/api/users/2"},
         {"label": "id=1-again", "url": "https://x/api/users/1"}],
    )
    assert result["success"] is True
    assert result["baseline"]["status_code"] == 403
    assert result["count"] == 2
    hot = next(v for v in result["variants"] if v["label"] == "id=2")
    assert hot["status_code"] == 200
    assert hot["status_changed"] is True
    assert hot["len_delta"] > 0
    same = next(v for v in result["variants"] if v["label"] == "id=1-again")
    assert same["status_changed"] is False


def test_batch_header_merge_and_cap(monkeypatch: "pytest.MonkeyPatch") -> None:
    seen: list[dict[str, Any]] = []

    def fake_request(method: str, url: str, **kwargs: Any) -> Any:
        seen.append(kwargs.get("headers") or {})
        r = _FakeResponse()
        r.text = "ok"
        r.url = url
        return r

    monkeypatch.setattr(http_replay_tools.requests, "request", fake_request)

    over = [{"headers": {"Authorization": f"Bearer t{i}"}} for i in range(60)]
    result = http_replay_tools._batch_impl(
        "GET", "https://x", {"X-Base": "1"}, None, 15, False, over
    )
    assert result["count"] == http_replay_tools._MAX_VARIANTS  # capped at 50
    assert result["dropped"] == 10
    # base header preserved, variant header merged onto it
    variant_headers = seen[1]  # seen[0] is baseline
    assert variant_headers["X-Base"] == "1"
    assert variant_headers["Authorization"].startswith("Bearer t")
