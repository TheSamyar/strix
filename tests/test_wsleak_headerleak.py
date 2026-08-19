"""header_leak (mocked) and ws_leak frame helpers + scheme guard."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from strix.tools.header_leak import tools as hl
from strix.tools.header_leak.tools import _header_leak_impl
from strix.tools.ws_leak import tools as wl


def _resp(headers: dict[str, str]) -> dict[str, Any]:
    return {"success": True, "status_code": 200, "body": "", "response_headers": headers}


# ---- header_leak ---------------------------------------------------------


def test_header_leak_version_and_debug(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hl,
        "_replay_impl",
        lambda *a, **k: _resp({"Server": "nginx/1.18.0", "X-Runtime": "0.03", "X-User-Id": "42"}),
    )
    out = _header_leak_impl("https://x/", 10)
    leaks = {f["leak"] for f in out["findings"]}
    assert "software version" in leaks
    assert "per-user identifier" in leaks
    assert out["possible_header_leak"] is True


def test_header_leak_jwt_pii(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = (
        base64.urlsafe_b64encode(json.dumps({"email": "v@x.com", "sub": "1"}).encode())
        .rstrip(b"=")
        .decode()
    )
    jwt = f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"
    monkeypatch.setattr(
        hl, "_replay_impl", lambda *a, **k: _resp({"Set-Cookie": f"t={jwt}; Path=/"})
    )
    out = _header_leak_impl("https://x/", 10)
    assert any(f["leak"] == "PII in JWT claims" for f in out["findings"])


def test_header_leak_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hl, "_replay_impl", lambda *a, **k: _resp({"Content-Type": "text/html"}))
    out = _header_leak_impl("https://x/", 10)
    assert out["possible_header_leak"] is False


# ---- ws_leak -------------------------------------------------------------


def test_ws_frame_roundtrip() -> None:
    payload = b'{"type":"data","secret":"leak"}'
    masked = wl._mask_frame(payload)
    # server frames are unmasked; simulate by clearing the mask bit and re-laying
    # the payload plainly (opcode 1, no mask) to test the decoder
    server_frame = bytes([0x81, len(payload)]) + payload
    assert wl._decode_frames(server_frame) == [payload.decode()]
    # sanity: our client frame set the mask bit
    assert masked[1] & 0x80


def test_ws_decode_multiple_frames() -> None:
    a, b = b"first", b"second-message"
    data = bytes([0x81, len(a)]) + a + bytes([0x81, len(b)]) + b
    assert wl._decode_frames(data) == ["first", "second-message"]


def test_ws_bad_scheme_rejected() -> None:
    assert wl._ws_leak_impl("https://x/", None, 1)["success"] is False
