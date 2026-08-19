"""Connect to a WebSocket unauthenticated and see if it streams data.

Real-time apps often gate the page behind login but leave the WebSocket wide
open — connect anonymously, send a subscribe/join message, and private data
(other users' messages, presence, updates) streams to you. This does the raw
handshake, subscribes with common message shapes, and reports what comes back.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from agents import RunContextWrapper, function_tool


_SUBSCRIBE_MESSAGES = (
    '{"type":"connection_init"}',
    '{"type":"subscribe","id":"1","payload":{}}',
    '{"action":"subscribe","channel":"*"}',
    '{"event":"subscribe","data":{"channel":"public"}}',
    "40",  # socket.io connect
    '42["subscribe",{}]',  # socket.io event
)


def _mask_frame(payload: bytes) -> bytes:
    mask = os.urandom(4)
    length = len(payload)
    out = bytearray([0x81])  # FIN + text opcode
    if length < 126:
        out.append(0x80 | length)
    elif length < 65536:
        out.append(0x80 | 126)
        out += length.to_bytes(2, "big")
    else:
        out.append(0x80 | 127)
        out += length.to_bytes(8, "big")
    out += mask
    out += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(out)


def _decode_frames(data: bytes) -> list[str]:
    """Best-effort parse of server→client (unmasked) text/binary frames."""
    messages: list[str] = []
    i = 0
    while i + 2 <= len(data):
        opcode = data[i] & 0x0F
        length = data[i + 1] & 0x7F
        i += 2
        if length == 126:
            if i + 2 > len(data):
                break
            length = int.from_bytes(data[i : i + 2], "big")
            i += 2
        elif length == 127:
            if i + 8 > len(data):
                break
            length = int.from_bytes(data[i : i + 8], "big")
            i += 8
        if i + length > len(data):
            break
        payload = data[i : i + length]
        i += length
        if opcode in (1, 2):
            messages.append(payload.decode("utf-8", "replace"))
    return messages


def _ws_leak_impl(url: str, headers: dict[str, str] | None, read_seconds: int) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme not in {"ws", "wss"}:
        return {"success": False, "error": "url must be ws:// or wss://"}
    use_tls = parsed.scheme == "wss"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    key = base64.b64encode(os.urandom(16)).decode()

    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=read_seconds + 3)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
        handshake = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\nOrigin: https://evil-strix.example\r\n{extra}\r\n"
        )
        sock.sendall(handshake.encode())
        sock.settimeout(read_seconds + 2)
        resp = sock.recv(4096)
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            return {
                "success": True,
                "url": url,
                "handshake_upgraded": False,
                "possible_ws_leak": False,
                "note": "server did not upgrade the unauthenticated connection",
            }

        for msg in _SUBSCRIBE_MESSAGES:
            with contextlib.suppress(OSError):
                sock.sendall(_mask_frame(msg.encode()))
        sock.settimeout(read_seconds)
        received = b""
        with contextlib.suppress(TimeoutError, OSError):
            while len(received) < 131072:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                received += chunk
        frames = _decode_frames(received)
        # A substantial data frame (beyond a tiny ack/pong) suggests streamed data.
        data_frames = [f for f in frames if len(f) > 8]
        return {
            "success": True,
            "url": url,
            "handshake_upgraded": True,
            "messages_received": len(frames),
            "sample": frames[:5],
            "possible_ws_leak": bool(data_frames),
            "note": (
                "unauth WebSocket upgraded AND streamed data — check for other users' data"
                if data_frames
                else "upgraded without auth; subscribe returned little — try app-specific messages"
            ),
        }
    except OSError as exc:
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()


@function_tool(timeout=60, strict_mode=False)
async def ws_leak(
    ctx: RunContextWrapper,
    url: str,
    headers: dict[str, str] | None = None,
    read_seconds: int = 4,
) -> str:
    """Connect to a WebSocket unauthenticated and flag streamed data.

    Does the raw WS handshake with a foreign Origin and NO auth; if it upgrades,
    sends common subscribe/join messages and reads what streams back. Data frames
    returned to an anonymous client = a WebSocket authorization/data-leak bug.
    Deliberately omits credentials — pass ``headers`` only to compare. Only test
    authorized targets.

    Returns JSON with ``handshake_upgraded``, ``messages_received``, ``sample``,
    and ``possible_ws_leak``.

    Args:
        url: The WebSocket URL (``ws://`` or ``wss://``).
        headers: Optional headers (leave empty to test as anonymous).
        read_seconds: How long to read for streamed messages (default 4).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_ws_leak_impl, url, headers, read_seconds),
        ensure_ascii=False,
        default=str,
    )
