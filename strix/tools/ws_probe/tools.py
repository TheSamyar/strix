"""WebSocket handshake / CSWSH probe.

The flagship WebSocket bug is Cross-Site WebSocket Hijacking: the server
authenticates the *handshake* with cookies but never validates ``Origin``,
so any off-origin page can open an authenticated socket. That signal lives
entirely in the HTTP upgrade handshake — no frame parsing needed — so this
tool tests the handshake only.

ponytail: handshake-level (does it 101-upgrade with a foreign Origin?),
not a full frame client. For sending/reading frames the agent has
interactive tooling + the ``websocket`` skill.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
from collections.abc import Callable
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from agents import RunContextWrapper, function_tool


@dataclass
class HandshakeResult:
    origin: str | None
    status: int
    upgraded: bool
    server: str
    error: str | None = None


# (host, port, path, use_tls, extra_headers) -> raw HTTP response bytes.
Connector = Callable[[str, int, str, bool, dict[str, str]], bytes]


def _raw_connect(host: str, port: int, path: str, use_tls: bool, headers: dict[str, str]) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    lines.extend(f"{k}: {v}" for k, v in headers.items() if v)
    request = ("\r\n".join(lines) + "\r\n\r\n").encode()

    sock = socket.create_connection((host, port), timeout=10)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # probing; cert validity is a separate check
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        chunks: list[bytes] = []
        while b"\r\n\r\n" not in b"".join(chunks):
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def _parse_response(raw: bytes) -> tuple[int, dict[str, str]]:
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    resp_headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()
    return status, resp_headers


def probe_handshake(
    url: str,
    origin: str | None,
    cookie: str | None = None,
    auth_header: str | None = None,
    connector: Connector = _raw_connect,
) -> HandshakeResult:
    """Perform one WS upgrade handshake and report whether it 101-upgraded."""
    parsed = urlparse(url)
    use_tls = parsed.scheme in ("wss", "https")
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers = {"Origin": origin or "", "Cookie": cookie or "", "Authorization": auth_header or ""}
    try:
        raw = connector(host, port, path, use_tls, headers)
    except (OSError, ssl.SSLError) as exc:
        return HandshakeResult(origin=origin, status=0, upgraded=False, server="", error=str(exc))
    status, resp_headers = _parse_response(raw)
    upgraded = status == 101 and resp_headers.get("upgrade", "").lower() == "websocket"
    return HandshakeResult(
        origin=origin, status=status, upgraded=upgraded, server=resp_headers.get("server", "")
    )


def _foreign_origin(url: str) -> str:
    parsed = urlparse(url)
    scheme = "https" if parsed.scheme in ("wss", "https") else "http"
    return f"{scheme}://evil.example"


@function_tool(timeout=60)
async def ws_probe(
    ctx: RunContextWrapper,
    url: str,
    cookie: str | None = None,
    auth_header: str | None = None,
) -> str:
    """Probe a WebSocket endpoint's handshake for CSWSH / origin enforcement.

    Runs two handshakes — one with the site's own Origin, one with a foreign
    Origin (``https://evil.example``) — using the supplied ``cookie`` /
    ``auth_header``. If the foreign-Origin handshake upgrades (HTTP 101), the
    server does not enforce Origin and is at risk of Cross-Site WebSocket
    Hijacking. Load the ``websocket`` skill for the full methodology and to
    build an off-origin PoC.

    Args:
        url: WebSocket URL (``ws://`` or ``wss://``).
        cookie: Optional ``Cookie`` header value (an authenticated session
            is what makes CSWSH impactful).
        auth_header: Optional ``Authorization`` header value.
    """
    del ctx
    if urlparse(url).scheme not in ("ws", "wss"):
        return json.dumps({"error": "url must start with ws:// or wss://"})
    parsed = urlparse(url)
    same_scheme = "https" if parsed.scheme == "wss" else "http"
    same_origin = f"{same_scheme}://{parsed.netloc}"
    baseline = probe_handshake(url, same_origin, cookie, auth_header)
    foreign = probe_handshake(url, _foreign_origin(url), cookie, auth_header)
    cswsh_risk = foreign.upgraded and (baseline.upgraded or baseline.status == 0)
    return json.dumps(
        {
            "success": True,
            "url": url,
            "cswsh_risk": cswsh_risk,
            "baseline_origin": asdict(baseline),
            "foreign_origin": asdict(foreign),
            "note": (
                "Foreign Origin upgraded — Origin not enforced; test for CSWSH."
                if cswsh_risk
                else "Foreign Origin rejected or handshake failed; Origin appears enforced."
            ),
        },
        ensure_ascii=False,
    )
