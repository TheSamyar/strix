"""WebSocket handshake / CSWSH probe — tests with a fake connector (no network)."""

from __future__ import annotations

from strix.tools.ws_probe.tools import _parse_response, probe_handshake


_UPGRADE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\nConnection: Upgrade\r\nServer: test\r\n\r\n"
)
_REJECT = b"HTTP/1.1 403 Forbidden\r\nServer: test\r\n\r\n"


def test_parse_response() -> None:
    status, headers = _parse_response(_UPGRADE)
    assert status == 101
    assert headers["upgrade"] == "websocket"


def test_upgrade_detected() -> None:
    result = probe_handshake(
        "wss://target/ws", "https://target", connector=lambda *a: _UPGRADE
    )
    assert result.upgraded is True
    assert result.status == 101


def test_rejected_handshake_not_upgraded() -> None:
    result = probe_handshake(
        "wss://target/ws", "https://evil.example", connector=lambda *a: _REJECT
    )
    assert result.upgraded is False
    assert result.status == 403


def test_foreign_origin_is_forwarded() -> None:
    captured: dict[str, str] = {}

    def connector(host: str, port: int, path: str, use_tls: bool, headers: dict) -> bytes:
        captured.update(headers)
        return _UPGRADE

    probe_handshake("wss://target/ws", "https://evil.example", cookie="s=1", connector=connector)
    assert captured["Origin"] == "https://evil.example"
    assert captured["Cookie"] == "s=1"


def test_connection_error_reported() -> None:
    def boom(*_a: object) -> bytes:
        raise OSError("refused")

    result = probe_handshake("wss://target/ws", "https://target", connector=boom)
    assert result.upgraded is False
    assert result.error == "refused"
