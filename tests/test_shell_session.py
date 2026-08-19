"""shell_session: listener catches a connection, shell_exec round-trips output."""

from __future__ import annotations

import socket
import threading
import time

from strix.tools.shell_session import manager


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fake_shell(host: str, port: int) -> None:
    """A trivial reverse shell: connect back, echo each line prefixed with 'out:'."""
    c = socket.create_connection((host, port), timeout=5)
    c.sendall(b"banner\n")
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break
            c.sendall(b"out:" + data)
    except OSError:
        pass
    finally:
        c.close()


def test_catch_shell_and_exec() -> None:
    port = _find_free_port()
    assert manager.start_listener(port, "127.0.0.1")["success"] is True
    try:
        threading.Thread(target=_fake_shell, args=("127.0.0.1", port), daemon=True).start()

        # wait for the connection to register
        deadline = time.time() + 5
        while time.time() < deadline and not manager.list_shells():
            time.sleep(0.05)
        shells = manager.list_shells()
        assert shells, "no shell caught"
        sid = shells[0]["session_id"]

        out = manager.shell_exec(sid, "id", read_timeout=2)
        assert out["success"] is True
        assert "out:id" in out["output"]  # our echo shell prefixed the command

        assert manager.close_shell(session_id=sid)["success"] is True
    finally:
        manager.close_shell(port=port)


def test_exec_missing_session() -> None:
    assert manager.shell_exec("nope", "id")["success"] is False


def test_close_nothing() -> None:
    assert manager.close_shell()["success"] is False
